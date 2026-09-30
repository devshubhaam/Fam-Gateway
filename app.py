import hashlib
import io
import json
import logging
import os
import re
import secrets
import threading
import time
from urllib.parse import urlencode
from collections import defaultdict
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request,
                   session, url_for, Response)
import requests
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from itsdangerous import BadSignature, URLSafeTimedSerializer
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

import poller
import security
import services
import webhooks
from db import get_db

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("app")

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-me"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("INSECURE_COOKIES", "0") != "1",
    MAX_CONTENT_LENGTH=64 * 1024,
)
if os.environ.get("MONGODB_URI") and not os.environ.get("SECRET_KEY"):
    raise RuntimeError("SECRET_KEY must be set in production")
BOOT_TIME = time.time()
BRAND = os.environ.get("BRAND_NAME", "UPIBridge")
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "15"))
UPI_ID_RE = re.compile(r"^[A-Za-z0-9._\-]{2,64}@[A-Za-z][A-Za-z0-9]{1,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------- helpers
_hits = defaultdict(list)


def rate_limited(key: str, limit: int, window: int) -> bool:
    now = time.time()
    recent = [t for t in _hits[key] if now - t < window]
    if len(recent) >= limit:
        _hits[key] = recent
        return True
    recent.append(now)
    _hits[key] = recent
    return False


def base_url() -> str:
    return os.environ.get("BASE_URL", request.url_root).rstrip("/")


# ---------------------------------------------------------------- email (Brevo templates)
try:
    from famway_mailer import famway_mail_async
except ImportError:  # mailer file missing: the app still runs, just without emails
    def famway_mail_async(*_args, **_kwargs):
        return None


def send_mail(event: str, email: str, name: str = "", **params) -> None:
    """Fire-and-forget email. A mail problem must never break signup/login/settings."""
    try:
        famway_mail_async(event, email, name, params)
    except Exception:  # noqa: BLE001
        log.exception("mail %s could not be queued", event)


def _now_ist() -> str:
    return fmt_ist_long(services.utcnow()) + " IST"


def _device() -> str:
    ua = request.headers.get("User-Agent", "")
    os_name = next((n for k, n in (("Android", "Android"), ("iPhone", "iPhone"), ("iPad", "iPad"),
                                   ("Windows", "Windows"), ("Mac OS", "Mac"), ("Linux", "Linux")) if k in ua),
                   "Unknown device")
    browser = next((n for k, n in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox", "Firefox"),
                                   ("Chrome", "Chrome"), ("Safari", "Safari")) if k in ua), "Browser")
    return f"{browser} on {os_name}"


def _dash_url() -> str:
    return base_url() + url_for("dashboard")


def _mask_key(key: str) -> str:
    return f"{key[:12]}...{key[-4:]}"


def _login_alert(merchant: dict) -> None:
    """Email a 'new login' alert when the sign-in comes from an IP we have not seen before."""
    ip = request.remote_addr or ""
    if not ip:
        return
    known = merchant.get("known_ips") or []
    if ip in known:
        return
    get_db().merchants.update_one(
        {"_id": merchant["_id"]},
        {"$push": {"known_ips": {"$each": [ip], "$slice": -10}}})
    if known:  # first ever login is not an alert
        send_mail("login_alert", merchant["email"], display_name(merchant),
                  device=_device(), location="IP " + ip, ip_address=ip, time=_now_ist(),
                  secure_url=base_url() + url_for("profile", tab="security"))


def _notify_new_key(m: dict, key: str) -> None:
    send_mail("api_key_created", m["email"], display_name(m),
              api_key_masked=_mask_key(key), key_name="Primary key", time=_now_ist(),
              ip_address=request.remote_addr or "Unknown", keys_url=base_url() + url_for("api_keys"))


def current_merchant():
    if "merchant" not in g:
        mid = session.get("mid")
        g.merchant = get_db().merchants.find_one({"_id": mid}) if mid else None
    return g.merchant


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_merchant():
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper


@app.template_filter("dt")
def fmt_dt(value):
    return value.strftime("%d %b %H:%M") if isinstance(value, datetime) else "-"


@app.context_processor
def inject_globals():
    if "csrf" not in session:
        session["csrf"] = security.new_csrf_token()
    return {"brand": BRAND, "csrf": session["csrf"], "me": current_merchant(),
            "support_whatsapp": re.sub(r"\D", "", os.environ.get("SUPPORT_WHATSAPP", ""))}


@app.before_request
def csrf_protect():
    if request.path == "/profile/avatar":
        request.max_content_length = 600 * 1024  # avatar upload; everything else keeps the 64 KB cap
    if request.method == "POST" and not request.path.startswith("/api/"):
        sent = request.form.get("csrf", "")
        if not sent or not security.safe_equals(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


@app.before_request
def _t0():
    g._t0 = time.time()


@app.after_request
def headers(resp):
    took = time.time() - getattr(g, "_t0", time.time())
    if took > 1.0:
        log.warning("SLOW %s %s took %.1fs", request.method, request.path, took)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path.startswith(("/dashboard", "/login", "/register", "/profile", "/integrations")):
        resp.headers["Cache-Control"] = "no-store"
        resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp


def parse_amount(value) -> int:
    if isinstance(value, bool) or value is None:
        raise services.OrderError("amount is required")
    try:
        d = Decimal(str(value).strip())
        if d != d.quantize(Decimal("0.01")):
            raise services.OrderError("amount can have at most 2 decimal places")
    except InvalidOperation:
        raise services.OrderError("amount must be a number")
    return int(d * 100)


def order_json(merchant: dict, order: dict, created=None) -> dict:
    out = {
        "order_id": order["order_id"],
        "order_ref": order.get("order_ref"),
        "status": effective_status(order),
        "amount": services.fmt_amount(order["amount_paise"]),
        "payable_amount": services.fmt_amount(order["payable_paise"]),
        "currency": "INR",
        "upi_link": services.upi_link(merchant, order),
        "qr_url": f"{base_url()}/qr/{order['order_id']}.svg",
        "pay_url": f"{base_url()}/pay/{order['order_id']}",
        "expires_at": order["expires_at"].isoformat(),
        "utr": order.get("utr"),
        "paid_at": order["paid_at"].isoformat() if order.get("paid_at") else None,
    }
    if created is not None:
        out["created"] = created
    return out


def effective_status(order: dict) -> str:
    if order["status"] == "pending" and order["expires_at"] < services.utcnow():
        return "expired"
    return order["status"]


# ---------------------------------------------------------------- public pages
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/docs")
def docs():
    return render_template("docs.html", base=base_url(), active="docs", status_ok=_status_snapshot()["ok"])


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ---------------------------------------------------------------- auth
def create_merchant(email: str, password_hash: str, verified: bool = True):
    """Insert a new merchant. Returns (merchant, plaintext_api_key). Raises DuplicateKeyError."""
    api_key = security.new_api_key()
    merchant = {
        "_id": "m_" + secrets.token_hex(8),
        "email": email,
        "email_verified": verified,
        "password_hash": password_hash,
        "created_at": services.utcnow(),
        "upi_id": "", "payee_name": "", "webhook_url": "",
        "api_key_hash": security.hash_api_key(api_key),
        "api_key_prefix": api_key[:12],
        "api_key_enc": security.encrypt(api_key),
        "webhook_secret_enc": security.encrypt(security.new_webhook_secret()),
        "imap": {"enabled": False, "host": "imap.gmail.com", "port": 993, "user": "",
                 "password_enc": None, "allowed_senders": [], "require_auth": True},
        "imap_status": {},
    }
    get_db().merchants.insert_one(merchant)
    return merchant, api_key


@app.route("/register", methods=["GET", "POST"])
def register():
    if os.environ.get("ALLOW_REGISTRATION", "1") != "1":
        abort(404)
    if request.method == "POST":
        if rate_limited("reg:" + request.remote_addr, 5, 3600):
            flash("Too many attempts. Try again later.", "error")
            return render_template("auth.html", mode="register"), 429
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not EMAIL_RE.match(email) or len(password) < 8:
            flash("Enter a valid email and a password of at least 8 characters.", "error")
            return render_template("auth.html", mode="register"), 400
        try:
            merchant, api_key = create_merchant(email, generate_password_hash(password), verified=False)
        except DuplicateKeyError:
            old = get_db().merchants.find_one({"email": email}) or {}
            if old.get("email_verified") is False:
                flash("This email is registered but not verified yet. Log in to get a new code.", "error")
            else:
                flash("That email is already registered.", "error")
            return render_template("auth.html", mode="register"), 409
        except Exception as exc:  # noqa: BLE001 - show the reason on screen instead of a blank 500
            log.exception("register failed")
            flash("Server error: %s: %s" % (type(exc).__name__, str(exc)[:200]), "error")
            return render_template("auth.html", mode="register"), 500
        session.clear()
        session["otp_mid"] = merchant["_id"]      # not logged in until the email is verified
        session["new_api_key"] = api_key
        _send_otp("signup", merchant)
        return redirect(url_for("verify_email"))
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if rate_limited("login:" + request.remote_addr, 10, 300):
            flash("Too many attempts. Try again in a few minutes.", "error")
            return render_template("auth.html", mode="login"), 429
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        admin_email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
        admin_pw = os.environ.get("ADMIN_PASSWORD", "")
        if admin_email and admin_pw and security.safe_equals(email, admin_email) and security.safe_equals(pw, admin_pw):
            merchant = get_db().merchants.find_one({"email": email})
            api_key = None
            if not merchant:
                merchant, api_key = create_merchant(email, generate_password_hash(admin_pw))
            session.clear()
            session["mid"] = merchant["_id"]
            if api_key:
                session["new_api_key"] = api_key
            return redirect(url_for("dashboard"))
        merchant = get_db().merchants.find_one({"email": email})
        if merchant and merchant.get("password_hash") and check_password_hash(merchant["password_hash"], request.form.get("password", "")):
            return _after_password(merchant)
        flash("Wrong email or password.", "error")
        return render_template("auth.html", mode="login"), 401
    return render_template("auth.html", mode="login")


# ---------------------------------------------------------------- OTP (signup verify / login 2-step / forgot password)
OTP_TTL_MIN = 10
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_SECONDS = 45
LOGIN_OTP_ON = os.environ.get("LOGIN_OTP", "1") == "1"      # set LOGIN_OTP=0 on Koyeb to switch 2-step login off
TRUST_DAYS = 30
_trust_signer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="trusted-device")

OTP_MESSAGES = {
    "wrong": "That code is not correct.",
    "expired": "This code has expired. Request a new one.",
    "locked": "Too many wrong attempts. Request a new code.",
}


def _aware(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=services.utcnow().tzinfo)


def _otp_hash(purpose: str, email: str, code: str) -> str:
    raw = f"{app.config['SECRET_KEY']}|{purpose}|{email}|{code}"
    return hashlib.sha256(raw.encode()).hexdigest()


def issue_otp(purpose: str, email: str):
    """Create a fresh 6-digit code. Returns None if one was sent less than OTP_RESEND_SECONDS ago."""
    col = get_db().otps
    key = f"{purpose}:{email}"
    now = services.utcnow()
    cur = col.find_one({"_id": key})
    if cur and (now - _aware(cur["created_at"])).total_seconds() < OTP_RESEND_SECONDS:
        return None
    code = f"{secrets.randbelow(10 ** 6):06d}"
    col.replace_one({"_id": key}, {
        "_id": key, "purpose": purpose, "email": email, "code_hash": _otp_hash(purpose, email, code),
        "attempts": 0, "created_at": now, "expires_at": now + timedelta(minutes=OTP_TTL_MIN)}, upsert=True)
    return code


def check_otp(purpose: str, email: str, code: str) -> str:
    """Returns 'ok' | 'wrong' | 'expired' | 'locked'. A correct code is single-use."""
    col = get_db().otps
    key = f"{purpose}:{email}"
    code = re.sub(r"\D", "", code or "")
    doc = col.find_one_and_update({"_id": key}, {"$inc": {"attempts": 1}}, return_document=ReturnDocument.AFTER)
    if not doc:
        return "wrong"
    if _aware(doc["expires_at"]) < services.utcnow():
        col.delete_one({"_id": key})
        return "expired"
    if doc["attempts"] > OTP_MAX_ATTEMPTS:
        col.delete_one({"_id": key})
        return "locked"
    if len(code) == 6 and secrets.compare_digest(doc["code_hash"], _otp_hash(purpose, email, code)):
        col.delete_one({"_id": key})
        return "ok"
    return "wrong"


def _send_otp(purpose: str, merchant: dict) -> bool:
    code = issue_otp(purpose, merchant["email"])
    if not code:
        return False
    send_mail("otp", merchant["email"], display_name(merchant), otp=code, expiry_minutes=OTP_TTL_MIN)
    return True


def _trusted_device(merchant: dict) -> bool:
    token = request.cookies.get("fw_td_" + merchant["_id"], "")
    try:
        return _trust_signer.loads(token, max_age=TRUST_DAYS * 86400) == merchant["_id"]
    except BadSignature:
        return False


def _finish_login(merchant: dict):
    session.clear()
    session["mid"] = merchant["_id"]
    _login_alert(merchant)
    return redirect(url_for("dashboard"))


def _after_password(merchant: dict):
    """A correct password still has to pass email verification / 2-step OTP."""
    if merchant.get("email_verified") is False:      # old accounts have no flag and count as verified
        session.clear()
        session["otp_mid"] = merchant["_id"]
        _send_otp("signup", merchant)
        flash("Please verify your email. We sent you a code.", "ok")
        return redirect(url_for("verify_email"))
    if LOGIN_OTP_ON and not _trusted_device(merchant):
        session.clear()
        session["otp_login_mid"] = merchant["_id"]
        _send_otp("login", merchant)
        return redirect(url_for("login_otp"))
    return _finish_login(merchant)


def _pending(session_key: str):
    mid = session.get(session_key)
    return get_db().merchants.find_one({"_id": mid}) if mid else None


def _otp_page(mode: str, status: int = 200, **ctx):
    return render_template("otp.html", mode=mode, **ctx), status


# --- signup: verify email
@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    m = _pending("otp_mid")
    if not m or m.get("email_verified") is not False:
        return redirect(url_for("login"))
    page = dict(email=m["email"], action=url_for("verify_email"), resend=url_for("verify_email_resend"))
    if request.method == "POST":
        if rate_limited("otpv:" + (request.remote_addr or ""), 20, 600):
            flash("Too many attempts. Try again in a few minutes.", "error")
            return _otp_page("verify_signup", 429, **page)
        res = check_otp("signup", m["email"], request.form.get("code", ""))
        if res != "ok":
            flash(OTP_MESSAGES[res], "error")
            return _otp_page("verify_signup", 400, **page)
        get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"email_verified": True}})
        key = session.get("new_api_key")
        session.clear()
        session["mid"] = m["_id"]
        if key:
            session["new_api_key"] = key
        _login_alert(m)  # first login: only records this IP
        send_mail("welcome", m["email"], display_name(m),
                  dashboard_url=_dash_url(), docs_url=base_url() + url_for("docs"))
        return redirect(url_for("dashboard"))
    return _otp_page("verify_signup", **page)


@app.post("/verify-email/resend")
def verify_email_resend():
    m = _pending("otp_mid")
    if not m:
        return redirect(url_for("login"))
    if rate_limited("otpr:" + m["email"], 5, 3600):
        flash("Too many codes requested. Try again later.", "error")
    elif _send_otp("signup", m):
        flash("A new code has been sent.", "ok")
    else:
        flash("Please wait a few seconds before requesting another code.", "error")
    return redirect(url_for("verify_email"))


# --- login: 2-step OTP
@app.route("/login/otp", methods=["GET", "POST"])
def login_otp():
    m = _pending("otp_login_mid")
    if not m:
        return redirect(url_for("login"))
    page = dict(email=m["email"], action=url_for("login_otp"), resend=url_for("login_otp_resend"))
    if request.method == "POST":
        if rate_limited("otpl:" + (request.remote_addr or ""), 20, 600):
            flash("Too many attempts. Try again in a few minutes.", "error")
            return _otp_page("login", 429, **page)
        res = check_otp("login", m["email"], request.form.get("code", ""))
        if res != "ok":
            flash(OTP_MESSAGES[res], "error")
            return _otp_page("login", 400, **page)
        resp = _finish_login(m)
        if request.form.get("trust"):
            resp.set_cookie("fw_td_" + m["_id"], _trust_signer.dumps(m["_id"]), max_age=TRUST_DAYS * 86400,
                            httponly=True, samesite="Lax", secure=app.config["SESSION_COOKIE_SECURE"])
        return resp
    return _otp_page("login", **page)


@app.post("/login/otp/resend")
def login_otp_resend():
    m = _pending("otp_login_mid")
    if not m:
        return redirect(url_for("login"))
    if rate_limited("otpr:" + m["email"], 5, 3600):
        flash("Too many codes requested. Try again later.", "error")
    elif _send_otp("login", m):
        flash("A new code has been sent.", "ok")
    else:
        flash("Please wait a few seconds before requesting another code.", "error")
    return redirect(url_for("login_otp"))


# --- forgot password (3 steps: email -> code -> new password)
@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if rate_limited("forgot:" + (request.remote_addr or ""), 5, 3600):
            flash("Too many attempts. Try again later.", "error")
            return _otp_page("forgot", 429, action=url_for("forgot"))
        if not EMAIL_RE.match(email):
            flash("Enter a valid email address.", "error")
            return _otp_page("forgot", 400, action=url_for("forgot"))
        m = get_db().merchants.find_one({"email": email})
        if m and not rate_limited("otpr:" + email, 5, 3600):
            _send_otp("reset", m)
        # same answer whether or not the account exists, so emails cannot be probed
        session.pop("reset_ok", None)
        session["reset_email"] = email
        flash("If an account exists for that email, we have sent a code.", "ok")
        return redirect(url_for("forgot_verify"))
    return _otp_page("forgot", action=url_for("forgot"))


@app.route("/forgot/verify", methods=["GET", "POST"])
def forgot_verify():
    email = session.get("reset_email")
    if not email:
        return redirect(url_for("forgot"))
    page = dict(email=email, action=url_for("forgot_verify"), resend=url_for("forgot_resend"))
    if request.method == "POST":
        if rate_limited("otpf:" + (request.remote_addr or ""), 20, 600):
            flash("Too many attempts. Try again in a few minutes.", "error")
            return _otp_page("forgot_verify", 429, **page)
        res = check_otp("reset", email, request.form.get("code", ""))
        if res != "ok":
            flash(OTP_MESSAGES[res], "error")
            return _otp_page("forgot_verify", 400, **page)
        session["reset_ok"] = email
        session["reset_at"] = time.time()
        return redirect(url_for("forgot_reset"))
    return _otp_page("forgot_verify", **page)


@app.post("/forgot/resend")
def forgot_resend():
    email = session.get("reset_email")
    if not email:
        return redirect(url_for("forgot"))
    m = get_db().merchants.find_one({"email": email})
    if rate_limited("otpr:" + email, 5, 3600):
        flash("Too many codes requested. Try again later.", "error")
    elif m and _send_otp("reset", m):
        flash("A new code has been sent.", "ok")
    else:
        flash("If an account exists for that email, we have sent a code.", "ok")
    return redirect(url_for("forgot_verify"))


@app.route("/forgot/reset", methods=["GET", "POST"])
def forgot_reset():
    email = session.get("reset_ok")
    if not email or time.time() - session.get("reset_at", 0) > 900:
        session.pop("reset_ok", None)
        flash("Your reset session expired. Please start again.", "error")
        return redirect(url_for("forgot"))
    page = dict(action=url_for("forgot_reset"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if len(pw) < 8:
            flash("Password must be at least 8 characters.", "error")
            return _otp_page("reset", 400, **page)
        if pw != request.form.get("confirm", ""):
            flash("The two passwords do not match.", "error")
            return _otp_page("reset", 400, **page)
        m = get_db().merchants.find_one({"email": email})
        if not m:
            return redirect(url_for("forgot"))
        get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {
            "password_hash": generate_password_hash(pw), "email_verified": True}})
        send_mail("password_changed", email, display_name(m), time=_now_ist(), device=_device(),
                  location="IP " + (request.remote_addr or "Unknown"),
                  secure_url=base_url() + url_for("profile", tab="security"))
        session.clear()
        flash("Password updated. Log in with your new password.", "ok")
        return redirect(url_for("login"))
    return _otp_page("reset", **page)


# ---------------------------------------------------------------- Google sign-in
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"


def google_enabled() -> bool:
    return bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))


@app.context_processor
def inject_google():
    return {"google_enabled": google_enabled()}


@app.get("/auth/google")
def google_start():
    if not google_enabled():
        abort(404)
    state = secrets.token_urlsafe(24)
    session["g_state"] = state
    params = {
        "client_id": os.environ["GOOGLE_CLIENT_ID"],
        "redirect_uri": base_url() + url_for("google_callback"),
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "prompt": "select_account",
    }
    return redirect(GOOGLE_AUTH_URL + "?" + urlencode(params))


@app.get("/auth/google/callback")
def google_callback():
    if not google_enabled():
        abort(404)
    expected = session.pop("g_state", "")
    if request.args.get("error") or not expected or not security.safe_equals(request.args.get("state", ""), expected):
        flash("Google sign-in was cancelled or failed. Please try again.", "error")
        return redirect(url_for("login"))
    try:
        tok = requests.post(GOOGLE_TOKEN_URL, data={
            "code": request.args.get("code", ""),
            "client_id": os.environ["GOOGLE_CLIENT_ID"],
            "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
            "redirect_uri": base_url() + url_for("google_callback"),
            "grant_type": "authorization_code",
        }, timeout=10)
        if not getattr(tok, "ok", True):
            log.error("google token endpoint said %s: %s", tok.status_code, tok.text[:300])
            try:
                body = tok.json()
                why = "%s - %s" % (body.get("error", "?"), body.get("error_description", ""))
            except ValueError:
                why = "HTTP %s" % tok.status_code
            flash("Google said: " + why, "error")
            return redirect(url_for("login"))
        tok.raise_for_status()
        info = requests.get(GOOGLE_USERINFO_URL, timeout=10,
                            headers={"Authorization": "Bearer " + tok.json()["access_token"]})
        info.raise_for_status()
        info = info.json()
    except (requests.RequestException, KeyError, ValueError):
        log.exception("google sign-in failed")
        flash("Could not reach Google. Please try again.", "error")
        return redirect(url_for("login"))

    email = str(info.get("email", "")).strip().lower()
    if not email or info.get("email_verified") is not True:
        flash("Your Google email is not verified.", "error")
        return redirect(url_for("login"))

    if session.pop("g_link", False) and current_merchant():
        me = current_merchant()
        if email != me["email"]:
            flash("That Google account uses a different email (%s). Sign in with %s to link it." % (email, me["email"]), "error")
        else:
            get_db().merchants.update_one({"_id": me["_id"]}, {"$set": {"google_disabled": False}})
            flash("Google account linked.", "ok")
        return redirect(url_for("profile", tab="social"))

    merchant = get_db().merchants.find_one({"email": email})
    if merchant:
        if merchant.get("google_disabled"):
            flash("Google sign-in is turned off for this account. Use your password.", "error")
            return redirect(url_for("login"))
        session.clear()
        session["mid"] = merchant["_id"]
        _login_alert(merchant)
        return redirect(url_for("dashboard"))
    if os.environ.get("ALLOW_REGISTRATION", "1") != "1":
        flash("New sign-ups are closed.", "error")
        return redirect(url_for("login"))
    try:
        merchant, api_key = create_merchant(email, "")
    except DuplicateKeyError:  # double-click race: the account now exists
        merchant, api_key = get_db().merchants.find_one({"email": email}), None
    session.clear()
    session["mid"] = merchant["_id"]
    if api_key:
        session["new_api_key"] = api_key
        send_mail("welcome", merchant["email"], display_name(merchant),
                  dashboard_url=_dash_url(), docs_url=base_url() + url_for("docs"))
    return redirect(url_for("dashboard"))


@app.get("/dbcheck")
def dbcheck():
    """Diagnostic: tells you in plain text whether MongoDB is reachable and how long it took."""
    import db as dbmod
    lines = [
        "MONGODB_URI set: %s" % bool(os.environ.get("MONGODB_URI")),
        "SECRET_KEY set: %s" % bool(os.environ.get("SECRET_KEY")),
        "GOOGLE keys set: %s" % google_enabled(),
        "app DB handle ready: %s" % (dbmod._db is not None),
    ]
    def timed(label, fn):
        t0 = time.time()
        try:
            fn()
            lines.append("%s: %.2fs" % (label, time.time() - t0))
        except Exception as exc:  # noqa: BLE001
            lines.append("%s FAILED after %.2fs: %s: %s" % (label, time.time() - t0, type(exc).__name__, str(exc)[:200]))

    timed("connect (get_db)", get_db)
    for n in (1, 2, 3):
        timed("db read #%d" % n, lambda: get_db().merchants.find_one({"email": "nobody@example.invalid"}))
    timed("password hash", lambda: generate_password_hash("timing-test-123"))
    lines.append("server uptime: %.0fs, threads: %d" % (time.time() - BOOT_TIME, threading.active_count()))
    return Response("\n".join(lines), mimetype="text/plain")


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------- dashboard
@app.get("/dashboard")
@login_required
def dashboard():
    db, m = get_db(), current_merchant()
    services.sweep_expired(db, m["_id"])
    orders = list(db.orders.find({"merchant_id": m["_id"]}).sort("created_at", -1).limit(15))
    payments = list(db.payments.find({"merchant_id": m["_id"]}).sort("created_at", -1).limit(10))
    emails = list(db.email_log.find({"merchant_id": m["_id"]}).sort("created_at", -1).limit(12))
    failed = db.deliveries.count_documents({"merchant_id": m["_id"], "status": "failed"})
    stats = {"total": 0, "paid": 0, "other": 0, "revenue_paise": 0}
    today = services.utcnow().date()
    days = {today - timedelta(days=i): {"orders": 0, "revenue": 0.0} for i in range(29, -1, -1)}
    for o in db.orders.find({"merchant_id": m["_id"]}).limit(5000):
        stats["total"] += 1
        d = o["created_at"].date()
        if d in days:
            days[d]["orders"] += 1
        if effective_status(o) == "paid":
            stats["paid"] += 1
            stats["revenue_paise"] += int(o.get("payable_paise") or 0)
            pd = (o.get("paid_at") or o["created_at"]).date()
            if pd in days:
                days[pd]["revenue"] += int(o.get("payable_paise") or 0) / 100
        else:
            stats["other"] += 1
    chart = [{"d": d.strftime("%d %b"), "orders": v["orders"], "revenue": round(v["revenue"], 2)} for d, v in days.items()]
    hour = (services.utcnow() + timedelta(hours=5, minutes=30)).hour
    greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 17 else "Good evening"
    display_name = (m.get("payee_name") or m["email"].split("@")[0]).strip()
    setup = {
        "upi": bool(m.get("upi_id")),
        "mail": bool(m["imap"].get("enabled") and m["imap"].get("user")),
        "hook": bool(m.get("webhook_url")),
        "order": stats["total"] > 0,
    }
    try:
        webhook_secret = security.decrypt(m["webhook_secret_enc"])
    except ValueError:
        webhook_secret = "(unreadable - SECRET_KEY changed)"
    return render_template(
        "dashboard.html", m=m, orders=orders, payments=payments, emails=emails,
        failed_webhooks=failed, webhook_secret=webhook_secret, stats=stats,
        chart=chart, greeting=greeting, display_name=display_name, setup=setup,
        new_api_key=session.pop("new_api_key", None), fmt=services.fmt_amount,
        status_of=effective_status)


@app.post("/dashboard/settings")
@login_required
def save_settings():
    m = current_merchant()
    upi_id = request.form.get("upi_id", "").strip()
    payee = request.form.get("payee_name", "").strip()[:60]
    webhook_url = request.form.get("webhook_url", "").strip()
    if upi_id and not UPI_ID_RE.match(upi_id):
        flash("That doesn't look like a valid UPI ID (example: name@fam).", "error")
        return redirect(url_for("dashboard"))
    if webhook_url:
        ok, reason = security.is_safe_webhook_url(webhook_url)
        if not ok:
            flash(reason, "error")
            return redirect(url_for("dashboard"))
    get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {
        "upi_id": upi_id, "payee_name": payee, "webhook_url": webhook_url}})
    flash("Payment settings saved.", "ok")
    return redirect(url_for("dashboard"))


@app.post("/dashboard/imap")
@login_required
def save_imap():
    m = current_merchant()
    cfg = dict(m["imap"])
    host = request.form.get("host", "").strip().lower()
    user = request.form.get("user", "").strip()
    password = request.form.get("password", "").replace(" ", "")
    senders = [s.strip().lower() for s in re.split(r"[,\n]", request.form.get("allowed_senders", "")) if s.strip()]
    if not host or not user:
        flash("IMAP host and username are required.", "error")
        return redirect(url_for("dashboard"))
    if password:
        cfg["password_enc"] = security.encrypt(password)
    if not cfg.get("password_enc"):
        flash("Enter the mailbox app password.", "error")
        return redirect(url_for("dashboard"))
    cfg.update(host=host, user=user, allowed_senders=senders,
               require_auth=request.form.get("require_auth") == "on",
               enabled=request.form.get("enabled") == "on")
    if cfg["enabled"] and not senders:
        flash("Add at least one allowed sender (the address your bank/app emails come from).", "error")
        return redirect(url_for("dashboard"))
    get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"imap": cfg}})
    flash("Mailbox settings saved.", "ok")
    return redirect(url_for("dashboard"))


@app.post("/dashboard/imap/test")
@login_required
def test_imap():
    cfg = current_merchant()["imap"]
    if not cfg.get("password_enc") or not cfg.get("user"):
        flash("Save mailbox settings first.", "error")
    else:
        err = poller.test_connection(cfg["host"], int(cfg.get("port", 993)), cfg["user"],
                                     security.decrypt(cfg["password_enc"]))
        flash("Mailbox connection works." if not err else f"Mailbox login failed: {err}",
              "ok" if not err else "error")
    return redirect(url_for("dashboard"))


@app.post("/dashboard/apikey")
@login_required
def regenerate_key():
    m = current_merchant()
    key = security.new_api_key()
    get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {
        "api_key_hash": security.hash_api_key(key), "api_key_prefix": key[:12],
        "api_key_enc": security.encrypt(key)}})
    session["new_api_key"] = key
    _notify_new_key(m, key)
    return redirect(url_for("dashboard"))


@app.post("/dashboard/test-order")
@login_required
def test_order():
    m = current_merchant()
    try:
        order, _ = services.create_order(get_db(), m, parse_amount(request.form.get("amount", "1")),
                                         note="test order")
    except services.OrderError as exc:
        flash(str(exc), "error")
        return redirect(url_for("dashboard"))
    return redirect(url_for("pay", order_id=order["order_id"]))


# ---------------------------------------------------------------- dashboard pages
IST = timedelta(hours=5, minutes=30)


def _ist(value):
    if not isinstance(value, datetime):
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=services.utcnow().tzinfo)
    return value + IST


@app.template_filter("ist")
def fmt_ist(value):
    d = _ist(value)
    if not d:
        return "-"
    return f"{d:%a %b} {d.day}, {d.hour % 12 or 12}:{d:%M}{'am' if d.hour < 12 else 'pm'}"


@app.template_filter("istlong")
def fmt_ist_long(value):
    d = _ist(value)
    return f"{d:%b} {d.day}, {d:%Y} \u00b7 {d:%I:%M %p}" if d else "-"


@app.template_filter("istlog")
def fmt_ist_log(value):
    d = _ist(value)
    return f"{d.day} {d:%b %Y}, {d:%I:%M %p}" if d else "-"


def _status_key(order: dict) -> str:
    return effective_status(order)


def _int_arg(name, default, allowed=None, minimum=1):
    try:
        v = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    if allowed is not None and v not in allowed:
        return default
    return max(v, minimum)


def _left(order: dict) -> str:
    secs = int((order["expires_at"] - services.utcnow()).total_seconds())
    if secs <= 0:
        return "Expired"
    h, rem = divmod(secs, 3600)
    mnt = rem // 60
    if h:
        return f"{h}h {mnt}m left"
    return f"{mnt}m {rem % 60}s left" if mnt < 5 else f"{mnt}m left"


# ---- Transactions
TX_TABS = {"all": None, "created": "pending", "captured": "paid", "expired": "expired", "failed": "cancelled"}
TX_DATES = ("all", "today", "yesterday", "7days", "30days", "this_month", "last_month")


def _date_range(key):
    """Returns (start, end) in UTC for a filter key; None means unbounded."""
    now = services.utcnow()
    ist_now = now + IST
    t0 = ist_now.replace(hour=0, minute=0, second=0, microsecond=0) - IST
    if key == "today":
        return t0, None
    if key == "yesterday":
        return t0 - timedelta(days=1), t0
    if key == "7days":
        return now - timedelta(days=7), None
    if key == "30days":
        return now - timedelta(days=30), None
    m0 = ist_now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - IST
    if key == "this_month":
        return m0, None
    if key == "last_month":
        prev = (ist_now.replace(day=1) - timedelta(days=1)).replace(day=1, hour=0, minute=0, second=0, microsecond=0) - IST
        return prev, m0
    return None, None


@app.get("/transactions")
@login_required
def transactions():
    db, m = get_db(), current_merchant()
    services.sweep_expired(db, m["_id"])
    everything = list(db.orders.find({"merchant_id": m["_id"]}).sort("created_at", -1).limit(5000))
    counts = {"pending": 0, "paid": 0, "expired": 0, "cancelled": 0}
    collected = 0
    for o in everything:
        st = _status_key(o)
        counts[st] = counts.get(st, 0) + 1
        if st == "paid":
            collected += int(o.get("payable_paise") or 0)

    tab = request.args.get("status", "all")
    tab = tab if tab in TX_TABS else "all"
    date_key = request.args.get("date", "30days")
    date_key = date_key if date_key in TX_DATES else "30days"
    limit = _int_arg("limit", 25, (10, 25, 50, 100))
    q = request.args.get("q", "").strip().lower()[:60]
    page = _int_arg("page", 1)

    start, end = _date_range(date_key)
    rows = []
    for o in everything:
        if TX_TABS[tab] and _status_key(o) != TX_TABS[tab]:
            continue
        if start and o["created_at"] < start:
            continue
        if end and o["created_at"] >= end:
            continue
        if q and q not in o["order_id"].lower() and q not in (o.get("utr") or "").lower():
            continue
        rows.append(o)
    total = len(rows)
    pages = max(1, -(-total // limit))
    page = min(page, pages)
    view = rows[(page - 1) * limit: page * limit]
    qs = {"status": tab, "date": date_key, "limit": limit, "q": q}
    return render_template(
        "transactions.html", active="transactions", rows=view, total=total, page=page, pages=pages,
        limit=limit, tab=tab, date_key=date_key, q=q, qs=qs, counts=counts, collected=collected,
        paid_count=counts["paid"], fmt=services.fmt_amount, status_of=_status_key)


@app.get("/transactions/<order_id>")
@login_required
def transaction_detail(order_id):
    db, m = get_db(), current_merchant()
    order = db.orders.find_one({"order_id": order_id, "merchant_id": m["_id"]})
    if not order:
        abort(404)
    deliveries = list(db.deliveries.find({"merchant_id": m["_id"], "order_id": order_id}).sort("created_at", -1))
    return render_template("transaction_detail.html", active="transactions", o=order,
                           status=_status_key(order), deliveries=deliveries, fmt=services.fmt_amount,
                           pay_url=f"{base_url()}/pay/{order_id}")


# ---- Payment links
LINK_EXPIRY = {"1m": 60, "5m": 300, "30m": 1800, "1h": 3600, "2h": 7200, "24h": 86400}


@app.get("/payment-links")
@login_required
def payment_links():
    db, m = get_db(), current_merchant()
    services.sweep_expired(db, m["_id"])
    links = list(db.orders.find({"merchant_id": m["_id"], "source": "link"}).sort("created_at", -1).limit(100))
    new_id = request.args.get("new", "")
    new_link = next((o for o in links if o["order_id"] == new_id), None)
    return render_template("payment_links.html", active="links", links=links, new_link=new_link,
                           base=base_url(), fmt=services.fmt_amount, status_of=_status_key, left=_left,
                           has_upi=bool(m.get("upi_id")))


@app.post("/payment-links")
@login_required
def create_payment_link():
    m = current_merchant()
    expiry = LINK_EXPIRY.get(request.form.get("expiry", "24h"), 86400)
    try:
        order, _ = services.create_order(get_db(), m, parse_amount(request.form.get("amount", "")),
                                         expires_in=expiry, source="link")
    except services.OrderError as exc:
        flash(str(exc), "error")
        return redirect(url_for("payment_links"))
    return redirect(url_for("payment_links", new=order["order_id"]))


def _close_link(order_id: str, new_status: str, message: str):
    now = services.utcnow()
    res = get_db().orders.update_one(
        {"order_id": order_id, "merchant_id": current_merchant()["_id"], "source": "link", "status": "pending"},
        {"$set": {"status": new_status, "expires_at": now, "grace_until": now}})
    if res.modified_count:
        flash(message, "ok")
    else:
        flash("That link is no longer active.", "error")
    return redirect(url_for("payment_links"))


@app.post("/payment-links/<order_id>/expire")
@login_required
def expire_payment_link(order_id):
    return _close_link(order_id, "expired", "Link expired.")


@app.post("/payment-links/<order_id>/disable")
@login_required
def disable_payment_link(order_id):
    return _close_link(order_id, "cancelled", "Link disabled.")


# ---- API keys
@app.get("/api-keys")
@login_required
def api_keys():
    m = current_merchant()
    key = None
    if m.get("api_key_enc"):
        try:
            key = security.decrypt(m["api_key_enc"])
        except ValueError:
            key = None
    return render_template("api_keys.html", active="keys", key=key, prefix=m.get("api_key_prefix", ""),
                           base=base_url())


@app.post("/api-keys/regenerate")
@login_required
def regenerate_api_key():
    m = current_merchant()
    key = security.new_api_key()
    get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {
        "api_key_hash": security.hash_api_key(key), "api_key_prefix": key[:12],
        "api_key_enc": security.encrypt(key)}})
    flash("New API key generated. The old key has stopped working.", "ok")
    _notify_new_key(m, key)
    return redirect(url_for("api_keys"))


# ---- Webhooks
MAX_ENDPOINTS = 10
LOG_FILTERS = ("all", "success", "failed")


def _pretty(text):
    try:
        return json.dumps(json.loads(text), indent=2)
    except (TypeError, ValueError):
        return text or ""


def _log_view(d: dict) -> dict:
    st = d.get("status")
    code = d.get("last_status")
    if st == "done":
        kind, label = "success", f"HTTP {code}" if code else "Delivered"
    elif st == "failed":
        kind, label = "failed", f"HTTP {code}" if code else "Failed"
    else:
        kind, label = "pending", "Retrying" if d.get("attempts") else "Queued"
    return {
        "did": d.get("did") or "", "created": d.get("created_at"), "url": d.get("url"),
        "name": d.get("endpoint_name") or "Endpoint", "kind": kind, "label": label,
        "attempts": d.get("attempts", 0), "error": d.get("last_error"), "order_id": d.get("order_id"),
        "payload": _pretty(d.get("body")), "response": d.get("last_response") or "",
        "last_attempt": d.get("last_attempt_at"),
    }


@app.get("/webhooks")
@login_required
def webhooks_page():
    db, m = get_db(), current_merchant()
    endpoints = list(db.webhook_endpoints.find({"merchant_id": m["_id"]}).sort("created_at", -1))
    logs_all = [_log_view(d) for d in db.deliveries.find({"merchant_id": m["_id"]}).sort("created_at", -1).limit(1000)]
    counts = {"all": len(logs_all),
              "success": sum(1 for x in logs_all if x["kind"] == "success"),
              "failed": sum(1 for x in logs_all if x["kind"] == "failed")}
    flt = request.args.get("filter", "all")
    flt = flt if flt in LOG_FILTERS else "all"
    logs = logs_all if flt == "all" else [x for x in logs_all if x["kind"] == flt]
    per = 10
    total = len(logs)
    pages = max(1, -(-total // per))
    page = min(_int_arg("page", 1), pages)
    view = logs[(page - 1) * per: page * per]
    try:
        secret = security.decrypt(m["webhook_secret_enc"])
    except ValueError:
        secret = "(unreadable - SECRET_KEY changed)"
    logs_js = [{"did": x["did"], "name": x["name"], "url": x["url"], "label": x["label"], "kind": x["kind"],
                "attempts": x["attempts"], "error": x["error"] or "", "order_id": x["order_id"] or "",
                "payload": x["payload"], "response": x["response"],
                "when": fmt_ist_log(x["created"]), "last": fmt_ist_log(x["last_attempt"])} for x in view]
    return render_template(
        "webhooks.html", active="webhooks", logs_js=logs_js, endpoints=endpoints, default_url=m.get("webhook_url", ""),
        logs=view, counts=counts, flt=flt, page=page, pages=pages, total=total, per=per,
        first=(page - 1) * per + 1 if total else 0, last=min(page * per, total), secret=secret)


@app.post("/webhooks/endpoints")
@login_required
def add_webhook_endpoint():
    db, m = get_db(), current_merchant()
    name = request.form.get("endpoint_name", "").strip()[:40]
    url = request.form.get("endpoint_url", "").strip()
    if not name or not url:
        flash("Enter a label and a URL for the endpoint.", "error")
    elif db.webhook_endpoints.count_documents({"merchant_id": m["_id"]}) >= MAX_ENDPOINTS:
        flash(f"You can add up to {MAX_ENDPOINTS} endpoints. Delete one first.", "error")
    elif any(e.get("url") == url for e in db.webhook_endpoints.find({"merchant_id": m["_id"]})):
        flash("That URL is already added.", "error")
    else:
        ok, reason = security.is_safe_webhook_url(url)
        if not ok:
            flash(reason, "error")
        else:
            db.webhook_endpoints.insert_one({
                "eid": secrets.token_hex(6), "merchant_id": m["_id"], "name": name, "url": url,
                "active": True, "created_at": services.utcnow()})
            flash("Webhook endpoint added.", "ok")
    return redirect(url_for("webhooks_page"))


@app.post("/webhooks/endpoints/<eid>/delete")
@login_required
def delete_webhook_endpoint(eid):
    db, m = get_db(), current_merchant()
    ep = db.webhook_endpoints.find_one({"eid": eid, "merchant_id": m["_id"]})
    if ep:
        db.webhook_endpoints.delete_one({"_id": ep["_id"]})
        flash("Webhook endpoint removed.", "ok")
    return redirect(url_for("webhooks_page"))


@app.post("/webhooks/logs/<did>/retry")
@login_required
def retry_delivery(did):
    db, m = get_db(), current_merchant()
    res = db.deliveries.update_one(
        {"did": did, "merchant_id": m["_id"], "status": "failed"},
        {"$set": {"status": "pending", "attempts": 0, "next_attempt": services.utcnow()}})
    flash("Delivery queued again." if res.modified_count else "That delivery cannot be retried.",
          "ok" if res.modified_count else "error")
    return redirect(url_for("webhooks_page", filter="all"))


# ---------------------------------------------------------------- checkout
def _order_or_404(order_id: str):
    order = get_db().orders.find_one({"order_id": order_id})
    if not order:
        abort(404)
    merchant = get_db().merchants.find_one({"_id": order["merchant_id"]})
    return merchant, order


@app.get("/pay/<order_id>")
def pay(order_id):
    merchant, order = _order_or_404(order_id)
    status = effective_status(order)
    return render_template("pay.html", merchant=merchant, order=order,
                           status="expired" if status == "cancelled" else status, fmt=services.fmt_amount,
                           link=services.upi_link(merchant, order))


@app.get("/api/public/orders/<order_id>")
def public_status(order_id):
    _, order = _order_or_404(order_id)
    st = effective_status(order)
    return jsonify(status="expired" if st == "cancelled" else st,
                   redirect_url=order.get("redirect_url") if order["status"] == "paid" else None)


def embed_avatar(svg: bytes, data_uri: str) -> bytes:
    """Put the merchant avatar in the middle of a segno SVG (needs error correction level H)."""
    text = svg.decode("utf-8")
    vb = re.search(r'viewBox="\s*([\d.\-]+)[ ,]+([\d.\-]+)[ ,]+([\d.]+)[ ,]+([\d.]+)"', text)
    if vb:
        vx, vy, w, h = (float(vb.group(i)) for i in range(1, 5))
    else:
        wm, hm = re.search(r'width="([\d.]+)', text), re.search(r'height="([\d.]+)', text)
        if not (wm and hm):
            return svg
        vx = vy = 0.0
        w, h = float(wm.group(1)), float(hm.group(1))
    size = min(w, h) * 0.22
    pad = size * 0.12
    cx, cy = vx + w / 2, vy + h / 2
    badge = ('<circle cx="%.2f" cy="%.2f" r="%.2f" fill="#fff"/>'
             '<image x="%.2f" y="%.2f" width="%.2f" height="%.2f" href="%s" preserveAspectRatio="xMidYMid slice" '
             'clip-path="circle(50%%)"/>') % (cx, cy, size / 2 + pad, cx - size / 2, cy - size / 2, size, size, data_uri)
    return text.replace("</svg>", badge + "</svg>").encode("utf-8")


@app.get("/qr/<order_id>.svg")
def qr(order_id):
    import segno
    merchant, order = _order_or_404(order_id)
    avatar = merchant.get("avatar")
    buf = io.BytesIO()
    segno.make(services.upi_link(merchant, order), error="h" if avatar else "m").save(
        buf, kind="svg", scale=8, border=2)
    body = embed_avatar(buf.getvalue(), avatar) if avatar else buf.getvalue()
    return Response(body, mimetype="image/svg+xml", headers={"Cache-Control": "private, max-age=60"})


# ---------------------------------------------------------------- profile
def display_name(m: dict) -> str:
    return (m.get("full_name") or m.get("payee_name") or m["email"].split("@")[0]).strip()


def _process_avatar(raw: bytes) -> str:
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = 20_000_000
    img = Image.open(io.BytesIO(raw))
    img.load()
    img = img.convert("RGBA")
    side = min(img.size)
    left, top = (img.width - side) // 2, (img.height - side) // 2
    img = img.crop((left, top, left + side, top + side)).resize((192, 192))
    out = io.BytesIO()
    img.save(out, "PNG", optimize=True)
    import base64
    return "data:image/png;base64," + base64.b64encode(out.getvalue()).decode()


@app.get("/profile")
@login_required
def profile():
    m = current_merchant()
    if not m.get("merchant_no"):
        m["merchant_no"] = str(secrets.randbelow(9 * 10 ** 9) + 10 ** 9)
        get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"merchant_no": m["merchant_no"]}})
    tab = request.args.get("tab", "general")
    if tab not in ("general", "avatar", "security", "social"):
        tab = "general"
    return render_template("profile.html", active="profile", tab=tab, m=m, name=display_name(m),
                           has_password=bool(m.get("password_hash")),
                           google_linked=not m.get("google_disabled"))


@app.post("/profile/details")
@login_required
def profile_details():
    m = current_merchant()
    name = request.form.get("full_name", "").strip()[:60]
    phone = re.sub(r"[\s\-]", "", request.form.get("phone", "")).removeprefix("+91")
    support = request.form.get("support_link", "").strip()[:200]
    if not name:
        flash("Full name is required.", "error")
    elif phone and not re.fullmatch(r"[6-9]\d{9}", phone):
        flash("Enter a valid 10-digit Indian mobile number.", "error")
    elif support and not (re.match(r"^https?://", support, re.I) or EMAIL_RE.match(support) or support.startswith("@")):
        flash("Support / contact must be a link (https://...), an email, or a @username.", "error")
    else:
        get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {
            "full_name": name, "phone": phone, "support_link": support}})
        flash("Profile details updated.", "ok")
    return redirect(url_for("profile", tab="general"))


@app.post("/profile/email")
@login_required
def profile_email():
    m = current_merchant()
    new = request.form.get("new_email", "").strip().lower()
    if m.get("password_hash") and not check_password_hash(m["password_hash"], request.form.get("password", "")):
        flash("Password is incorrect.", "error")
    elif not EMAIL_RE.match(new):
        flash("Enter a valid email address.", "error")
    elif new == m["email"]:
        flash("That is already your email.", "error")
    else:
        try:
            get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"email": new}})
            flash("Email changed to %s." % new, "ok")
            send_mail("email_changed", m["email"], display_name(m), old_email=m["email"], new_email=new,
                      time=_now_ist(), secure_url=base_url() + url_for("profile", tab="security"))
        except DuplicateKeyError:
            flash("That email is already registered.", "error")
    return redirect(url_for("profile", tab="general"))


@app.post("/profile/avatar")
@login_required
def profile_avatar():
    m = current_merchant()
    if request.form.get("remove"):
        get_db().merchants.update_one({"_id": m["_id"]}, {"$unset": {"avatar": ""}})
        flash("Avatar removed. QR codes go back to plain.", "ok")
        return redirect(url_for("profile", tab="avatar"))
    f = request.files.get("avatar")
    if not f or not f.filename:
        flash("Choose an image first.", "error")
        return redirect(url_for("profile", tab="avatar"))
    try:
        data = _process_avatar(f.read())
    except Exception:  # noqa: BLE001 - any decode failure means "not a usable image"
        flash("That file is not a valid PNG, JPG, GIF or WebP image.", "error")
        return redirect(url_for("profile", tab="avatar"))
    get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"avatar": data}})
    flash("Avatar updated. It now appears in the centre of your QR codes.", "ok")
    return redirect(url_for("profile", tab="avatar"))


@app.errorhandler(413)
def too_large(_e):
    if request.path == "/profile/avatar":
        flash("Image is too large (max 600 KB).", "error")
        return redirect(url_for("profile", tab="avatar"))
    return "Request too large", 413


@app.post("/profile/password")
@login_required
def profile_password():
    m = current_merchant()
    cur = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    if m.get("password_hash") and not check_password_hash(m["password_hash"], cur):
        flash("Current password is incorrect.", "error")
    elif len(new) < 8:
        flash("New password must be at least 8 characters.", "error")
    elif new != request.form.get("confirm_password", ""):
        flash("The two new passwords do not match.", "error")
    else:
        get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"password_hash": generate_password_hash(new)}})
        flash("Password updated.", "ok")
        send_mail("password_changed", m["email"], display_name(m), time=_now_ist(), device=_device(),
                  location="IP " + (request.remote_addr or "Unknown"),
                  secure_url=base_url() + url_for("profile", tab="security"))
    return redirect(url_for("profile", tab="security"))


@app.get("/profile/google/link")
@login_required
def profile_google_link():
    if not google_enabled():
        abort(404)
    session["g_link"] = True
    return redirect(url_for("google_start"))


@app.post("/profile/google/unlink")
@login_required
def profile_google_unlink():
    m = current_merchant()
    if not m.get("password_hash"):
        flash("Set a password first, otherwise you would be locked out.", "error")
    else:
        get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"google_disabled": True}})
        flash("Google sign-in turned off for this account.", "ok")
    return redirect(url_for("profile", tab="social"))


# ---------------------------------------------------------------- integrations
DEFAULT_SENDERS = [s.strip() for s in os.environ.get("ALERT_SENDERS", "famapp.in").split(",") if s.strip()]


@app.route("/integrations", methods=["GET", "POST"])
@login_required
def integrations():
    m = current_merchant()
    if request.method == "POST":
        gmail = request.form.get("gmail", "").strip().lower()
        password = re.sub(r"\s", "", request.form.get("app_password", ""))
        upi = request.form.get("fampay_upi_id", "").strip()
        cfg = dict(m["imap"])
        if not EMAIL_RE.match(gmail):
            flash("Enter the Gmail address linked to FamPay.", "error")
        elif not UPI_ID_RE.match(upi):
            flash("That doesn't look like a valid UPI ID (example: name@fam).", "error")
        elif not password and not cfg.get("password_enc"):
            flash("Enter your 16-character Gmail App Password.", "error")
        elif password and not re.fullmatch(r"[A-Za-z0-9]{16}", password):
            flash("An App Password is exactly 16 letters, no spaces.", "error")
        else:
            secret = password or security.decrypt(cfg["password_enc"])
            err = poller.test_connection("imap.gmail.com", 993, gmail, secret)
            if err:
                flash("Gmail login failed: %s. Check the App Password and that IMAP is enabled." % err, "error")
                return redirect(url_for("integrations"))
            cfg.update(host="imap.gmail.com", port=993, user=gmail, enabled=True,
                       password_enc=security.encrypt(secret),
                       allowed_senders=cfg.get("allowed_senders") or DEFAULT_SENDERS)
            get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"imap": cfg, "upi_id": upi}})
            flash("Gmail connected. Payments will now be verified automatically.", "ok")
        return redirect(url_for("integrations"))
    imap = m["imap"]
    connected = bool(imap.get("enabled") and imap.get("user") and imap.get("password_enc"))
    return render_template("integrations.html", active="integrations", m=m, connected=connected,
                           has_password=bool(imap.get("password_enc")),
                           last_error=(m.get("imap_status") or {}).get("last_error"))


@app.post("/integrations/disconnect")
@login_required
def integrations_disconnect():
    m = current_merchant()
    cfg = dict(m["imap"])
    cfg.update(enabled=False, user="", password_enc=None)
    get_db().merchants.update_one({"_id": m["_id"]}, {"$set": {"imap": cfg}})
    flash("Gmail disconnected. Automatic verification is off.", "ok")
    return redirect(url_for("integrations"))


# ---------------------------------------------------------------- system status
def _status_snapshot() -> dict:
    now = services.utcnow()
    comps = [{"name": "API", "detail": "Order creation and status endpoints", "ok": True, "ms": None}]
    t0 = time.time()
    try:
        get_db().merchants.find_one({"_id": "__status_ping__"})
        comps.append({"name": "Database", "detail": "Orders, payments and accounts", "ok": True,
                      "ms": int((time.time() - t0) * 1000)})
        boxes = [x for x in get_db().merchants.find({"imap.enabled": True}).limit(500)]
        fresh = [x for x in boxes if (x.get("imap_status") or {}).get("last_poll_at")
                 and (now - x["imap_status"]["last_poll_at"]).total_seconds() < 600
                 and not x["imap_status"].get("last_error")]
        comps.append({"name": "Payment verification", "detail": "Mailbox polling and matching",
                      "ok": (not boxes) or bool(fresh), "ms": None,
                      "note": "%d of %d mailboxes checked in the last 10 minutes" % (len(fresh), len(boxes)) if boxes else "No mailboxes connected yet"})
        recent = list(get_db().deliveries.find({}).sort("created_at", -1).limit(200))
        bad = sum(1 for d in recent if d.get("status") == "failed")
        comps.append({"name": "Webhook delivery", "detail": "Signed callbacks to your servers",
                      "ok": not recent or bad / len(recent) < 0.5, "ms": None,
                      "note": ("%d of the last %d deliveries failed" % (bad, len(recent))) if recent else "No deliveries yet"})
    except Exception:  # noqa: BLE001 - a dead database must show as an outage, not a 500
        comps.append({"name": "Database", "detail": "Orders, payments and accounts", "ok": False, "ms": None})
    return {"ok": all(c["ok"] for c in comps), "components": comps,
            "uptime_seconds": int(time.time() - BOOT_TIME), "checked_at": now.isoformat()}


@app.get("/status")
def status_page():
    return render_template("status.html", active="status", snap=_status_snapshot())


@app.get("/status.json")
def status_json():
    return jsonify(_status_snapshot())


# ---------------------------------------------------------------- JSON API
def api_merchant():
    header = request.headers.get("Authorization", "")
    key = header[7:].strip() if header.lower().startswith("bearer ") else request.headers.get("X-API-Key", "")
    if not key:
        return None
    return get_db().merchants.find_one({"api_key_hash": security.hash_api_key(key)})


def api_error(message, status):
    return jsonify(error=message), status


@app.post("/api/v1/orders")
def api_create_order():
    m = api_merchant()
    if not m:
        return api_error("invalid or missing API key", 401)
    if rate_limited("api:" + m["_id"], 120, 60):
        return api_error("rate limit exceeded", 429)
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return api_error("body must be a JSON object", 400)
    try:
        amount = parse_amount(data.get("amount"))
        redirect_url = data.get("redirect_url") or None
        if redirect_url and not re.match(r"^https?://", str(redirect_url), re.I):
            raise services.OrderError("redirect_url must start with http:// or https://")
        callback = data.get("callback_url") or None
        if callback:
            ok, reason = security.is_safe_webhook_url(callback)
            if not ok:
                raise services.OrderError("callback_url: " + reason)
        order, created = services.create_order(
            get_db(), m, amount,
            order_ref=(str(data["order_ref"])[:100] if data.get("order_ref") else None),
            note=(str(data["note"])[:60] if data.get("note") else None),
            callback_url=callback, redirect_url=redirect_url,
            expires_in=int(data.get("expires_in", 900)))
    except (services.OrderError, ValueError, TypeError) as exc:
        status = exc.status if isinstance(exc, services.OrderError) else 400
        return api_error(str(exc), status)
    return jsonify(order_json(m, order, created)), (201 if created else 200)


@app.get("/api/v1/orders/<order_id>")
def api_get_order(order_id):
    m = api_merchant()
    if not m:
        return api_error("invalid or missing API key", 401)
    order = get_db().orders.find_one({"order_id": order_id, "merchant_id": m["_id"]})
    if not order:
        return api_error("order not found", 404)
    return jsonify(order_json(m, order))


# ---------------------------------------------------------------- background workers
def _loop(fn, interval, name):
    while True:
        try:
            fn(get_db())
        except Exception:  # noqa: BLE001 - keep the worker alive
            log.exception("%s crashed; retrying", name)
        time.sleep(interval)


def start_workers():
    threading.Thread(target=_loop, args=(poller.poll_all, POLL_SECONDS, "poller"), daemon=True).start()
    threading.Thread(target=_loop, args=(webhooks.deliver_due, 3, "webhooks"), daemon=True).start()
    log.info("background workers started")


if os.environ.get("RUN_WORKERS", "1") == "1" and os.environ.get("MONGODB_URI"):
    start_workers()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
