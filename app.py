import io
import logging
import os
import re
import secrets
import threading
import time
from urllib.parse import urlencode
from collections import defaultdict
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template, request,
                   session, url_for, Response)
import requests
from pymongo.errors import DuplicateKeyError
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
    return {"brand": BRAND, "csrf": session["csrf"], "me": current_merchant()}


@app.before_request
def csrf_protect():
    if request.method == "POST" and not request.path.startswith("/api/"):
        sent = request.form.get("csrf", "")
        if not sent or not security.safe_equals(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


@app.after_request
def headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    if request.path.startswith(("/dashboard", "/login", "/register")):
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
    return render_template("docs.html", base=base_url())


@app.get("/healthz")
def healthz():
    return {"ok": True}


# ---------------------------------------------------------------- auth
def create_merchant(email: str, password_hash: str):
    """Insert a new merchant. Returns (merchant, plaintext_api_key). Raises DuplicateKeyError."""
    api_key = security.new_api_key()
    merchant = {
        "_id": "m_" + secrets.token_hex(8),
        "email": email,
        "password_hash": password_hash,
        "created_at": services.utcnow(),
        "upi_id": "", "payee_name": "", "webhook_url": "",
        "api_key_hash": security.hash_api_key(api_key),
        "api_key_prefix": api_key[:12],
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
            merchant, api_key = create_merchant(email, generate_password_hash(password))
        except DuplicateKeyError:
            flash("That email is already registered.", "error")
            return render_template("auth.html", mode="register"), 409
        session.clear()
        session["mid"] = merchant["_id"]
        session["new_api_key"] = api_key
        return redirect(url_for("dashboard"))
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if rate_limited("login:" + request.remote_addr, 10, 300):
            flash("Too many attempts. Try again in a few minutes.", "error")
            return render_template("auth.html", mode="login"), 429
        email = request.form.get("email", "").strip().lower()
        merchant = get_db().merchants.find_one({"email": email})
        if merchant and merchant.get("password_hash") and check_password_hash(merchant["password_hash"], request.form.get("password", "")):
            session.clear()
            session["mid"] = merchant["_id"]
            return redirect(url_for("dashboard"))
        flash("Wrong email or password.", "error")
        return render_template("auth.html", mode="login"), 401
    return render_template("auth.html", mode="login")


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

    merchant = get_db().merchants.find_one({"email": email})
    if merchant:
        session.clear()
        session["mid"] = merchant["_id"]
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
    t = time.time()
    try:
        dbmod.open_db(lines)
        lines.append("DB + INDEXES: OK in %.1fs" % (time.time() - t))
    except Exception as exc:  # noqa: BLE001
        lines.append("FAILED after %.1fs: %s: %s" % (time.time() - t, type(exc).__name__, str(exc)[:300]))
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
    try:
        webhook_secret = security.decrypt(m["webhook_secret_enc"])
    except ValueError:
        webhook_secret = "(unreadable - SECRET_KEY changed)"
    return render_template(
        "dashboard.html", m=m, orders=orders, payments=payments, emails=emails,
        failed_webhooks=failed, webhook_secret=webhook_secret,
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
        "api_key_hash": security.hash_api_key(key), "api_key_prefix": key[:12]}})
    session["new_api_key"] = key
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
    return render_template("pay.html", merchant=merchant, order=order,
                           status=effective_status(order), fmt=services.fmt_amount,
                           link=services.upi_link(merchant, order))


@app.get("/api/public/orders/<order_id>")
def public_status(order_id):
    _, order = _order_or_404(order_id)
    return jsonify(status=effective_status(order),
                   redirect_url=order.get("redirect_url") if order["status"] == "paid" else None)


@app.get("/qr/<order_id>.svg")
def qr(order_id):
    import segno
    merchant, order = _order_or_404(order_id)
    buf = io.BytesIO()
    segno.make(services.upi_link(merchant, order), error="m").save(buf, kind="svg", scale=8, border=2)
    return Response(buf.getvalue(), mimetype="image/svg+xml",
                    headers={"Cache-Control": "private, max-age=60"})


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
