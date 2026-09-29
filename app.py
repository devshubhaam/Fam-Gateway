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
            merchant, api_key = create_merchant(email, generate_password_hash(password))
        except DuplicateKeyError:
            flash("That email is already registered.", "error")
            return render_template("auth.html", mode="register"), 409
        except Exception as exc:  # noqa: BLE001 - show the reason on screen instead of a blank 500
            log.exception("register failed")
            flash("Server error: %s: %s" % (type(exc).__name__, str(exc)[:200]), "error")
            return render_template("auth.html", mode="register"), 500
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
