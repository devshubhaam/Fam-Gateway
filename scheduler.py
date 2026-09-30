"""Roz ke scheduled mails: Daily Digest, Monthly Statement, Getting Started,
Integration Reminder, Inactive Account.

Har mail se pehle scheduled_mail collection me ek "claim" (_id) insert hota hai.
_id unique hoti hai, isliye restart ya double run par bhi ek mail dobara nahi jati.
"""
import logging
import os
from datetime import datetime, timedelta, timezone

from pymongo.errors import DuplicateKeyError

from services import fmt_amount, utcnow

try:
    from famway_mailer import famway_mail
except ImportError:  # mailer missing: app chalti rahe, bas mail nahi
    def famway_mail(*_a, **_k):
        return {"ok": False, "error": "mailer missing"}

log = logging.getLogger("scheduler")

IST = timedelta(hours=5, minutes=30)
DIGEST_HOUR = int(os.environ.get("DIGEST_HOUR_IST", "9"))
INACTIVE_DAYS = int(os.environ.get("INACTIVE_DAYS", "30"))
MONTHS = ["January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December"]


def _aware(dt):
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _site():
    return os.environ.get("BASE_URL", "https://famgateway.in").rstrip("/")


def _name(m):
    return (m.get("full_name") or m.get("payee_name") or m["email"].split("@")[0])


def _eligible(m):
    return bool(m.get("email")) and m.get("email_verified") is not False and not m.get("suspended")


def _claim(db, key):
    """True agar ye mail pehli baar claim hui (yaani bhejni hai)."""
    try:
        db.scheduled_mail.insert_one({"_id": key, "created_at": utcnow()})
        return True
    except DuplicateKeyError:
        return False


def _send(db, key, event, m, params):
    if not _claim(db, key):
        return False
    try:
        r = famway_mail(event, m["email"], _name(m), {
            "dashboard_url": _site() + "/dashboard",
            "docs_url": _site() + "/docs",
            **params,
        })
        if not r.get("ok"):
            log.error("scheduled %s to %s failed: %s", event, m["email"], r.get("error"))
    except Exception:  # noqa: BLE001
        log.exception("scheduled %s crashed for %s", event, m.get("email"))
    return True


def _range_stats(db, mid, start, end):
    paid = list(db.orders.find({"merchant_id": mid, "status": "paid",
                                "paid_at": {"$gte": start, "$lt": end}}))
    failed = db.orders.count_documents({"merchant_id": mid, "status": "expired",
                                        "expires_at": {"$gte": start, "$lt": end}})
    total = sum(o.get("payable_paise", 0) for o in paid)
    return len(paid), total, failed


def daily_digest(db, now):
    ist = now + IST
    if ist.hour < DIGEST_HOUR:
        return
    today0 = (ist.replace(hour=0, minute=0, second=0, microsecond=0)) - IST
    start, end = today0 - timedelta(days=1), today0
    label = (ist - timedelta(days=1))
    for m in db.merchants.find({}):
        if not _eligible(m):
            continue
        count, total, failed = _range_stats(db, m["_id"], start, end)
        if count == 0 and failed == 0:
            continue
        key = f"digest:{m['_id']}:{label:%Y-%m-%d}"
        _send(db, key, "daily_digest", m, {
            "date": f"{label.day} {label:%b %Y}",
            "payments_count": str(count),
            "total_amount": "\u20b9" + fmt_amount(total),
            "amount": "\u20b9" + fmt_amount(total),
            "failed_count": str(failed),
            "pending_count": str(db.orders.count_documents({"merchant_id": m["_id"], "status": "pending"})),
        })


def monthly_statement(db, now):
    ist = now + IST
    if ist.day != 1 or ist.hour < DIGEST_HOUR:
        return
    this_month0 = ist.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    prev_last = this_month0 - timedelta(days=1)
    prev_month0 = prev_last.replace(day=1)
    start, end = prev_month0 - IST, this_month0 - IST
    for m in db.merchants.find({}):
        if not _eligible(m):
            continue
        count, total, failed = _range_stats(db, m["_id"], start, end)
        if count == 0:
            continue
        key = f"monthly:{m['_id']}:{prev_month0:%Y-%m}"
        avg = total // count if count else 0
        _send(db, key, "monthly_statement", m, {
            "month": f"{MONTHS[prev_month0.month - 1]} {prev_month0.year}",
            "payments_count": str(count),
            "total_amount": "\u20b9" + fmt_amount(total),
            "amount": "\u20b9" + fmt_amount(total),
            "average_amount": "\u20b9" + fmt_amount(avg),
            "failed_count": str(failed),
        })


def onboarding(db, now):
    """Getting Started (1 din baad) aur Integration Reminder (3 din baad, koi order nahi)."""
    for m in db.merchants.find({"created_at": {"$gte": now - timedelta(days=10)}}):
        if not _eligible(m):
            continue
        age = now - _aware(m["created_at"])
        if timedelta(days=1) <= age < timedelta(days=4):
            _send(db, f"getting_started:{m['_id']}", "getting_started", m, {})
        if age >= timedelta(days=3):
            if db.orders.count_documents({"merchant_id": m["_id"]}) == 0:
                _send(db, f"integration_reminder:{m['_id']}", "integration_reminder", m, {})


def inactive_accounts(db, now):
    """Jinhone INACTIVE_DAYS se koi order nahi banaya. Har 60 din me max ek baar."""
    cutoff = now - timedelta(days=INACTIVE_DAYS)
    period = now.toordinal() // 60
    for m in db.merchants.find({"created_at": {"$lt": cutoff}}):
        if not _eligible(m):
            continue
        if db.orders.count_documents({"merchant_id": m["_id"], "created_at": {"$gte": cutoff}}) > 0:
            continue
        _send(db, f"inactive:{m['_id']}:{period}", "inactive_account", m, {"days": str(INACTIVE_DAYS)})


def run_due(db):
    """app.py ka background loop ise har 5 minute me chalata hai."""
    now = utcnow()
    for fn in (daily_digest, monthly_statement, onboarding, inactive_accounts):
        try:
            fn(db, now)
        except Exception:  # noqa: BLE001
            log.exception("scheduler step %s failed", fn.__name__)
