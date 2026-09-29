import hashlib
import imaplib
import logging
import os
import time
from datetime import datetime, timedelta, timezone

import mailparse as mailparser
from security import decrypt
from services import GRACE_SECONDS, settle_payment, sweep_expired, utcnow

log = logging.getLogger("poller")

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
IDLE_POLL_SECONDS = int(os.environ.get("IDLE_POLL_SECONDS", "300"))


def _imap_date(dt: datetime) -> str:
    return f"{dt.day:02d}-{MONTHS[dt.month - 1]}-{dt.year}"


def _log_email(db, merchant_id, message_id, sender, subject, result, **extra):
    db.email_log.insert_one({
        "merchant_id": merchant_id, "message_id": message_id, "sender": sender,
        "subject": (subject or "")[:120], "result": result, "created_at": utcnow(), **extra,
    })


def process_email(db, merchant: dict, raw: bytes) -> bool:
    """Handle one raw email. Returns True if it should be marked \\Seen."""
    msg = mailparser.load_message(raw)
    sender = mailparser.sender_address(msg)
    subject = msg.get("Subject", "")
    message_id = (msg.get("Message-ID") or "").strip() or \
        "sha1:" + hashlib.sha1(raw).hexdigest()
    mid = merchant["_id"]

    if db.email_log.find_one({"merchant_id": mid, "message_id": message_id}):
        return True  # already handled

    imap_cfg = merchant.get("imap", {})
    allowed = imap_cfg.get("allowed_senders", [])
    if not mailparser.sender_allowed(sender, allowed):
        return False  # not ours; leave it alone in the mailbox

    if imap_cfg.get("require_auth", True) and not mailparser.authenticated(msg, sender.split("@")[1]):
        _log_email(db, mid, message_id, sender, subject, "rejected: sender not authenticated (DKIM/DMARC)")
        return True

    parsed = mailparser.parse_credit(mailparser.extract_text(msg))
    if not parsed.is_credit or not parsed.amount_paise:
        _log_email(db, mid, message_id, sender, subject, f"ignored: {parsed.reason}")
        return True

    utr = parsed.utr or "msg-" + hashlib.sha1(message_id.encode()).hexdigest()[:16]
    outcome = settle_payment(db, merchant, parsed.amount_paise, utr,
                             mailparser.email_datetime(msg), source="email")
    _log_email(db, mid, message_id, sender, subject, outcome,
               amount_paise=parsed.amount_paise, utr=utr)
    return True


def poll_merchant(db, merchant: dict) -> int:
    cfg = merchant["imap"]
    password = decrypt(cfg["password_enc"])
    since = _imap_date(utcnow() - timedelta(days=3))
    handled = 0
    conn = imaplib.IMAP4_SSL(cfg["host"], int(cfg.get("port", 993)), timeout=25)
    try:
        conn.login(cfg["user"], password)
        conn.select("INBOX")
        uids = []
        for sender in cfg.get("allowed_senders", []):
            typ, data = conn.uid("search", None, "UNSEEN", "SINCE", since, "FROM", f'"{sender.strip()}"')
            if typ == "OK" and data and data[0]:
                uids.extend(data[0].split())
        for uid in sorted(set(uids), key=int):
            typ, data = conn.uid("fetch", uid, "(BODY.PEEK[])")
            if typ != "OK" or not data or not isinstance(data[0], tuple):
                continue
            if process_email(db, merchant, data[0][1]):
                conn.uid("store", uid, "+FLAGS", "\\Seen")
            handled += 1
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return handled


def has_active_orders(db, merchant_id) -> bool:
    cutoff = utcnow() - timedelta(seconds=GRACE_SECONDS)
    return db.orders.find_one({"merchant_id": merchant_id,
                               "$or": [{"status": "pending"},
                                       {"status": "expired", "expires_at": {"$gte": cutoff}}]}) is not None


def poll_all(db):
    sweep_expired(db)
    now = utcnow()
    for merchant in db.merchants.find({"imap.enabled": True}):
        last = merchant.get("imap_status", {}).get("last_poll_at")
        due = (not last) or (now - last).total_seconds() >= IDLE_POLL_SECONDS
        if not (has_active_orders(db, merchant["_id"]) or due):
            continue
        try:
            poll_merchant(db, merchant)
            status = {"last_poll_at": utcnow(), "last_error": None}
        except Exception as exc:  # noqa: BLE001 - surface any IMAP/login problem in the dashboard
            log.warning("poll failed for %s: %s", merchant.get("email"), exc)
            status = {"last_poll_at": utcnow(), "last_error": str(exc)[:200]}
        db.merchants.update_one({"_id": merchant["_id"]}, {"$set": {"imap_status": status}})


def test_connection(host: str, port: int, user: str, password: str) -> str:
    """Returns '' on success or an error message."""
    try:
        conn = imaplib.IMAP4_SSL(host, port, timeout=15)
        conn.login(user, password)
        conn.select("INBOX", readonly=True)
        conn.logout()
        return ""
    except Exception as exc:  # noqa: BLE001
        return str(exc)[:200]
