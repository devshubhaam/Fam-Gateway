import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlencode

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

from security import new_order_id


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


MIN_PAISE = _int_env("MIN_AMOUNT_PAISE", 100)          # Rs 1
MAX_PAISE = _int_env("MAX_AMOUNT_PAISE", 10_000_000)   # Rs 1,00,000
MAX_OFFSET_PAISE = _int_env("MAX_AMOUNT_OFFSET_PAISE", 30)
GRACE_SECONDS = _int_env("LATE_PAYMENT_GRACE_SECONDS", 1800)
CLOCK_SKEW = timedelta(seconds=120)


class OrderError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def fmt_amount(paise: int) -> str:
    return f"{paise // 100}.{paise % 100:02d}"


def upi_link(merchant: dict, order: dict) -> str:
    params = {
        "pa": merchant["upi_id"],
        "pn": merchant.get("payee_name") or "Merchant",
        "am": fmt_amount(order["payable_paise"]),
        "cu": "INR",
        "tn": order.get("note") or order["order_id"],
    }
    return "upi://pay?" + urlencode(params, quote_via=quote)


def sweep_expired(db, merchant_id=None) -> int:
    query = {"status": "pending", "expires_at": {"$lt": utcnow()}}
    if merchant_id is not None:
        query["merchant_id"] = merchant_id
    return db.orders.update_many(query, {"$set": {"status": "expired"}}).modified_count


def create_order(db, merchant: dict, amount_paise: int, *, order_ref=None, note=None,
                 callback_url=None, redirect_url=None, expires_in=900, source=None) -> tuple[dict, bool]:
    """Returns (order, created). Re-uses a live pending order with the same order_ref."""
    if not merchant.get("upi_id"):
        raise OrderError("Set your UPI ID in the dashboard before creating orders", 409)
    if not isinstance(amount_paise, int) or not (MIN_PAISE <= amount_paise <= MAX_PAISE):
        raise OrderError(f"amount must be between {fmt_amount(MIN_PAISE)} and {fmt_amount(MAX_PAISE)} INR")
    expires_in = max(60, min(int(expires_in), 86400))

    sweep_expired(db, merchant["_id"])
    if order_ref:
        existing = db.orders.find_one({"merchant_id": merchant["_id"], "order_ref": order_ref,
                                       "status": "pending", "amount_paise": amount_paise})
        if existing:
            return existing, False

    now = utcnow()
    for offset in range(MAX_OFFSET_PAISE + 1):
        order = {
            "order_id": new_order_id(),
            "merchant_id": merchant["_id"],
            "order_ref": order_ref,
            "note": note,
            "source": source,
            "amount_paise": amount_paise,
            "payable_paise": amount_paise + offset,
            "status": "pending",
            "created_at": now,
            "expires_at": now + timedelta(seconds=expires_in),
            "grace_until": now + timedelta(seconds=expires_in + GRACE_SECONDS),
            "callback_url": callback_url,
            "redirect_url": redirect_url,
            "utr": None,
            "paid_at": None,
        }
        try:
            db.orders.insert_one(order)
            return order, True
        except DuplicateKeyError:
            continue  # another pending order already holds this payable amount
    raise OrderError("Too many pending orders with this amount right now; retry shortly", 429)


def build_payload(order: dict) -> dict:
    return {
        "event": "payment.success",
        "order_id": order["order_id"],
        "order_ref": order.get("order_ref"),
        "amount": fmt_amount(order["amount_paise"]),
        "payable_amount": fmt_amount(order["payable_paise"]),
        "currency": "INR",
        "utr": order.get("utr"),
        "paid_at": order["paid_at"].isoformat() if order.get("paid_at") else None,
        "paid_late": bool(order.get("paid_late")),
    }


def webhook_destinations(db, merchant: dict, order: dict) -> list:
    """(url, label) pairs: the order's callback (or the merchant default) plus every active endpoint."""
    dests = []

    def add(url, label):
        if url and url not in [u for u, _ in dests]:
            dests.append((url, label))

    if order.get("callback_url"):
        add(order["callback_url"], "Order callback")
    else:
        add(merchant.get("webhook_url"), "Default endpoint")
    for ep in db.webhook_endpoints.find({"merchant_id": merchant["_id"], "active": True}):
        add(ep.get("url"), ep.get("name") or "Endpoint")
    return dests


def queue_webhook(db, merchant: dict, order: dict):
    body = json.dumps(build_payload(order), separators=(",", ":"))
    for url, label in webhook_destinations(db, merchant, order):
        db.deliveries.insert_one({
            "did": secrets.token_hex(8),
            "merchant_id": merchant["_id"],
            "order_id": order["order_id"],
            "url": url,
            "endpoint_name": label,
            "body": body,
            "status": "pending",
            "attempts": 0,
            "next_attempt": utcnow(),
            "created_at": utcnow(),
        })


def settle_payment(db, merchant: dict, amount_paise: int, utr: str, received_at: datetime,
                   source: str = "email") -> str:
    """Record an incoming credit and match it to an order.

    Returns 'duplicate' | 'matched' | 'late_matched' | 'unmatched'.
    """
    mid = merchant["_id"]
    try:
        db.payments.insert_one({
            "merchant_id": mid, "utr": utr, "amount_paise": amount_paise,
            "received_at": received_at, "source": source, "status": "unmatched",
            "order_id": None, "created_at": utcnow(),
        })
    except DuplicateKeyError:
        return "duplicate"

    now = utcnow()
    base = {"merchant_id": mid, "payable_paise": amount_paise,
            "created_at": {"$lte": received_at + CLOCK_SKEW}}
    update = {"$set": {"status": "paid", "utr": utr, "paid_at": now}}

    order = db.orders.find_one_and_update(
        {**base, "status": "pending", "expires_at": {"$gte": received_at}},
        update, sort=[("created_at", 1)], return_document=ReturnDocument.AFTER)
    outcome = "matched"
    if order is None:
        order = db.orders.find_one_and_update(
            {**base, "status": {"$in": ["pending", "expired"]}, "grace_until": {"$gte": received_at}},
            {"$set": {"status": "paid", "utr": utr, "paid_at": now, "paid_late": True}},
            sort=[("created_at", -1)], return_document=ReturnDocument.AFTER)
        outcome = "late_matched"
    if order is None:
        return "unmatched"

    db.payments.update_one({"merchant_id": mid, "utr": utr},
                           {"$set": {"status": outcome, "order_id": order["order_id"]}})
    queue_webhook(db, merchant, order)
    return outcome
