import os
import threading

_db = None
_lock = threading.Lock()


def get_db():
    global _db
    if _db is None:
        with _lock:
            if _db is None:
                from pymongo import MongoClient

                client = MongoClient(os.environ["MONGODB_URI"], serverSelectionTimeoutMS=8000, tz_aware=True)
                db = client[os.environ.get("MONGODB_DB", "upibridge")]
                ensure_indexes(db)
                _db = db
    return _db


def set_db(db):
    """Used by tests to inject a fake database."""
    global _db
    _db = db


def ensure_indexes(db):
    db.merchants.create_index("email", unique=True)
    db.merchants.create_index("api_key_hash", unique=True, sparse=True)
    db.orders.create_index("order_id", unique=True)
    db.orders.create_index([("merchant_id", 1), ("created_at", -1)])
    # Only one *pending* order per merchant may hold a given payable amount -> unambiguous matching.
    db.orders.create_index(
        [("merchant_id", 1), ("payable_paise", 1)],
        unique=True,
        partialFilterExpression={"status": "pending"},
    )
    # A bank UTR can settle at most one payment per merchant (idempotency).
    db.payments.create_index([("merchant_id", 1), ("utr", 1)], unique=True)
    db.deliveries.create_index([("status", 1), ("next_attempt", 1)])
    db.email_log.create_index([("merchant_id", 1), ("message_id", 1)])
    db.email_log.create_index("created_at", expireAfterSeconds=7 * 86400)
