import logging
import os
import threading
import time

log = logging.getLogger("db")

_db = None
_lock = threading.Lock()


def get_db():
    global _db
    if _db is None:
        with _lock:
            if _db is None:
                from pymongo import MongoClient

                db = open_db()
                _db = db
    return _db


def open_db(report=None):
    """Connect and make sure indexes exist. Every network call has a timeout so nothing can hang forever."""
    from pymongo import MongoClient

    t = time.time()
    client = MongoClient(
        os.environ["MONGODB_URI"],
        serverSelectionTimeoutMS=8000, connectTimeoutMS=8000, socketTimeoutMS=20000,
        tz_aware=True,
    )
    db = client[os.environ.get("MONGODB_DB", "upibridge")]
    log.info("mongo client created in %.1fs; creating indexes", time.time() - t)
    ensure_indexes(db, report)
    log.info("mongo ready in %.1fs", time.time() - t)
    return db


def set_db(db):
    """Used by tests to inject a fake database."""
    global _db
    _db = db


def ensure_indexes(db, report=None):
    def step(name, fn):
        t = time.time()
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            msg = "index %s FAILED after %.1fs: %s: %s" % (name, time.time() - t, type(exc).__name__, str(exc)[:200])
            log.error(msg)
            if report is not None:
                report.append(msg)
            raise
        msg = "index %s ok %.1fs" % (name, time.time() - t)
        log.info(msg)
        if report is not None:
            report.append(msg)

    step("merchants.email", lambda: db.merchants.create_index("email", unique=True))
    step("merchants.api_key_hash", lambda: db.merchants.create_index("api_key_hash", unique=True, sparse=True))
    step("orders.order_id", lambda: db.orders.create_index("order_id", unique=True))
    step("orders.merchant_created", lambda: db.orders.create_index([("merchant_id", 1), ("created_at", -1)]))
    # Only one *pending* order per merchant may hold a given payable amount -> unambiguous matching.
    step("orders.pending_amount", lambda: db.orders.create_index(
        [("merchant_id", 1), ("payable_paise", 1)],
        unique=True,
        partialFilterExpression={"status": "pending"},
    ))
    # A bank UTR can settle at most one payment per merchant (idempotency).
    step("payments.utr", lambda: db.payments.create_index([("merchant_id", 1), ("utr", 1)], unique=True))
    step("passkeys.merchant", lambda: db.passkeys.create_index("merchant_id"))
    step("deliveries.merchant", lambda: db.deliveries.create_index([("merchant_id", 1), ("created_at", -1)]))
    step("deliveries.status", lambda: db.deliveries.create_index([("status", 1), ("next_attempt", 1)]))
    step("email_log.message", lambda: db.email_log.create_index([("merchant_id", 1), ("message_id", 1)]))
    step("email_log.ttl", lambda: db.email_log.create_index("created_at", expireAfterSeconds=7 * 86400))
