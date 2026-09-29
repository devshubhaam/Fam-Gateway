import logging
from datetime import timedelta

import requests
from pymongo import ReturnDocument

from security import decrypt, is_safe_webhook_url, sign_webhook
from services import utcnow

log = logging.getLogger("webhooks")

BACKOFF_SECONDS = [10, 30, 120, 600, 3600, 21600]  # 6 attempts total


def deliver_due(db, limit: int = 20) -> int:
    sent = 0
    for _ in range(limit):
        now = utcnow()
        # Claim atomically and push next_attempt out as a lease so two workers never double-send.
        delivery = db.deliveries.find_one_and_update(
            {"status": "pending", "next_attempt": {"$lte": now}},
            {"$set": {"next_attempt": now + timedelta(seconds=60)}},
            sort=[("next_attempt", 1)], return_document=ReturnDocument.AFTER)
        if delivery is None:
            break
        attempt_delivery(db, delivery)
        sent += 1
    return sent


def attempt_delivery(db, delivery: dict):
    merchant = db.merchants.find_one({"_id": delivery["merchant_id"]})
    attempts = delivery["attempts"] + 1
    ok, error = False, ""
    if merchant is None or not merchant.get("webhook_secret_enc"):
        error = "merchant or webhook secret missing"
    else:
        safe, reason = is_safe_webhook_url(delivery["url"])
        if not safe:
            error = reason
        else:
            body = delivery["body"].encode()
            ts = str(int(utcnow().timestamp()))
            secret = decrypt(merchant["webhook_secret_enc"])
            try:
                resp = requests.post(
                    delivery["url"], data=body, timeout=8, allow_redirects=False,
                    headers={"Content-Type": "application/json", "X-Timestamp": ts,
                             "X-Signature": "sha256=" + sign_webhook(secret, ts, body),
                             "User-Agent": "upibridge-webhook/1.0"})
                ok = 200 <= resp.status_code < 300
                error = "" if ok else f"HTTP {resp.status_code}"
            except requests.RequestException as exc:
                error = str(exc)[:150]

    update = {"attempts": attempts, "last_error": error or None, "last_attempt_at": utcnow()}
    if ok:
        update["status"] = "done"
    elif attempts >= len(BACKOFF_SECONDS):
        update["status"] = "failed"
    else:
        update["next_attempt"] = utcnow() + timedelta(seconds=BACKOFF_SECONDS[attempts - 1])
    db.deliveries.update_one({"_id": delivery["_id"]}, {"$set": update})
    if not ok:
        log.info("webhook %s attempt %s failed: %s", delivery["order_id"], attempts, error)
