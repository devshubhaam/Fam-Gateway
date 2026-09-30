import logging
import os
from datetime import timedelta

import requests
from pymongo import ReturnDocument

from security import decrypt, is_safe_webhook_url, sign_webhook
from services import utcnow

try:
    from famway_mailer import famway_mail_async
except ImportError:  # mailer file missing: webhooks still work, just no emails
    def famway_mail_async(*_args, **_kwargs):
        return None

log = logging.getLogger("webhooks")

FAIL_ALERT_AFTER = 3  # email the merchant once an endpoint has failed this many attempts in a row

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
    status_code, resp_text = None, None
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
                status_code = resp.status_code
                text = getattr(resp, "text", "")
                resp_text = text[:500] if isinstance(text, str) else ""
                ok = 200 <= resp.status_code < 300
                error = "" if ok else f"HTTP {resp.status_code}"
            except requests.RequestException as exc:
                error = str(exc)[:150]

    update = {"attempts": attempts, "last_error": error or None, "last_attempt_at": utcnow(),
              "last_status": status_code, "last_response": resp_text}
    if ok:
        update["status"] = "done"
    elif attempts >= len(BACKOFF_SECONDS):
        update["status"] = "failed"
    else:
        update["next_attempt"] = utcnow() + timedelta(seconds=BACKOFF_SECONDS[attempts - 1])
    db.deliveries.update_one({"_id": delivery["_id"]}, {"$set": update})
    if not ok:
        log.info("webhook %s attempt %s failed: %s", delivery["order_id"], attempts, error)
    _webhook_health_mail(db, merchant, delivery, ok, attempts, status_code, error)


def _webhook_health_mail(db, merchant, delivery, ok: bool, attempts: int, status_code, error: str):
    """Email 'webhook failing' once per outage and 'webhook recovered' when it works again. Never raises."""
    try:
        if not merchant or not merchant.get("email"):
            return
        url = delivery["url"]
        key = f"{merchant['_id']}|{url}"
        now = utcnow()
        site = os.environ.get("BASE_URL", "https://famgateway.in").rstrip("/")
        ist = now + timedelta(hours=5, minutes=30)
        when = f"{ist.day} {ist:%b %Y}, {ist:%I:%M %p} IST"
        name = merchant.get("full_name") or merchant.get("payee_name") or merchant["email"].split("@")[0]
        state = db.webhook_state.find_one({"_id": key}) or {}
        if not ok and attempts >= FAIL_ALERT_AFTER and not state.get("failing"):
            db.webhook_state.replace_one({"_id": key}, {"_id": key, "failing": True, "since": now}, upsert=True)
            famway_mail_async("webhook_failing", merchant["email"], name, {
                "endpoint_url": url, "failed_attempts": str(attempts),
                "status_code": str(status_code) if status_code else (error or "No response"),
                "time": when, "logs_url": site + "/webhooks"})
        elif ok and state.get("failing"):
            since = state.get("since") or now
            delivered = db.deliveries.count_documents(
                {"merchant_id": merchant["_id"], "url": url, "status": "done", "last_attempt_at": {"$gte": since}})
            db.webhook_state.replace_one({"_id": key}, {"_id": key, "failing": False, "since": None}, upsert=True)
            famway_mail_async("webhook_recovered", merchant["email"], name, {
                "endpoint_url": url, "delivered_events": str(max(delivered, 1)),
                "time": when, "logs_url": site + "/webhooks"})
    except Exception:  # noqa: BLE001 - a mail problem must never break webhook delivery
        log.exception("webhook health mail failed")
