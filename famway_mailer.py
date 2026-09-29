"""
FamWay Mailer (Brevo transactional templates) - Python

SETUP
  1. pip install requests
  2. Templates upload karo (bulk_upload_brevo.py) -> famway-template-ids.json ban jayegi
  3. BREVO_API_KEY ko environment variable me rakho (code me hardcode mat karo)

USAGE
  from famway_mailer import famway_mail

  famway_mail("otp", email, name, {"otp": "482913", "expiry_minutes": 10})

  famway_mail("payment_received", email, name, {
      "amount": "Rs 499.00",
      "order_id": "ORD123",
      "utr": "412345678901",
      "payer_upi": "rahul@upi",
      "time": "30 Sep 2026, 12:43 AM",
      "transaction_url": "https://famgateway.in/dashboard/tx/ORD123",
  })

  Result: {"ok": True/False, "message_id": ..., "error": ...}

  Flask/Django me request block na ho isliye slow jagah par background thread
  ya task queue (Celery/RQ) se call karna behtar hai.
"""
import json
import logging
import os
import threading
from datetime import datetime
from pathlib import Path

import requests

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
SUPPORT_EMAIL = "support@famgateway.in"  # <-- apna support email

# Event -> Brevo template ID (0 = abhi banaya nahi)
TEMPLATES = {
    'otp': 0,  # 01
    'welcome': 0,  # 02
    'password_reset': 0,  # 03
    'login_alert': 0,  # 04
    'email_changed': 0,  # 05
    'password_changed': 0,  # 06
    'account_verified': 0,  # 07
    'payment_received': 0,  # 08
    'payment_failed': 0,  # 09
    'refund_processed': 0,  # 10
    'settlement_summary': 0,  # 11
    'api_key_created': 0,  # 12
    'webhook_failing': 0,  # 13
    'usage_report': 0,  # 14
    'invoice': 0,  # 15
    'maintenance_notice': 0,  # 16
    'feedback_request': 0,  # 17
    'announcement': 0,  # 18
    'passkey_created': 0,  # 19
    'passkey_removed': 0,  # 20
    '2fa_enabled': 0,  # 21
    '2fa_disabled': 0,  # 22
    'email_verification': 0,  # 23
    'api_key_revoked': 0,  # 24
    'account_suspended': 0,  # 25
    'account_reactivated': 0,  # 26
    'account_deletion': 0,  # 27
    'webhook_recovered': 0,  # 28
    'webhook_secret_regen': 0,  # 29
    'whitelist_changed': 0,  # 30
    'rate_limit_warning': 0,  # 31
    'daily_digest': 0,  # 32
    'complaint_received': 0,  # 33
    'getting_started': 0,  # 34
    'integration_reminder': 0,  # 35
    'inactive_account': 0,  # 36
    'ticket_received': 0,  # 37
    'ticket_resolved': 0,  # 38
    'suspicious_activity': 0,  # 39
    'phone_changed': 0,  # 40
    'logged_out_all': 0,  # 41
    'recovery_codes_regen': 0,  # 42
    'policy_update': 0,  # 43
    'failed_payment_spike': 0,  # 44
    'monthly_statement': 0,  # 45
}

# bulk_upload_brevo.py ne jo IDs banayi wo yahan auto-load hoti hain
_ids_file = Path(__file__).resolve().parent / "famway-template-ids.json"
if _ids_file.exists():
    TEMPLATES.update(json.loads(_ids_file.read_text()))

log = logging.getLogger("famway_mailer")


def famway_mail(event: str, to_email: str, to_name: str = "", params: dict | None = None) -> dict:
    api_key = os.getenv("BREVO_API_KEY")
    if not api_key:
        return {"ok": False, "message_id": None, "error": "BREVO_API_KEY set nahi hai"}

    template_id = TEMPLATES.get(event, 0)
    if not template_id:
        return {"ok": False, "message_id": None, "error": f"Template ID missing: {event}"}

    # Common params jo har template me chahiye
    merged = {
        "name": to_name or "there",
        "support_email": SUPPORT_EMAIL,
        "year": datetime.now().year,
    }
    merged.update(params or {})

    payload = {
        "to": [{"email": to_email, "name": to_name or to_email}],
        "templateId": template_id,
        "params": merged,
    }
    headers = {"accept": "application/json", "content-type": "application/json", "api-key": api_key}

    try:
        r = requests.post(BREVO_API_URL, headers=headers, json=payload, timeout=15)
        data = r.json() if r.content else {}
    except requests.RequestException as e:
        log.error("Brevo request failed (%s): %s", event, e)
        return {"ok": False, "message_id": None, "error": str(e)}

    if 200 <= r.status_code < 300:
        return {"ok": True, "message_id": data.get("messageId"), "error": None}

    log.error("Brevo error (%s): HTTP %s %s", event, r.status_code, r.text)
    return {"ok": False, "message_id": None, "error": data.get("message", f"HTTP {r.status_code}")}


def famway_mail_async(event: str, to_email: str, to_name: str = "", params: dict | None = None) -> None:
    """Background thread me mail bhejta hai, request slow nahi hoti.
    Result nahi milta, fail hone par sirf log hota hai."""
    threading.Thread(
        target=famway_mail, args=(event, to_email, to_name, params), daemon=True
    ).start()
