"""Turn a raw bank/UPI-app email into (amount, utr) — or reject it.

IMPORTANT: real bank/app emails differ. The regexes below are generic defaults.
If credits are not being detected, look at the "Recent emails" table in the
dashboard and tune CREDIT_WORDS / AMOUNT_RE / UTR_RES for your sender.
"""
import html
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from email import message_from_bytes, policy
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime, timezone
from typing import Optional

CREDIT_WORDS = r"(?:credited|received|deposited|paid you|sent you)"
DEBIT_WORDS = r"(?:debited|paid to|sent to|withdrawn)"
AMOUNT_RE = r"(?:₹|Rs\.?|INR)\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)"

UTR_RES = [
    re.compile(r"(?:UTR|RRN|Ref(?:erence)?(?:\s*(?:No|Number|ID))?\.?|Txn(?:\s*ID)?|UPI\s*Ref)\D{0,20}(\d{12})", re.I),
    re.compile(r"(?<!\d)(\d{12})(?!\d)"),
]


@dataclass
class ParsedCredit:
    amount_paise: Optional[int] = None
    utr: Optional[str] = None
    is_credit: bool = False
    reason: str = ""


def to_paise(value: str) -> Optional[int]:
    try:
        return int((Decimal(value.replace(",", "")) * 100).to_integral_value())
    except (InvalidOperation, ValueError):
        return None


def normalize(text: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html.unescape(text).replace("\xa0", " ")
    return re.sub(r"\s+", " ", text).strip()


def parse_credit(text: str) -> ParsedCredit:
    text = normalize(text)
    has_credit = re.search(CREDIT_WORDS, text, re.I) is not None
    has_debit = re.search(DEBIT_WORDS, text, re.I) is not None
    if not has_credit:
        return ParsedCredit(reason="debit" if has_debit else "no credit wording")

    amount = None
    near = re.search(CREDIT_WORDS + r"(?:(?!balance)[^0-9₹]){0,60}" + AMOUNT_RE, text, re.I)
    if not near:
        near = re.search(AMOUNT_RE + r"[^.]{0,60}?" + CREDIT_WORDS, text, re.I)
    if near:
        amount = to_paise(near.group(1))
    else:
        found = {m for m in re.findall(AMOUNT_RE, text, re.I)}
        if len(found) == 1:
            amount = to_paise(next(iter(found)))
    if not amount or amount <= 0:
        return ParsedCredit(is_credit=True, reason="credit found but no amount")

    utr = None
    for rx in UTR_RES:
        m = rx.search(text)
        if m:
            utr = m.group(1)
            break
    return ParsedCredit(amount_paise=amount, utr=utr, is_credit=True, reason="ok")


def extract_text(msg) -> str:
    parts = [msg.get("Subject", "") or ""]
    plain, html_parts = [], []
    for part in msg.walk():
        ctype = part.get_content_type()
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except Exception:
            continue
        if not isinstance(content, str):
            continue
        (plain if ctype == "text/plain" else html_parts if ctype == "text/html" else []).append(content)
    parts.extend(plain if plain else html_parts)
    return "\n".join(parts)


def sender_address(msg) -> str:
    return parseaddr(msg.get("From", ""))[1].lower()


def sender_allowed(address: str, allowed: list) -> bool:
    if not address or "@" not in address or not allowed:
        return False
    domain = address.split("@", 1)[1]
    for entry in allowed:
        entry = entry.strip().lower().lstrip("@")
        if not entry:
            continue
        if "@" in entry:
            if address == entry:
                return True
        elif domain == entry or domain.endswith("." + entry):
            return True
    return False


def _aligned(d: str, from_domain: str) -> bool:
    d, from_domain = d.lower().strip(), from_domain.lower()
    return d == from_domain or from_domain.endswith("." + d) or d.endswith("." + from_domain)


def authenticated(msg, from_domain: str) -> bool:
    """True if the receiving server recorded a passing, domain-aligned DKIM or DMARC result."""
    for header in msg.get_all("Authentication-Results", []) or []:
        h = str(header)
        for m in re.finditer(r"dkim=pass[^;]*?header\.d=([^\s;]+)", h, re.I):
            if _aligned(m.group(1), from_domain):
                return True
        m = re.search(r"dmarc=pass[^;]*?header\.from=([^\s;]+)", h, re.I)
        if m and _aligned(m.group(1), from_domain):
            return True
    return False


def email_datetime(msg) -> datetime:
    try:
        dt = parsedate_to_datetime(msg.get("Date"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def load_message(raw: bytes):
    return message_from_bytes(raw, policy=policy.default)
