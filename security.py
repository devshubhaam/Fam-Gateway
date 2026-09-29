import base64
import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken


def _fernet() -> Fernet:
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        secret = os.environ.get("SECRET_KEY")
        if not secret:
            raise RuntimeError("Set SECRET_KEY (or ENCRYPTION_KEY) in the environment")
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()).decode()
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt(text: str) -> str:
    return _fernet().encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Could not decrypt stored secret (was SECRET_KEY changed?)") from exc


def new_api_key() -> str:
    return "sk_live_" + secrets.token_urlsafe(24)


def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def new_webhook_secret() -> str:
    return "whsec_" + secrets.token_urlsafe(24)


def new_order_id() -> str:
    return "ord_" + secrets.token_urlsafe(9).replace("-", "a").replace("_", "b")


def sign_webhook(secret: str, timestamp: str, body: bytes) -> str:
    msg = timestamp.encode() + b"." + body
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def new_csrf_token() -> str:
    return secrets.token_urlsafe(24)


def safe_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def is_safe_webhook_url(url: str) -> tuple[bool, str]:
    """Reject non-http(s) URLs and hosts that resolve to private/loopback/link-local space."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "Invalid URL"
    allow_http = os.environ.get("ALLOW_HTTP_WEBHOOKS", "0") == "1"
    if parsed.scheme not in (("https", "http") if allow_http else ("https",)):
        return False, "Webhook URL must start with https://"
    host = parsed.hostname
    if not host:
        return False, "Webhook URL has no host"
    if os.environ.get("ALLOW_PRIVATE_WEBHOOKS", "0") == "1":
        return True, ""
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror:
        return False, "Webhook host could not be resolved"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
                or ip.is_multicast or ip.is_unspecified):
            return False, "Webhook host resolves to a private address"
    return True, ""
