"""Passkey (WebAuthn) verification with only the `cryptography` package (already in requirements).

Registration uses attestation "none": we store the credential id + public key and never trust
the attestation statement. Login verifies the signature over authenticatorData || SHA-256(clientDataJSON).
Supported algorithms: ES256 (-7), RS256 (-257), EdDSA (-8).
"""
import base64
import hashlib
import hmac
import json
import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

ALGS = (-7, -257, -8)
FLAG_UP, FLAG_UV, FLAG_AT = 0x01, 0x04, 0x40


class PasskeyError(Exception):
    """Any reason a passkey ceremony must be rejected. The message is safe to show the user."""


def b64u_enc(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def b64u_dec(text: str) -> bytes:
    if not isinstance(text, str):
        raise PasskeyError("Malformed passkey response.")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise PasskeyError("Malformed passkey response.")


# ---------------------------------------------------------------- minimal CBOR (enough for COSE / attestation)
def _cbor(data: bytes, i: int = 0, depth: int = 0):
    """Decode one CBOR item. Returns (value, next_index)."""
    if depth > 8 or i >= len(data):
        raise PasskeyError("Malformed passkey data.")
    head = data[i]
    major, info = head >> 5, head & 0x1F
    i += 1
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        if i + size > len(data):
            raise PasskeyError("Malformed passkey data.")
        arg = int.from_bytes(data[i:i + size], "big")
        i += size
    else:
        raise PasskeyError("Unsupported CBOR encoding.")
    if major == 0:
        return arg, i
    if major == 1:
        return -1 - arg, i
    if major in (2, 3):
        if i + arg > len(data):
            raise PasskeyError("Malformed passkey data.")
        raw = data[i:i + arg]
        return (raw if major == 2 else raw.decode("utf-8", "replace")), i + arg
    if major == 4:
        if arg > 64:
            raise PasskeyError("Malformed passkey data.")
        out = []
        for _ in range(arg):
            item, i = _cbor(data, i, depth + 1)
            out.append(item)
        return out, i
    if major == 5:
        if arg > 64:
            raise PasskeyError("Malformed passkey data.")
        out = {}
        for _ in range(arg):
            k, i = _cbor(data, i, depth + 1)
            v, i = _cbor(data, i, depth + 1)
            out[k] = v
        return out, i
    if major == 7 and info in (20, 21, 22):
        return {20: False, 21: True, 22: None}[info], i
    raise PasskeyError("Unsupported CBOR encoding.")


# ---------------------------------------------------------------- COSE key -> cryptography key
def load_public_key(cose_bytes: bytes):
    cose, _ = _cbor(cose_bytes)
    if not isinstance(cose, dict):
        raise PasskeyError("Unsupported passkey key.")
    kty, alg = cose.get(1), cose.get(3)
    try:
        if kty == 2 and alg == -7 and cose.get(-1) == 1:
            x, y = cose[-2], cose[-3]
            if len(x) != 32 or len(y) != 32:
                raise PasskeyError("Unsupported passkey key.")
            return -7, ec.EllipticCurvePublicNumbers(
                int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        if kty == 3 and alg == -257:
            return -257, rsa.RSAPublicNumbers(
                int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-1], "big")).public_key()
        if kty == 1 and alg == -8 and cose.get(-1) == 6:
            return -8, ed25519.Ed25519PublicKey.from_public_bytes(cose[-2])
    except (KeyError, TypeError, ValueError):
        pass
    raise PasskeyError("This passkey uses an unsupported algorithm.")


def _verify_signature(alg: int, key, signature: bytes, signed: bytes) -> None:
    try:
        if alg == -7:
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif alg == -257:
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            key.verify(signature, signed)
    except InvalidSignature:
        raise PasskeyError("Passkey signature is not valid.")


# ---------------------------------------------------------------- shared checks
def _client_data(raw_b64: str, kind: str, challenge: str, origin: str):
    raw = b64u_dec(raw_b64)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise PasskeyError("Malformed passkey response.")
    if data.get("type") != kind:
        raise PasskeyError("Wrong passkey request type.")
    if not hmac.compare_digest(str(data.get("challenge", "")), challenge):
        raise PasskeyError("Passkey challenge did not match. Please try again.")
    allowed = (origin,) if isinstance(origin, str) else tuple(origin)
    if data.get("origin") not in allowed:
        raise PasskeyError("Passkey was created for a different website.")
    if data.get("crossOrigin"):
        raise PasskeyError("Passkey cannot be used inside a cross-origin frame.")
    return raw


def _check_auth_data(auth: bytes, rp_id: str, require_uv: bool):
    if len(auth) < 37:
        raise PasskeyError("Malformed passkey response.")
    if not hmac.compare_digest(auth[:32], hashlib.sha256(rp_id.encode()).digest()):
        raise PasskeyError("Passkey belongs to a different domain.")
    flags = auth[32]
    if not flags & FLAG_UP:
        raise PasskeyError("Passkey did not confirm user presence.")
    if require_uv and not flags & FLAG_UV:
        raise PasskeyError("Passkey needs your fingerprint, face or screen lock.")
    return flags, struct.unpack(">I", auth[33:37])[0]


# ---------------------------------------------------------------- registration
def verify_registration(client_data_b64, attestation_b64, challenge, origin, rp_id, require_uv=True) -> dict:
    _client_data(client_data_b64, "webauthn.create", challenge, origin)
    att, _ = _cbor(b64u_dec(attestation_b64))
    if not isinstance(att, dict) or not isinstance(att.get("authData"), bytes):
        raise PasskeyError("Malformed passkey response.")
    auth = att["authData"]
    flags, sign_count = _check_auth_data(auth, rp_id, require_uv)
    if not flags & FLAG_AT or len(auth) < 55:
        raise PasskeyError("Passkey did not include a credential.")
    cred_len = int.from_bytes(auth[53:55], "big")
    if cred_len == 0 or cred_len > 1023 or len(auth) < 55 + cred_len:
        raise PasskeyError("Malformed passkey response.")
    cred_id = auth[55:55 + cred_len]
    _cose, end = _cbor(auth, 55 + cred_len)
    cose_bytes = auth[55 + cred_len:end]          # stored exactly as the authenticator sent it
    alg, _key = load_public_key(cose_bytes)
    if alg not in ALGS:
        raise PasskeyError("This passkey uses an unsupported algorithm.")
    return {"credential_id": b64u_enc(cred_id), "public_key": b64u_enc(cose_bytes),
            "alg": alg, "sign_count": sign_count, "aaguid": auth[37:53].hex()}


# ---------------------------------------------------------------- authentication
def verify_authentication(client_data_b64, auth_data_b64, signature_b64, public_key_b64, stored_count,
                          challenge, origin, rp_id, require_uv=True) -> int:
    """Returns the new signature counter. Raises PasskeyError on any problem."""
    client_raw = _client_data(client_data_b64, "webauthn.get", challenge, origin)
    auth = b64u_dec(auth_data_b64)
    _flags, new_count = _check_auth_data(auth, rp_id, require_uv)
    alg, key = load_public_key(b64u_dec(public_key_b64))
    _verify_signature(alg, key, b64u_dec(signature_b64), auth + hashlib.sha256(client_raw).digest())
    # counters of 0 mean "not supported" (synced passkeys); otherwise it must go up or the key was cloned
    if (new_count or stored_count) and new_count <= stored_count:
        raise PasskeyError("This passkey looks cloned and was blocked. Remove it and add a new one.")
    return new_count
