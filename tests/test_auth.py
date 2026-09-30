"""Register / Login pages (Google + Email + Passkey). Uses a software authenticator to exercise real WebAuthn checks."""
import hashlib
import json
import os
import struct
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402

fakes.install()
os.environ.update(SECRET_KEY="test-secret", RUN_WORKERS="0", INSECURE_COOKIES="1")
os.environ.pop("MONGODB_URI", None)

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import db as dbmod  # noqa: E402
import passkeys  # noqa: E402

dbmod.set_db(fakes.FakeDB())
import app as appmod  # noqa: E402

ORIGIN, RP_ID = "https://x.test", "x.test"
ENV = {"BASE_URL": ORIGIN, "GOOGLE_CLIENT_ID": "cid", "GOOGLE_CLIENT_SECRET": "csec"}


def fresh():
    d = fakes.FakeDB()
    dbmod.ensure_indexes(d)
    dbmod.set_db(d)
    return d


# ---------------------------------------------------------------- tiny CBOR writer + software authenticator
def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + n.to_bytes(2, "big")


def cbor(v):
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        raw = v.encode()
        return _head(3, len(raw)) + raw
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, dict):
        return _head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


class Authenticator:
    def __init__(self, uv=True):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.counter = 0
        self.uv = uv

    def _flags(self, extra=0):
        return 0x01 | (0x04 if self.uv else 0) | extra

    def create(self, options, origin=ORIGIN, rp_id=RP_ID):
        nums = self.key.public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth = (hashlib.sha256(rp_id.encode()).digest() + bytes([self._flags(0x40)]) + struct.pack(">I", 0)
                + bytes(16) + len(self.cred_id).to_bytes(2, "big") + self.cred_id + cose)
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": origin}).encode()
        att = cbor({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": passkeys.b64u_enc(self.cred_id),
                "response": {"clientDataJSON": passkeys.b64u_enc(client), "attestationObject": passkeys.b64u_enc(att)}}

    def get(self, options, handle, origin=ORIGIN, rp_id=RP_ID, counter=None, bad_sig=False):
        self.counter = self.counter + 1 if counter is None else counter
        auth = hashlib.sha256(rp_id.encode()).digest() + bytes([self._flags()]) + struct.pack(">I", self.counter)
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}).encode()
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        if bad_sig:
            sig = sig[:-1] + bytes([sig[-1] ^ 1])
        return {"id": passkeys.b64u_enc(self.cred_id), "response": {
            "clientDataJSON": passkeys.b64u_enc(client), "authenticatorData": passkeys.b64u_enc(auth),
            "signature": passkeys.b64u_enc(sig), "userHandle": passkeys.b64u_enc(handle.encode()) if handle else ""}}


class AuthBase(unittest.TestCase):
    def setUp(self):
        self.db = fresh()
        appmod.app.config["TESTING"] = True
        appmod._hits.clear()
        self.c = appmod.app.test_client()
        p = mock.patch.dict(os.environ, ENV)
        p.start()
        self.addCleanup(p.stop)

    def csrf(self, c=None, path="/login"):
        html = (c or self.c).get(path).get_data(as_text=True)
        return html.split('name="csrf" value="')[1].split('"')[0]

    def signup_data(self, **over):
        d = {"name": "Test User", "email": "u@x.io", "phone": "9876543210",
             "password": "password123", "confirm_password": "password123"}
        d.update(over)
        return d

    def register(self, c=None):
        """Full signup incl. the email code, leaves the client logged in."""
        c = c or self.c
        sent = []
        with mock.patch.object(appmod, "famway_mail_async", lambda ev, to, name, params: sent.append((ev, params))):
            r = c.post("/register", data={"csrf": self.csrf(c, "/register"), **self.signup_data()})
            self.assertEqual(r.status_code, 302)
            code = next(p["otp"] for ev, p in sent if ev == "otp")
            r = c.post("/verify-email", data={"csrf": self.csrf(c, "/verify-email"), "code": code})
        self.assertEqual(r.status_code, 302)
        return self.db.merchants.find_one({"email": "u@x.io"})


class PageTests(AuthBase):
    def test_register_page_matches_design(self):
        html = self.c.get("/register").get_data(as_text=True)
        for text in ["Register for", "Free forever. No credit card required.", "Continue with Google",
                     "or sign up with email", "Full Name", "Email address", "Phone Number (WhatsApp)", "+91",
                     "Confirm Password", "Create Account", "Already have an account?", "Get started<br><span>in minutes.</span>",
                     "Free forever &mdash; zero platform fees", "Configure UPI Notifications in 30 seconds",
                     "Instant API key &amp; live webhook alerts", "Independent developer tool. Not affiliated with Tri O Tech",
                     "famgateway-logo.png", "auth-register", "By creating an account, you agree to our"]:
            self.assertIn(text, html, text)
        self.assertNotIn("Passkey", html)          # sign-up is Google + Email only

    def test_login_page_matches_design(self):
        html = self.c.get("/login").get_data(as_text=True)
        for text in ["Sign In to", "Sign in to your", "Google", "Passkey", "or sign in with email", "Forgot password?",
                     "Keep me signed in for 7 days", "Sign In &rarr;", "Create one free", "UPI payments,<br><span>automated.</span>",
                     "Real-time automated UPI transaction matching", "Instant webhook callbacks on payment",
                     "auth-login", "grid-template-columns:1fr 1fr"]:
            self.assertIn(text, html, text)

    def test_google_button_hidden_when_not_configured(self):
        with mock.patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "", "GOOGLE_CLIENT_SECRET": ""}):
            html = self.c.get("/register").get_data(as_text=True)
            self.assertNotIn("Continue with Google", html)
            self.assertIn("grid-template-columns:1fr;", self.c.get("/login").get_data(as_text=True))

    def test_static_assets_served(self):
        for path in ["/static/auth.css", "/static/famgateway-logo.png", "/static/favicon.png"] + \
                    ["/static/fonts/poppins-%d.woff2" % w for w in (300, 400, 500, 600, 700)]:
            self.assertEqual(self.c.get(path).status_code, 200, path)

    def test_otp_and_forgot_pages_use_auth_layout(self):
        html = self.c.get("/forgot").get_data(as_text=True)
        self.assertIn("auth-form-card", html)
        self.assertIn("Send code", html)

    def test_turnstile_widget_only_when_configured(self):
        self.assertNotIn("cf-turnstile", self.c.get("/register").get_data(as_text=True))
        with mock.patch.dict(os.environ, {"TURNSTILE_SITE_KEY": "0xSITE", "TURNSTILE_SECRET_KEY": "sec"}):
            self.assertIn('data-sitekey="0xSITE"', self.c.get("/register").get_data(as_text=True))


class EmailSignupTests(AuthBase):
    def post_reg(self, **over):
        return self.c.post("/register", data={"csrf": self.csrf(path="/register"), **self.signup_data(**over)})

    def test_signup_saves_name_and_phone(self):
        m = self.register()
        self.assertEqual((m["full_name"], m["phone"]), ("Test User", "9876543210"))

    def test_validation_errors_keep_typed_values(self):
        cases = [({"confirm_password": "different1"}, "do not match"), ({"phone": "12345"}, "10-digit"),
                 ({"name": "  "}, "full name"), ({"password": "short", "confirm_password": "short"}, "at least 8"),
                 ({"email": "nope"}, "valid email")]
        for over, msg in cases:
            r = self.post_reg(**over)
            self.assertEqual(r.status_code, 400, over)
            self.assertIn(msg, r.get_data(as_text=True))
            self.assertIsNone(self.db.merchants.find_one({"email": "u@x.io"}))
        self.assertIn('value="9876543210"', self.post_reg(confirm_password="x").get_data(as_text=True))

    def test_phone_with_plus91_accepted(self):
        with mock.patch.object(appmod, "famway_mail_async", lambda *a: None):
            self.assertEqual(self.post_reg(phone="+91 98765 43210").status_code, 302)
        self.assertEqual(self.db.merchants.find_one({"email": "u@x.io"})["phone"], "9876543210")

    def test_turnstile_blocks_and_allows(self):
        with mock.patch.dict(os.environ, {"TURNSTILE_SITE_KEY": "s", "TURNSTILE_SECRET_KEY": "k"}):
            self.assertEqual(self.post_reg().status_code, 400)
            tok = self.csrf(path="/register")

            class R:
                def json(self):
                    return {"success": True}
            with mock.patch.object(appmod.requests, "post", return_value=R()), \
                    mock.patch.object(appmod, "famway_mail_async", lambda *a: None):
                r = self.c.post("/register", data={"csrf": tok, "cf-turnstile-response": "tok", **self.signup_data()})
            self.assertEqual(r.status_code, 302)

    def test_remember_me_sets_persistent_cookie(self):
        m = self.register()
        c = appmod.app.test_client()
        tok = self.csrf(c)
        with mock.patch.object(appmod, "famway_mail_async", lambda *a: None):
            r = c.post("/login", data={"csrf": tok, "email": "u@x.io", "password": "password123", "remember": "1"})
        self.assertEqual(r.status_code, 302)              # -> /login/otp (2-step) since this browser is new
        self.assertTrue(c.get("/login/otp").status_code == 200 and m)

    def test_login_wrong_password_keeps_email(self):
        self.register()
        c = appmod.app.test_client()
        r = c.post("/login", data={"csrf": self.csrf(c), "email": "u@x.io", "password": "wrongwrong"})
        self.assertEqual(r.status_code, 401)
        self.assertIn('value="u@x.io"', r.get_data(as_text=True))


class PasskeyTests(AuthBase):
    def add_passkey(self, c, auth):
        tok = self.csrf(c, "/profile?tab=security")
        hdr = {"X-CSRF-Token": tok}
        opts = c.post("/passkey/register/begin", headers=hdr).get_json()
        self.assertTrue(opts["ok"], opts)
        o = opts["options"]
        self.assertEqual(o["rp"]["id"], RP_ID)
        self.assertEqual(o["authenticatorSelection"]["userVerification"], "required")
        body = auth.create(o)
        body["name"] = "My laptop"
        with mock.patch.object(appmod, "famway_mail_async", lambda *a: None):
            return c.post("/passkey/register/finish", json=body, headers=hdr).get_json()

    def login_begin(self, c):
        tok = self.csrf(c, "/login")
        res = c.post("/passkey/login/begin", headers={"X-CSRF-Token": tok}).get_json()
        self.assertTrue(res["ok"])
        return res["options"], {"X-CSRF-Token": tok}

    def test_full_passkey_lifecycle(self):
        m = self.register()
        auth = Authenticator()
        self.assertTrue(self.add_passkey(self.c, auth)["ok"])
        stored = self.db.passkeys.find_one({})
        self.assertEqual((stored["merchant_id"], stored["name"]), (m["_id"], "My laptop"))
        self.assertIn("My laptop", self.c.get("/profile?tab=security").get_data(as_text=True))

        anon = appmod.app.test_client()                    # new browser: no cookie, no trusted device
        opts, hdr = self.login_begin(anon)
        res = anon.post("/passkey/login/finish", json={**auth.get(opts, m["_id"]), "remember": True}, headers=hdr)
        self.assertTrue(res.get_json()["ok"], res.get_json())
        self.assertEqual(res.get_json()["redirect"], "/dashboard")
        self.assertEqual(anon.get("/dashboard").status_code, 200)         # logged in, no email code asked
        self.assertIn("Expires=", res.headers.get("Set-Cookie", ""))       # "keep me signed in" -> 7 day cookie
        self.assertEqual(self.db.passkeys.find_one({})["sign_count"], 1)
        self.assertIsNotNone(self.db.passkeys.find_one({})["last_used_at"])

    def test_without_remember_cookie_is_session_only(self):
        m = self.register()
        auth = Authenticator()
        self.add_passkey(self.c, auth)
        anon = appmod.app.test_client()
        opts, hdr = self.login_begin(anon)
        res = anon.post("/passkey/login/finish", json=auth.get(opts, m["_id"]), headers=hdr)
        self.assertTrue(res.get_json()["ok"])
        self.assertNotIn("Expires=", res.headers.get("Set-Cookie", ""))

    def _login_fails(self, mutate):
        m = self.register()
        auth = Authenticator()
        self.add_passkey(self.c, auth)
        anon = appmod.app.test_client()
        opts, hdr = self.login_begin(anon)
        res = anon.post("/passkey/login/finish", json=mutate(auth, opts, m), headers=hdr)
        self.assertEqual(res.status_code, 400, res.get_json())
        self.assertFalse(res.get_json()["ok"])
        self.assertEqual(anon.get("/dashboard").status_code, 302)          # still logged out
        return res.get_json()["error"]

    def test_bad_signature_rejected(self):
        self.assertIn("signature", self._login_fails(lambda a, o, m: a.get(o, m["_id"], bad_sig=True)))

    def test_wrong_origin_rejected(self):
        self.assertIn("different website", self._login_fails(lambda a, o, m: a.get(o, m["_id"], origin="https://evil.test")))

    def test_wrong_rp_id_rejected(self):
        self.assertIn("different domain", self._login_fails(lambda a, o, m: a.get(o, m["_id"], rp_id="evil.test")))

    def test_unknown_passkey_rejected(self):
        self.assertIn("not linked", self._login_fails(lambda a, o, m: {**a.get(o, m["_id"]), "id": "AAAA"}))

    def test_user_handle_must_match(self):
        self.assertIn("does not match", self._login_fails(lambda a, o, m: a.get(o, "m_someoneelse")))

    def test_challenge_is_single_use(self):
        m = self.register()
        auth = Authenticator()
        self.add_passkey(self.c, auth)
        anon = appmod.app.test_client()
        opts, hdr = self.login_begin(anon)
        body = auth.get(opts, m["_id"])
        self.assertTrue(anon.post("/passkey/login/finish", json=body, headers=hdr).get_json()["ok"])
        replay = appmod.app.test_client()
        self.login_begin(replay)                                            # replay client has its own fresh challenge
        self.assertFalse(replay.post("/passkey/login/finish", json=body, headers={"X-CSRF-Token": self.csrf(replay)}).get_json()["ok"])
        again = anon.post("/passkey/login/finish", json=body, headers={"X-CSRF-Token": self.csrf(anon)})
        self.assertFalse(again.get_json()["ok"])                            # same browser, challenge already used

    def test_cloned_authenticator_counter_rejected(self):
        m = self.register()
        auth = Authenticator()
        self.add_passkey(self.c, auth)
        for n, ok in ((5, True), (5, False), (3, False), (6, True)):
            anon = appmod.app.test_client()
            opts, hdr = self.login_begin(anon)
            res = anon.post("/passkey/login/finish", json=auth.get(opts, m["_id"], counter=n), headers=hdr)
            self.assertEqual(res.get_json()["ok"], ok, (n, res.get_json()))

    def test_user_verification_required(self):
        self.register()
        auth = Authenticator(uv=False)
        res = self.add_passkey(self.c, auth)
        self.assertFalse(res["ok"])
        self.assertIn("fingerprint", res["error"])
        self.assertEqual(self.db.passkeys.count_documents({}), 0)

    def test_registration_needs_login_and_csrf(self):
        anon = appmod.app.test_client()
        self.assertEqual(anon.post("/passkey/register/begin", headers={"X-CSRF-Token": self.csrf(anon)}).status_code, 302)
        self.register()
        self.assertEqual(self.c.post("/passkey/register/begin").status_code, 400)        # no csrf header

    def test_same_passkey_cannot_join_two_accounts(self):
        self.register()
        auth = Authenticator()
        self.assertTrue(self.add_passkey(self.c, auth)["ok"])
        self.assertFalse(self.add_passkey(self.c, auth)["ok"])

    def test_remove_passkey_and_lockout_guard(self):
        m = self.register()
        auth = Authenticator()
        self.add_passkey(self.c, auth)
        tok = self.csrf(self.c, "/profile?tab=security")
        with mock.patch.object(appmod, "famway_mail_async", lambda *a: None):
            r = self.c.post("/profile/passkey/delete", data={"csrf": tok, "id": passkeys.b64u_enc(auth.cred_id)})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self.db.passkeys.count_documents({}), 0)
        # a Google-only account with Google switched off must keep its last passkey
        self.add_passkey(self.c, Authenticator())
        self.db.merchants.update_one({"_id": m["_id"]}, {"$set": {"password_hash": "", "google_disabled": True}})
        with mock.patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "", "GOOGLE_CLIENT_SECRET": ""}):
            pid = self.db.passkeys.find_one({})["_id"]
            self.c.post("/profile/passkey/delete", data={"csrf": tok, "id": pid})
        self.assertEqual(self.db.passkeys.count_documents({}), 1)

    def test_cannot_delete_someone_elses_passkey(self):
        self.register()
        auth = Authenticator()
        self.add_passkey(self.c, auth)
        self.db.merchants.insert_one({"_id": "m_other", "email": "o@x.io", "password_hash": "x"})
        self.db.passkeys.update_one({}, {"$set": {"merchant_id": "m_other"}})
        tok = self.csrf(self.c, "/profile?tab=security")
        self.c.post("/profile/passkey/delete", data={"csrf": tok, "id": passkeys.b64u_enc(auth.cred_id)})
        self.assertEqual(self.db.passkeys.count_documents({}), 1)


class CborTests(unittest.TestCase):
    def test_garbage_is_rejected_not_crashing(self):
        for raw in (b"", b"\xff", b"\xa1", b"\x5f", os.urandom(40)):
            try:
                passkeys._cbor(raw)
            except passkeys.PasskeyError:
                pass

    def test_round_trip_cose(self):
        key = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
        cose = cbor({1: 2, 3: -7, -1: 1, -2: key.x.to_bytes(32, "big"), -3: key.y.to_bytes(32, "big")})
        alg, pub = passkeys.load_public_key(cose)
        self.assertEqual(alg, -7)
        self.assertEqual(pub.public_numbers().x, key.x)


if __name__ == "__main__":
    unittest.main()
