import os
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402

fakes.install()
os.environ.update(SECRET_KEY="test-secret", RUN_WORKERS="0", INSECURE_COOKIES="1",
                  GOOGLE_CLIENT_ID="cid", GOOGLE_CLIENT_SECRET="csec", BASE_URL="https://x.test")
os.environ.pop("MONGODB_URI", None)

import db as dbmod  # noqa: E402

dbmod.set_db(fakes.FakeDB())
import app as appmod  # noqa: E402


class Resp:
    def __init__(self, data):
        self._d = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._d


def fresh():
    d = fakes.FakeDB()
    dbmod.ensure_indexes(d)
    dbmod.set_db(d)
    return d


class GoogleTests(unittest.TestCase):
    def go(self, c, info, state_ok=True):
        r = c.get("/auth/google")
        self.assertEqual(r.status_code, 302)
        state = r.headers["Location"].split("state=")[1].split("&")[0]
        with mock.patch.object(appmod.requests, "post", return_value=Resp({"access_token": "t"})), \
             mock.patch.object(appmod.requests, "get", return_value=Resp(info)):
            return c.get("/auth/google/callback?code=abc&state=" + (state if state_ok else "bad"))

    def test_signup_creates_account_and_logs_in(self):
        d = fresh()
        c = appmod.app.test_client()
        r = self.go(c, {"email": "A@x.com", "email_verified": True})
        self.assertTrue(r.headers["Location"].endswith("/dashboard"))
        m = d.merchants.find_one({"email": "a@x.com"})
        self.assertIsNotNone(m)
        self.assertEqual(m["password_hash"], "")
        self.assertEqual(c.get("/dashboard").status_code, 200)

    def test_existing_account_logs_in_without_duplicate(self):
        d = fresh()
        c = appmod.app.test_client()
        self.go(c, {"email": "a@x.com", "email_verified": True})
        c2 = appmod.app.test_client()
        self.go(c2, {"email": "a@x.com", "email_verified": True})
        self.assertEqual(len(list(d.merchants.find({}))), 1)

    def test_unverified_email_rejected(self):
        d = fresh()
        c = appmod.app.test_client()
        r = self.go(c, {"email": "a@x.com", "email_verified": False})
        self.assertTrue(r.headers["Location"].endswith("/login"))
        self.assertIsNone(d.merchants.find_one({"email": "a@x.com"}))

    def test_bad_state_rejected(self):
        d = fresh()
        c = appmod.app.test_client()
        r = self.go(c, {"email": "a@x.com", "email_verified": True}, state_ok=False)
        self.assertTrue(r.headers["Location"].endswith("/login"))
        self.assertIsNone(d.merchants.find_one({"email": "a@x.com"}))

    def test_google_account_cannot_password_login(self):
        fresh()
        c = appmod.app.test_client()
        self.go(c, {"email": "a@x.com", "email_verified": True})
        c2 = appmod.app.test_client()
        c2.get("/login")
        with c2.session_transaction() as s:
            tok = s["csrf"]
        r = c2.post("/login", data={"email": "a@x.com", "password": "", "csrf": tok})
        self.assertEqual(r.status_code, 401)

    def test_button_shows_only_when_configured(self):
        fresh()
        c = appmod.app.test_client()
        self.assertIn(b"Continue with Google", c.get("/register").data)
        with mock.patch.dict(os.environ, {"GOOGLE_CLIENT_ID": ""}):
            self.assertNotIn(b"Continue with Google", c.get("/register").data)


if __name__ == "__main__":
    unittest.main()
