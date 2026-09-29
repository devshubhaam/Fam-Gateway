import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402

fakes.install()
os.environ.update(SECRET_KEY="test-secret", RUN_WORKERS="0", INSECURE_COOKIES="1",
                  ADMIN_EMAIL="Owner@Example.com", ADMIN_PASSWORD="S3cret-pass!")
os.environ.pop("MONGODB_URI", None)

import db as dbmod  # noqa: E402

dbmod.set_db(fakes.FakeDB())
import app as appmod  # noqa: E402


class AdminLogin(unittest.TestCase):
    def setUp(self):
        d = fakes.FakeDB()
        dbmod.ensure_indexes(d)
        dbmod.set_db(d)
        self.db = d
        self.c = appmod.app.test_client()
        self.c.get("/login")
        with self.c.session_transaction() as s:
            self.tok = s["csrf"]

    def login(self, email, pw):
        return self.c.post("/login", data={"email": email, "password": pw, "csrf": self.tok})

    def test_admin_logs_in_without_registering_and_sees_dashboard(self):
        r = self.login("owner@example.com", "S3cret-pass!")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(len(list(self.db.merchants.find({}))), 1)
        page = self.c.get("/dashboard")
        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Total revenue", page.data)
        self.assertIn(b"Payment settings", page.data)

    def test_second_login_reuses_account(self):
        self.login("owner@example.com", "S3cret-pass!")
        self.c.get("/logout")
        self.c.get("/login")
        with self.c.session_transaction() as s:
            self.tok = s["csrf"]
        self.login("owner@example.com", "S3cret-pass!")
        self.assertEqual(len(list(self.db.merchants.find({}))), 1)

    def test_wrong_password_rejected(self):
        r = self.login("owner@example.com", "nope-nope")
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
  
