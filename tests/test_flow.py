import json
import os
import sys
import types
import unittest
from datetime import timedelta
from email.message import EmailMessage
from email.utils import format_datetime
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakes  # noqa: E402

fakes.install()
os.environ.update(SECRET_KEY="test-secret", RUN_WORKERS="0", INSECURE_COOKIES="1")
os.environ.pop("MONGODB_URI", None)

import db as dbmod  # noqa: E402
import mailparse  # noqa: E402
import poller  # noqa: E402
import security  # noqa: E402
import services  # noqa: E402
import webhooks  # noqa: E402

FAKE_DB = fakes.FakeDB()
dbmod.set_db(FAKE_DB)
import app as appmod  # noqa: E402


def fresh_db():
    d = fakes.FakeDB()
    dbmod.ensure_indexes(d)  # same indexes production creates
    dbmod.set_db(d)
    return d


def make_merchant(db, **over):
    m = {"_id": "m_1", "email": "a@b.co", "upi_id": "me@fam", "payee_name": "Me",
         "webhook_url": "", "webhook_secret_enc": security.encrypt("whsec_test"),
         "imap": {"enabled": True, "host": "h", "port": 993, "user": "u", "password_enc": None,
                  "allowed_senders": ["bank.com"], "require_auth": True}}
    m.update(over)
    db.merchants.insert_one(m)
    return m


def raw_email(body, sender="alerts@bank.com", auth=True, msg_id="<1@x>", subject="Credit alert", when=None):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = "me@gmail.com"
    msg["Subject"] = subject
    msg["Message-ID"] = msg_id
    msg["Date"] = format_datetime(when or services.utcnow())
    if auth:
        msg["Authentication-Results"] = ("mx.google.com; dkim=pass header.i=@bank.com header.d=bank.com; "
                                         "spf=pass; dmarc=pass (p=REJECT) header.from=bank.com")
    msg.set_content(body)
    return msg.as_bytes()


CREDIT = "Dear customer, INR 499.00 has been credited to your account XX1234 via UPI. UTR: 412345678901. Available balance INR 2,500.00"


class ParserTests(unittest.TestCase):
    def test_credit_amount_and_utr(self):
        p = mailparse.parse_credit(CREDIT)
        self.assertTrue(p.is_credit)
        self.assertEqual(p.amount_paise, 49900)
        self.assertEqual(p.utr, "412345678901")

    def test_does_not_pick_balance(self):
        p = mailparse.parse_credit("Your account was credited. Balance INR 2,500.00. Rs 75 credited. Ref 123456789012")
        self.assertEqual(p.amount_paise, 7500)

    def test_debit_ignored(self):
        p = mailparse.parse_credit("Rs. 300.00 debited from your account, paid to SHOP. UTR 999999999999")
        self.assertFalse(p.is_credit)

    def test_received_from(self):
        p = mailparse.parse_credit("You received \u20b9120.50 from RAVI. UPI Ref No 555555555555")
        self.assertEqual((p.amount_paise, p.utr), (12050, "555555555555"))

    def test_sender_rules(self):
        self.assertTrue(mailparse.sender_allowed("a@alerts.bank.com", ["bank.com"]))
        self.assertTrue(mailparse.sender_allowed("a@bank.com", ["a@bank.com"]))
        self.assertFalse(mailparse.sender_allowed("a@evilbank.com", ["bank.com"]))
        self.assertFalse(mailparse.sender_allowed("a@bank.com", []))


class OrderTests(unittest.TestCase):
    def setUp(self):
        self.db = fresh_db()
        self.m = make_merchant(self.db)

    def test_unique_payable_amounts(self):
        o1, _ = services.create_order(self.db, self.m, 49900)
        o2, _ = services.create_order(self.db, self.m, 49900)
        self.assertEqual((o1["payable_paise"], o2["payable_paise"]), (49900, 49901))

    def test_order_ref_idempotent(self):
        o1, c1 = services.create_order(self.db, self.m, 100, order_ref="r1")
        o2, c2 = services.create_order(self.db, self.m, 100, order_ref="r1")
        self.assertTrue(c1)
        self.assertFalse(c2)
        self.assertEqual(o1["order_id"], o2["order_id"])

    def test_amount_bounds_and_exhaustion(self):
        with self.assertRaises(services.OrderError):
            services.create_order(self.db, self.m, 5)
        for _ in range(services.MAX_OFFSET_PAISE + 1):
            services.create_order(self.db, self.m, 1000)
        with self.assertRaises(services.OrderError) as ctx:
            services.create_order(self.db, self.m, 1000)
        self.assertEqual(ctx.exception.status, 429)

    def test_expired_amount_is_released(self):
        o1, _ = services.create_order(self.db, self.m, 2000, expires_in=60)
        self.db.orders.update_one({"order_id": o1["order_id"]},
                                  {"$set": {"expires_at": services.utcnow() - timedelta(seconds=5)}})
        o2, _ = services.create_order(self.db, self.m, 2000)
        self.assertEqual(o2["payable_paise"], 2000)

    def test_settle_match_and_duplicate(self):
        o, _ = services.create_order(self.db, self.m, 49900)
        now = services.utcnow()
        self.assertEqual(services.settle_payment(self.db, self.m, 49900, "U1", now), "matched")
        self.assertEqual(self.db.orders.find_one({"order_id": o["order_id"]})["status"], "paid")
        self.assertEqual(services.settle_payment(self.db, self.m, 49900, "U1", now), "duplicate")

    def test_utr_settles_only_one_order(self):
        services.create_order(self.db, self.m, 49900)
        services.create_order(self.db, self.m, 49900)  # 499.01
        services.settle_payment(self.db, self.m, 49900, "U1", services.utcnow())
        self.assertEqual(services.settle_payment(self.db, self.m, 49900, "U1", services.utcnow()), "duplicate")
        paid = [o for o in self.db.orders.find({"status": "paid"})]
        self.assertEqual(len(paid), 1)

    def test_unmatched_and_stale_email(self):
        services.create_order(self.db, self.m, 49900)
        self.assertEqual(services.settle_payment(self.db, self.m, 12345, "U2", services.utcnow()), "unmatched")
        old = services.utcnow() - timedelta(hours=2)   # payment older than the order
        self.assertEqual(services.settle_payment(self.db, self.m, 49900, "U3", old), "unmatched")

    def test_late_payment_within_grace(self):
        o, _ = services.create_order(self.db, self.m, 3000, expires_in=60)
        paid_at = services.utcnow() + timedelta(seconds=300)  # after expiry, inside grace
        self.db.orders.update_one({"order_id": o["order_id"]}, {"$set": {"status": "expired"}})
        self.assertEqual(services.settle_payment(self.db, self.m, 3000, "U4", paid_at), "late_matched")
        self.assertTrue(self.db.orders.find_one({"order_id": o["order_id"]})["paid_late"])

    def test_webhook_queued(self):
        m = make_merchant(self.db, _id="m_2", email="c@d.co", webhook_url="https://hook.example.com/x")
        services.create_order(self.db, m, 500)
        services.settle_payment(self.db, m, 500, "U5", services.utcnow())
        d = self.db.deliveries.find_one({"merchant_id": "m_2"})
        self.assertEqual(json.loads(d["body"])["utr"], "U5")


class EmailPipelineTests(unittest.TestCase):
    def setUp(self):
        self.db = fresh_db()
        self.m = make_merchant(self.db, webhook_url="https://hook.example.com/x")
        self.order, _ = services.create_order(self.db, self.m, 49900)

    def test_authentic_credit_settles(self):
        self.assertTrue(poller.process_email(self.db, self.m, raw_email(CREDIT)))
        self.assertEqual(self.db.orders.find_one({"order_id": self.order["order_id"]})["status"], "paid")
        self.assertEqual(self.db.deliveries.count_documents({}), 1)

    def test_same_message_twice(self):
        raw = raw_email(CREDIT)
        poller.process_email(self.db, self.m, raw)
        poller.process_email(self.db, self.m, raw)
        self.assertEqual(self.db.deliveries.count_documents({}), 1)

    def test_spoofed_mail_rejected(self):
        poller.process_email(self.db, self.m, raw_email(CREDIT, auth=False))
        self.assertEqual(self.db.orders.find_one({"order_id": self.order["order_id"]})["status"], "pending")
        self.assertIn("not authenticated", self.db.email_log.find_one({})["result"])

    def test_unlisted_sender_left_alone(self):
        self.assertFalse(poller.process_email(self.db, self.m, raw_email(CREDIT, sender="x@evil.com")))
        self.assertEqual(self.db.orders.find_one({"order_id": self.order["order_id"]})["status"], "pending")

    def test_misaligned_dkim_rejected(self):
        raw = raw_email(CREDIT, auth=False).replace(b"\n\n", b"\nAuthentication-Results: mx; dkim=pass header.d=attacker.net\n\n", 1)
        poller.process_email(self.db, self.m, raw)
        self.assertEqual(self.db.orders.find_one({"order_id": self.order["order_id"]})["status"], "pending")


class WebhookTests(unittest.TestCase):
    def setUp(self):
        self.db = fresh_db()
        self.m = make_merchant(self.db, webhook_url="https://hook.example.com/x")
        services.create_order(self.db, self.m, 500)
        services.settle_payment(self.db, self.m, 500, "U9", services.utcnow())

    def public_dns(self, host, port, *a, **k):
        return [(2, 1, 6, "", ("93.184.216.34", port))]

    def test_signed_and_done(self):
        resp = mock.Mock(status_code=200)
        with mock.patch("socket.getaddrinfo", self.public_dns), \
                mock.patch.object(webhooks.requests, "post", return_value=resp) as post:
            self.assertEqual(webhooks.deliver_due(self.db), 1)
        kwargs = post.call_args.kwargs
        ts, sig = kwargs["headers"]["X-Timestamp"], kwargs["headers"]["X-Signature"]
        self.assertEqual(sig, "sha256=" + security.sign_webhook("whsec_test", ts, kwargs["data"]))
        self.assertEqual(self.db.deliveries.find_one({})["status"], "done")

    def test_failure_schedules_retry(self):
        resp = mock.Mock(status_code=500)
        with mock.patch("socket.getaddrinfo", self.public_dns), \
                mock.patch.object(webhooks.requests, "post", return_value=resp):
            webhooks.deliver_due(self.db)
        d = self.db.deliveries.find_one({})
        self.assertEqual((d["status"], d["attempts"]), ("pending", 1))
        self.assertGreater(d["next_attempt"], services.utcnow())

    def test_private_target_blocked(self):
        def private_dns(host, port, *a, **k):
            return [(2, 1, 6, "", ("169.254.169.254", port))]
        with mock.patch("socket.getaddrinfo", private_dns), \
                mock.patch.object(webhooks.requests, "post") as post:
            webhooks.deliver_due(self.db)
        post.assert_not_called()
        self.assertIn("private", self.db.deliveries.find_one({})["last_error"])


class WebTests(unittest.TestCase):
    def setUp(self):
        self.db = fresh_db()
        appmod.app.config["TESTING"] = True
        appmod._hits.clear()
        self.c = appmod.app.test_client()

    def csrf(self, path="/login"):
        html = self.c.get(path).get_data(as_text=True)
        return html.split('name="csrf" value="')[1].split('"')[0]

    def register(self):
        """Sign up and finish the email-code step, like a real user."""
        tok = self.csrf("/register")
        sent = []
        with mock.patch.object(appmod, "famway_mail_async", lambda ev, to, name, params: sent.append((ev, params))):
            r = self.c.post("/register", data={"csrf": tok, "name": "Test User", "email": "u@x.io", "phone": "9876543210",
                                               "password": "password123", "confirm_password": "password123"})
            self.assertEqual(r.status_code, 302)
            code = next(p["otp"] for ev, p in sent if ev == "otp")
            r = self.c.post("/verify-email", data={"csrf": self.csrf("/verify-email"), "code": code})
        self.assertEqual(r.status_code, 302)
        return r

    def test_public_pages_render(self):
        for path in ["/", "/docs", "/login", "/register", "/healthz"]:
            self.assertEqual(self.c.get(path).status_code, 200, path)
        self.assertIn("UPIBridge", self.c.get("/").get_data(as_text=True))

    def test_csrf_enforced(self):
        self.assertEqual(self.c.post("/login", data={"email": "a", "password": "b"}).status_code, 400)

    def test_full_api_flow(self):
        self.register()
        page = self.c.get("/api-keys").get_data(as_text=True)
        api_key = page.split('id="apiKeyText0"')[1].split('value="')[1].split('"')[0]
        self.assertTrue(api_key.startswith("sk_live_"))
        tok = page.split('name="csrf" value="')[1].split('"')[0]
        r = self.c.post("/dashboard/settings", data={"csrf": tok, "upi_id": "me@fam", "payee_name": "Me", "webhook_url": ""})
        self.assertEqual(r.status_code, 302)

        anon = appmod.app.test_client()
        hdr = {"Authorization": f"Bearer {api_key}"}
        self.assertEqual(anon.post("/api/v1/orders", json={"amount": 10}).status_code, 401)
        self.assertEqual(anon.post("/api/v1/orders", json={"amount": "abc"}, headers=hdr).status_code, 400)
        self.assertEqual(anon.post("/api/v1/orders", json={"amount": 10.555}, headers=hdr).status_code, 400)
        self.assertEqual(anon.post("/api/v1/orders", json={"amount": 10, "redirect_url": "javascript:alert(1)"}, headers=hdr).status_code, 400)

        r = anon.post("/api/v1/orders", json={"amount": 499, "order_ref": "u1"}, headers=hdr)
        self.assertEqual(r.status_code, 201)
        o = r.get_json()
        self.assertEqual(o["payable_amount"], "499.00")
        self.assertIn("upi://pay?pa=me%40fam", o["upi_link"])
        self.assertEqual(anon.post("/api/v1/orders", json={"amount": 499, "order_ref": "u1"}, headers=hdr).status_code, 200)

        self.assertEqual(anon.get(f"/api/v1/orders/{o['order_id']}", headers=hdr).get_json()["status"], "pending")
        self.assertIn("499.00", anon.get(f"/pay/{o['order_id']}").get_data(as_text=True))
        self.assertEqual(anon.get(f"/api/public/orders/{o['order_id']}").get_json()["status"], "pending")

        merchant = self.db.merchants.find_one({})
        services.settle_payment(self.db, merchant, 49900, "UTR123456789012", services.utcnow())
        got = anon.get(f"/api/v1/orders/{o['order_id']}", headers=hdr).get_json()
        self.assertEqual((got["status"], got["utr"]), ("paid", "UTR123456789012"))
        self.assertEqual(anon.get(f"/api/public/orders/{o['order_id']}").get_json()["status"], "paid")

    def test_other_merchant_cannot_read_order(self):
        m1 = make_merchant(self.db)
        o, _ = services.create_order(self.db, m1, 100)
        self.register()
        page = self.c.get("/api-keys").get_data(as_text=True)
        key = page.split('id="apiKeyText0"')[1].split('value="')[1].split('"')[0]
        r = appmod.app.test_client().get(f"/api/v1/orders/{o['order_id']}", headers={"Authorization": f"Bearer {key}"})
        self.assertEqual(r.status_code, 404)

    def test_ssrf_callback_rejected(self):
        self.register()
        page = self.c.get("/api-keys").get_data(as_text=True)
        key = page.split('id="apiKeyText0"')[1].split('value="')[1].split('"')[0]
        tok = page.split('name="csrf" value="')[1].split('"')[0]
        self.c.post("/dashboard/settings", data={"csrf": tok, "upi_id": "me@fam", "payee_name": "", "webhook_url": ""})
        r = appmod.app.test_client().post("/api/v1/orders", headers={"Authorization": f"Bearer {key}"},
                                          json={"amount": 5, "callback_url": "http://127.0.0.1:8000/x"})
        self.assertEqual(r.status_code, 400)

    def test_qr_route_wiring(self):
        seg = types.ModuleType("segno")

        class Q:
            def save(self, buf, **kw):
                buf.write(b"<svg/>")
        seg.make = lambda data, **kw: Q()
        sys.modules["segno"] = seg
        m = make_merchant(self.db)
        o, _ = services.create_order(self.db, m, 100)
        r = self.c.get(f"/qr/{o['order_id']}.svg")
        self.assertEqual((r.status_code, r.mimetype), (200, "image/svg+xml"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
