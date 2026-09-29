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
                  ADMIN_EMAIL="owner@example.com", ADMIN_PASSWORD="S3cret-pass!")
os.environ.pop("MONGODB_URI", None)

import db as dbmod  # noqa: E402

dbmod.set_db(fakes.FakeDB())
import app as appmod  # noqa: E402
import services  # noqa: E402
import webhooks  # noqa: E402


class PagesBase(unittest.TestCase):
    def setUp(self):
        appmod._hits.clear()  # the login rate limiter is process-wide
        env = mock.patch.dict(os.environ, {"ALLOW_PRIVATE_WEBHOOKS": "1"})  # skip DNS lookups in tests
        env.start()
        self.addCleanup(env.stop)
        d = fakes.FakeDB()
        dbmod.ensure_indexes(d)
        dbmod.set_db(d)
        self.db = d
        self.c = appmod.app.test_client()
        self.c.get("/login")
        with self.c.session_transaction() as s:
            self.tok = s["csrf"]
        self.c.post("/login", data={"email": "owner@example.com", "password": "S3cret-pass!", "csrf": self.tok})
        self.c.get("/dashboard")  # login clears the session; rendering a page issues a fresh csrf token
        with self.c.session_transaction() as s:
            self.tok = s["csrf"]
        self.m = self.db.merchants.find_one({})
        self.c.post("/dashboard/settings", data={"csrf": self.tok, "upi_id": "me@fam", "payee_name": "Me", "webhook_url": ""})

    def post(self, path, **data):
        data["csrf"] = self.tok
        return self.c.post(path, data=data, follow_redirects=False)


class AllPagesOpen(PagesBase):
    def test_every_page_renders_with_sidebar(self):
        for path in ("/dashboard", "/transactions", "/payment-links", "/api-keys", "/webhooks"):
            r = self.c.get(path)
            self.assertEqual(r.status_code, 200, path)
            for label in (b"Transactions", b"Payment Links", b"API Keys", b"Webhooks"):
                self.assertIn(label, r.data, path)

    def test_pages_need_login(self):
        anon = appmod.app.test_client()
        for path in ("/transactions", "/payment-links", "/api-keys", "/webhooks"):
            self.assertEqual(anon.get(path).status_code, 302, path)

    def test_unknown_transaction_is_404(self):
        self.assertEqual(self.c.get("/transactions/ord_nope").status_code, 404)


class PaymentLinks(PagesBase):
    def test_generate_expire_disable(self):
        r = self.post("/payment-links", amount="20", expiry="1h")
        self.assertEqual(r.status_code, 302)
        order = self.db.orders.find_one({"source": "link"})
        self.assertIsNotNone(order)
        self.assertEqual(order["amount_paise"], 2000)
        page = self.c.get(r.headers["Location"])
        self.assertIn(order["order_id"].encode(), page.data)
        self.assertIn(b"generatedLinkRow", page.data)
        self.assertIn(b"Pending", page.data)

        self.post(f"/payment-links/{order['order_id']}/disable")
        self.assertEqual(self.db.orders.find_one({"order_id": order["order_id"]})["status"], "cancelled")
        self.assertIn(b"Disabled", self.c.get("/payment-links").data)
        pay = self.c.get(f"/pay/{order['order_id']}")
        self.assertEqual(pay.status_code, 200)
        self.assertIn(b"expired", pay.data)
        self.assertEqual(self.c.get(f"/api/public/orders/{order['order_id']}").get_json()["status"], "expired")

        self.post("/payment-links", amount="30", expiry="5m")
        o2 = [o for o in self.db.orders.find({"source": "link"}) if o["amount_paise"] == 3000][0]
        self.post(f"/payment-links/{o2['order_id']}/expire")
        self.assertEqual(self.db.orders.find_one({"order_id": o2["order_id"]})["status"], "expired")

    def test_bad_amount_and_missing_upi(self):
        r = self.post("/payment-links", amount="0.5", expiry="1h")
        self.assertIn(b"amount must be between", self.c.get(r.headers["Location"]).data)
        self.db.merchants.update_one({"_id": self.m["_id"]}, {"$set": {"upi_id": ""}})
        r = self.post("/payment-links", amount="10", expiry="1h")
        self.assertIn(b"Set your UPI ID", self.c.get(r.headers["Location"]).data)

    def test_cannot_close_another_merchants_link(self):
        other, _ = appmod.create_merchant("b@x.io", "x")
        order, _ = services.create_order(self.db, {**other, "upi_id": "b@fam"}, 1000, source="link")
        self.post(f"/payment-links/{order['order_id']}/disable")
        self.assertEqual(self.db.orders.find_one({"order_id": order["order_id"]})["status"], "pending")


class ApiKeys(PagesBase):
    def test_shows_full_key_and_regenerates(self):
        first = self.c.get("/api-keys").data
        self.assertIn(b"sk_live_", first)
        self.post("/api-keys/regenerate")
        m2 = self.db.merchants.find_one({})
        self.assertNotEqual(m2["api_key_hash"], self.m["api_key_hash"])
        page = self.c.get("/api-keys").data
        import security
        self.assertIn(security.decrypt(m2["api_key_enc"]).encode(), page)
        self.assertIn(b"/api/v1/orders", page)

    def test_legacy_merchant_without_stored_key(self):
        self.db.merchants.update_one({"_id": self.m["_id"]}, {"$set": {"api_key_enc": None}})
        page = self.c.get("/api-keys").data
        self.assertIn(b"Generate a new key to see", page)


class Transactions(PagesBase):
    def make(self, amount, ref=None):
        order, _ = services.create_order(self.db, self.db.merchants.find_one({}), amount, order_ref=ref)
        return order

    def test_stats_filters_search_and_detail(self):
        a = self.make(1000, "cust-1")
        self.make(2000)
        services.settle_payment(self.db, self.db.merchants.find_one({}), a["payable_paise"], "UTR111",
                                services.utcnow())
        page = self.c.get("/transactions").data
        self.assertIn(a["order_id"].encode(), page)
        self.assertIn(b"UTR111", page)
        self.assertIn(b"Captured", page)
        self.assertNotIn(b"No transactions match", page)

        cap = self.c.get("/transactions?status=captured").data
        self.assertIn(a["order_id"].encode(), cap)
        created = self.c.get("/transactions?status=created").data
        self.assertNotIn(a["order_id"].encode(), created)

        self.assertIn(a["order_id"].encode(), self.c.get("/transactions?q=" + a["order_id"][:8]).data)
        self.assertIn(b"No transactions match", self.c.get("/transactions?q=zzzzzz").data)
        self.assertEqual(self.c.get("/transactions?date=bogus&limit=abc&page=-4").status_code, 200)

        det = self.c.get(f"/transactions/{a['order_id']}")
        self.assertEqual(det.status_code, 200)
        self.assertIn(b"UTR111", det.data)

    def test_pagination(self):
        for i in range(12):
            self.make(100 * (i + 1) + 100)
        p1 = self.c.get("/transactions?limit=10&date=all").data
        self.assertIn(b"of <span id=\"lblTotalPages\">2</span>", p1)
        p2 = self.c.get("/transactions?limit=10&date=all&page=2").data
        self.assertIn(b"lblCurrentPage\">2<", p2)


class Webhooks(PagesBase):
    def test_add_delete_and_validation(self):
        self.post("/webhooks/endpoints", endpoint_name="Store", endpoint_url="https://a.example.com/hook")
        self.assertEqual(self.db.webhook_endpoints.count_documents({}), 1)
        self.post("/webhooks/endpoints", endpoint_name="Dup", endpoint_url="https://a.example.com/hook")
        self.assertEqual(self.db.webhook_endpoints.count_documents({}), 1)
        r = self.post("/webhooks/endpoints", endpoint_name="Bad", endpoint_url="http://insecure.example.com")
        self.assertIn(b"https", self.c.get(r.headers["Location"]).data)
        self.assertIn(b"Store", self.c.get("/webhooks").data)
        eid = self.db.webhook_endpoints.find_one({})["eid"]
        self.post(f"/webhooks/endpoints/{eid}/delete")
        self.assertEqual(self.db.webhook_endpoints.count_documents({}), 0)

    def test_fan_out_logs_filters_and_retry(self):
        m = self.db.merchants.find_one({})
        self.post("/webhooks/endpoints", endpoint_name="Store", endpoint_url="https://a.example.com/hook")
        self.post("/webhooks/endpoints", endpoint_name="Bot", endpoint_url="https://b.example.com/hook")
        self.db.merchants.update_one({"_id": m["_id"]}, {"$set": {"webhook_url": "https://c.example.com/hook"}})
        m = self.db.merchants.find_one({})
        order, _ = services.create_order(self.db, m, 1000)
        services.settle_payment(self.db, m, order["payable_paise"], "UTR9", services.utcnow())
        self.assertEqual(self.db.deliveries.count_documents({}), 3)

        good = mock.Mock(status_code=200, text='{"ok":true}')
        bad = mock.Mock(status_code=500, text="boom")
        replies = iter([good, bad, bad])
        with mock.patch.object(webhooks.requests, "post", side_effect=lambda *a, **k: next(replies)):
            webhooks.deliver_due(self.db)
        for d in self.db.deliveries.find({}):
            if d["status"] != "done":
                self.db.deliveries.update_one({"did": d["did"]}, {"$set": {"status": "failed"}})

        page = self.c.get("/webhooks").data
        self.assertIn(b"HTTP 200", page)
        self.assertIn(b"HTTP 500", page)
        self.assertIn(b"https://b.example.com/hook", page)
        ok = self.c.get("/webhooks?filter=success").data
        self.assertNotIn(b"HTTP 500", ok)
        bad_page = self.c.get("/webhooks?filter=failed").data
        self.assertIn(b"HTTP 500", bad_page)
        self.assertNotIn(b"HTTP 200", bad_page)

        failed = self.db.deliveries.find_one({"status": "failed"})
        self.post(f"/webhooks/logs/{failed['did']}/retry")
        self.assertEqual(self.db.deliveries.find_one({"did": failed["did"]})["status"], "pending")
        self.assertIn(order["order_id"].encode(), self.c.get(f"/transactions/{order['order_id']}").data)

    def test_default_url_still_gets_one_delivery(self):
        m = self.db.merchants.find_one({})
        self.db.merchants.update_one({"_id": m["_id"]}, {"$set": {"webhook_url": "https://c.example.com/hook"}})
        m = self.db.merchants.find_one({})
        order, _ = services.create_order(self.db, m, 1000)
        services.settle_payment(self.db, m, order["payable_paise"], "UTR1", services.utcnow())
        self.assertEqual(self.db.deliveries.count_documents({}), 1)


if __name__ == "__main__":
    unittest.main()
