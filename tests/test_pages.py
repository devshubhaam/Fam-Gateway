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


# ---------------------------------------------------------------- profile / integrations / status / docs / checkout
import base64  # noqa: E402
import io  # noqa: E402


def _png(size=(300, 200), color=(200, 30, 30)):
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, "PNG")
    return buf.getvalue()


class ProfilePages(PagesBase):
    def flash_text(self, r):
        return r.get_data(as_text=True)

    def test_profile_renders_all_tabs_and_merchant_id(self):
        r = self.c.get("/profile")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        for label in ("General", "Branding", "Security", "Social Logins", "Merchant ID", "Personal Details"):
            self.assertIn(label, html)
        m = self.db.merchants.find_one({})
        self.assertRegex(m["merchant_no"], r"^\d{10}$")
        self.assertIn(m["merchant_no"], html)
        self.assertEqual(self.c.get("/profile?tab=security").status_code, 200)
        self.assertEqual(self.c.get("/profile?tab=bogus").status_code, 200)

    def test_profile_needs_login(self):
        anon = appmod.app.test_client()
        for p in ("/profile", "/integrations"):
            self.assertEqual(anon.get(p).status_code, 302, p)

    def test_edit_details(self):
        self.post("/profile/details", full_name="Shubham Kumar", phone="+91 98765-43210", support_link="https://t.me/shub")
        m = self.db.merchants.find_one({})
        self.assertEqual((m["full_name"], m["phone"], m["support_link"]), ("Shubham Kumar", "9876543210", "https://t.me/shub"))
        self.post("/profile/details", full_name="X", phone="12345", support_link="")
        self.assertEqual(self.db.merchants.find_one({})["phone"], "9876543210")  # invalid phone rejected
        self.post("/profile/details", full_name="X", phone="", support_link="not a link")
        self.assertEqual(self.db.merchants.find_one({})["full_name"], "Shubham Kumar")
        self.assertIn("Shubham Kumar", self.c.get("/dashboard").get_data(as_text=True))  # sidebar name

    def test_change_email(self):
        self.post("/profile/email", new_email="new@example.com", password="wrong")
        self.assertEqual(self.db.merchants.find_one({})["email"], "owner@example.com")
        self.post("/profile/email", new_email="new@example.com", password="S3cret-pass!")
        self.assertEqual(self.db.merchants.find_one({})["email"], "new@example.com")
        self.post("/profile/email", new_email="not-an-email", password="S3cret-pass!")
        self.assertEqual(self.db.merchants.find_one({})["email"], "new@example.com")

    def test_change_email_to_taken_address(self):
        appmod.create_merchant("taken@example.com", "x")
        self.post("/profile/email", new_email="taken@example.com", password="S3cret-pass!")
        self.assertEqual(self.db.merchants.find_one({"_id": self.m["_id"]})["email"], "owner@example.com")

    def test_change_password(self):
        self.post("/profile/password", current_password="nope", new_password="Another-pass1", confirm_password="Another-pass1")
        self.post("/profile/password", current_password="S3cret-pass!", new_password="short", confirm_password="short")
        self.post("/profile/password", current_password="S3cret-pass!", new_password="Another-pass1", confirm_password="different")
        from werkzeug.security import check_password_hash
        self.assertTrue(check_password_hash(self.db.merchants.find_one({})["password_hash"], "S3cret-pass!"))
        self.post("/profile/password", current_password="S3cret-pass!", new_password="Another-pass1", confirm_password="Another-pass1")
        self.assertTrue(check_password_hash(self.db.merchants.find_one({})["password_hash"], "Another-pass1"))

    def test_avatar_upload_is_square_png_and_removable(self):
        r = self.c.post("/profile/avatar", data={"csrf": self.tok, "avatar": (io.BytesIO(_png()), "me.png")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        av = self.db.merchants.find_one({})["avatar"]
        self.assertTrue(av.startswith("data:image/png;base64,"))
        from PIL import Image
        img = Image.open(io.BytesIO(base64.b64decode(av.split(",", 1)[1])))
        self.assertEqual(img.size, (192, 192))
        self.assertIn(av[:60], self.c.get("/profile?tab=avatar").get_data(as_text=True))
        self.post("/profile/avatar", remove="1")
        self.assertNotIn("avatar", self.db.merchants.find_one({}))

    def test_avatar_rejects_non_images_and_huge_files(self):
        self.c.post("/profile/avatar", data={"csrf": self.tok, "avatar": (io.BytesIO(b"<script>x</script>"), "x.png")},
                    content_type="multipart/form-data")
        self.assertNotIn("avatar", self.db.merchants.find_one({}))
        r = self.c.post("/profile/avatar", data={"csrf": self.tok, "avatar": (io.BytesIO(b"0" * 700_000), "big.png")},
                        content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("avatar", self.db.merchants.find_one({}))

    def test_other_posts_still_capped_at_64kb(self):
        r = self.c.post("/profile/details", data={"csrf": self.tok, "full_name": "x" * 100_000})
        self.assertEqual(r.status_code, 413)

    def test_google_unlink_and_link(self):
        with mock.patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "id", "GOOGLE_CLIENT_SECRET": "sec"}):
            self.assertIn("Unlink Account", self.c.get("/profile?tab=social").get_data(as_text=True))
            self.post("/profile/google/unlink")
            self.assertTrue(self.db.merchants.find_one({})["google_disabled"])
            self.assertIn("Link Google Account", self.c.get("/profile?tab=social").get_data(as_text=True))

    def test_google_unlink_needs_a_password(self):
        self.db.merchants.update_one({"_id": self.m["_id"]}, {"$set": {"password_hash": ""}})
        self.post("/profile/google/unlink")
        self.assertFalse(self.db.merchants.find_one({}).get("google_disabled"))

    def test_google_login_blocked_after_unlink(self):
        self.db.merchants.update_one({"_id": self.m["_id"]}, {"$set": {"google_disabled": True}})
        anon = appmod.app.test_client()
        anon.get("/login")
        with mock.patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "id", "GOOGLE_CLIENT_SECRET": "sec"}):
            with anon.session_transaction() as s:
                s["g_state"] = "st"
            tok = mock.Mock(ok=True, status_code=200)
            tok.json.return_value = {"access_token": "t"}
            info = mock.Mock()
            info.json.return_value = {"email": "owner@example.com", "email_verified": True}
            with mock.patch.object(appmod.requests, "post", return_value=tok), \
                 mock.patch.object(appmod.requests, "get", return_value=info):
                r = anon.get("/auth/google/callback?state=st&code=c")
            self.assertEqual(r.headers["Location"], "/login")
            with anon.session_transaction() as s:
                self.assertNotIn("mid", s)


class QrAvatar(unittest.TestCase):
    def test_embed_avatar_handles_both_svg_shapes(self):
        uri = "data:image/png;base64,AAAA"
        with_vb = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="800" height="800"><path d="M0 0"/></svg>'
        no_vb = b'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200"><path d="M0 0"/></svg>'
        a = appmod.embed_avatar(with_vb, uri).decode()
        b = appmod.embed_avatar(no_vb, uri).decode()
        self.assertIn('cx="50.00" cy="50.00"', a)      # centre in viewBox units
        self.assertIn('cx="100.00" cy="100.00"', b)    # centre in pixel units
        for out in (a, b):
            self.assertTrue(out.endswith("</svg>"))
            self.assertIn(uri, out)
        self.assertEqual(appmod.embed_avatar(b"<svg></svg>", uri), b"<svg></svg>")  # unknown shape: untouched

    def test_qr_route_uses_high_error_correction_with_avatar(self):
        import types
        calls = {}

        class Q:
            def save(self, buf, kind, scale, border):
                buf.write(b'<svg viewBox="0 0 10 10" width="80" height="80"></svg>')

        fake = types.ModuleType("segno")
        fake.make = lambda text, error: (calls.setdefault("error", error), Q())[1]
        d = fakes.FakeDB(); dbmod.ensure_indexes(d); dbmod.set_db(d)
        m, _ = appmod.create_merchant("q@example.com", "x")
        d.merchants.update_one({"_id": m["_id"]}, {"$set": {"upi_id": "q@fam", "avatar": "data:image/png;base64,AAAA"}})
        m = d.merchants.find_one({"_id": m["_id"]})
        order, _ = services.create_order(d, m, 5000)
        with mock.patch.dict(sys.modules, {"segno": fake}):
            r = appmod.app.test_client().get("/qr/%s.svg" % order["order_id"])
        self.assertEqual(calls["error"], "h")
        self.assertIn(b"<image", r.data)


class IntegrationsPage(PagesBase):
    def test_renders_form(self):
        html = self.c.get("/integrations").get_data(as_text=True)
        for s in ("Automated Verification", "FamPay-linked Gmail Address", "Gmail App Password", "Your FamPay UPI ID", "Not connected"):
            self.assertIn(s, html)

    def test_connect_saves_mailbox_and_upi(self):
        with mock.patch.object(appmod.poller, "test_connection", return_value="") as t:
            self.post("/integrations", gmail="Me@Gmail.com", app_password="abcd efgh ijkl mnop", fampay_upi_id="me2@fam")
        t.assert_called_once()
        m = self.db.merchants.find_one({})
        self.assertTrue(m["imap"]["enabled"])
        self.assertEqual((m["imap"]["user"], m["imap"]["host"], m["upi_id"]), ("me@gmail.com", "imap.gmail.com", "me2@fam"))
        self.assertTrue(m["imap"]["allowed_senders"])
        self.assertNotIn("abcdefghijklmnop", str(m))  # stored encrypted
        html = self.c.get("/integrations").get_data(as_text=True)
        self.assertIn("Connected", html)
        self.assertIn("Disconnect Gmail", html)

    def test_bad_login_is_not_saved(self):
        with mock.patch.object(appmod.poller, "test_connection", return_value="AUTHENTICATIONFAILED"):
            self.post("/integrations", gmail="me@gmail.com", app_password="abcdefghijklmnop", fampay_upi_id="me2@fam")
        m = self.db.merchants.find_one({})
        self.assertFalse(m["imap"]["enabled"])
        self.assertEqual(m["upi_id"], "me@fam")

    def test_validation(self):
        with mock.patch.object(appmod.poller, "test_connection", return_value="") as t:
            self.post("/integrations", gmail="nope", app_password="abcdefghijklmnop", fampay_upi_id="me@fam")
            self.post("/integrations", gmail="me@gmail.com", app_password="abcdefghijklmnop", fampay_upi_id="bad upi")
            self.post("/integrations", gmail="me@gmail.com", app_password="tooshort", fampay_upi_id="me@fam")
            self.post("/integrations", gmail="me@gmail.com", app_password="", fampay_upi_id="me@fam")
        t.assert_not_called()
        self.assertFalse(self.db.merchants.find_one({})["imap"]["enabled"])

    def test_keep_saved_password_when_blank_and_disconnect(self):
        with mock.patch.object(appmod.poller, "test_connection", return_value=""):
            self.post("/integrations", gmail="me@gmail.com", app_password="abcdefghijklmnop", fampay_upi_id="me@fam")
            self.post("/integrations", gmail="me@gmail.com", app_password="", fampay_upi_id="new@fam")
        self.assertEqual(self.db.merchants.find_one({})["upi_id"], "new@fam")
        self.post("/integrations/disconnect")
        m = self.db.merchants.find_one({})
        self.assertFalse(m["imap"]["enabled"])
        self.assertEqual(m["imap"]["user"], "")
        self.assertIsNone(m["imap"]["password_enc"])


class StatusAndDocs(PagesBase):
    def test_status_is_public_and_json_works(self):
        anon = appmod.app.test_client()
        r = anon.get("/status")
        self.assertEqual(r.status_code, 200)
        self.assertIn("System Status", r.get_data(as_text=True))
        self.assertIn("All systems operational", r.get_data(as_text=True))
        j = anon.get("/status.json").get_json()
        self.assertTrue(j["ok"])
        self.assertEqual({c["name"] for c in j["components"]}, {"API", "Database", "Payment verification", "Webhook delivery"})

    def test_status_shows_outage_when_db_dies(self):
        with mock.patch.object(appmod, "get_db", side_effect=RuntimeError("down")):
            j = appmod._status_snapshot()
        self.assertFalse(j["ok"])

    def test_status_flags_stale_mailbox(self):
        self.db.merchants.update_one({"_id": self.m["_id"]}, {"$set": {
            "imap": {**self.m["imap"], "enabled": True, "user": "a@b.c"},
            "imap_status": {"last_error": "login failed", "last_poll_at": services.utcnow()}}})
        self.assertFalse(appmod._status_snapshot()["ok"])

    def test_docs_public_and_logged_in(self):
        anon = appmod.app.test_client().get("/docs")
        self.assertEqual(anon.status_code, 200)
        me = self.c.get("/docs")
        for r in (anon, me):
            html = r.get_data(as_text=True)
            for s in ("Developer Documentation", "/api/v1/orders", "X-Signature", "Base URL"):
                self.assertIn(s, html)
        self.assertIn("System Status", me.get_data(as_text=True))   # dashboard sidebar
        self.assertNotIn("sk_live_xxx</pre>\n<script", anon.get_data(as_text=True))

    def test_sidebar_has_new_entries(self):
        html = self.c.get("/transactions").get_data(as_text=True)
        for s in ("Integrations", "Profile", "Documentation", "System Status"):
            self.assertIn(s, html)
        self.assertNotIn("wa.me", html)
        with mock.patch.dict(os.environ, {"SUPPORT_WHATSAPP": "+91 99999 00000"}):
            self.assertIn("wa.me/919999900000", self.c.get("/transactions").get_data(as_text=True))


class CheckoutPage(PagesBase):
    def make(self):
        return services.create_order(self.db, self.db.merchants.find_one({}), 2000)[0]

    def test_pending_layout(self):
        o = self.make()
        html = self.c.get("/pay/%s" % o["order_id"]).get_data(as_text=True)
        for s in ("Order total", "Scan with any UPI app", "Save QR", "Open UPI app", "Expires In", "Waiting for payment", o["order_id"], "Secured by"):
            self.assertIn(s, html)
        self.assertIn("checkout.css", html)

    def test_paid_and_expired_states(self):
        o = self.make()
        self.db.orders.update_one({"order_id": o["order_id"]}, {"$set": {"status": "paid", "utr": "412345678901"}})
        html = self.c.get("/pay/%s" % o["order_id"]).get_data(as_text=True)
        self.assertIn("Payment received", html)
        self.assertIn("412345678901", html)
        o2 = self.make()
        self.db.orders.update_one({"order_id": o2["order_id"]}, {"$set": {"status": "cancelled"}})
        self.assertIn("This payment link has expired", self.c.get("/pay/%s" % o2["order_id"]).get_data(as_text=True))
