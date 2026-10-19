import http.client
import re
import threading
import unittest
from urllib.parse import urlencode

from lan_safety import mdns, snmp
from lan_safety.db import Database
from lan_safety.oui import OuiDatabase
from lan_safety.scanner import run_scan
from lan_safety.web import is_loopback, make_server

from .helpers import CFG, sources

GW = ("192.168.1.1", "aa:bb:cc:00:00:01")
EVIL = ("192.168.1.66", "aa:bb:cc:66:66:66")


class WebTests(unittest.TestCase):
    def setUp(self):
        import os
        import tempfile

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = os.path.join(tmp.name, "w.db")
        db = Database(self.path)
        run_scan(db, CFG, OuiDatabase({}), sources([GW]))
        # hostname malevolo con HTML: deve comparire solo escapato
        m = {EVIL[0]: mdns.MdnsDevice('<script>alert(1)</script>', {"_ssh._tcp"})}
        run_scan(db, CFG, OuiDatabase({}), sources([GW, EVIL], mdns_info=m))
        db.close()
        self.server = make_server(self.path, "127.0.0.1", 0)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def req(self, method, path, body=None, host=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Host": host or f"127.0.0.1:{self.port}", **(headers or {})}
        if body is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        conn.request(method, path, body=urlencode(body) if body is not None else None, headers=h)
        resp = conn.getresponse()
        data = resp.read().decode()
        conn.close()
        return resp, data

    def csrf(self):
        return re.search(r'name="csrf" value="([^"]+)"', self.req("GET", "/")[1]).group(1)

    def test_page_renders_and_escapes(self):
        resp, page = self.req("GET", "/")
        self.assertEqual(resp.status, 200)
        self.assertIn("Sconosciuto", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("default-src 'none'", resp.getheader("Content-Security-Policy"))
        self.assertEqual(resp.getheader("X-Frame-Options"), "DENY")

    def test_json_api(self):
        import json

        data = json.loads(self.req("GET", "/api/devices")[1])
        self.assertEqual({d["mac"] for d in data}, {GW[1], EVIL[1]})

    def test_foreign_host_header_rejected(self):
        self.assertEqual(self.req("GET", "/", host="evil.example")[0].status, 403)
        self.assertEqual(self.req("GET", "/api/devices", host=f"evil.example:{self.port}")[0].status, 403)

    def test_post_requires_csrf_and_valid_origin(self):
        self.assertEqual(self.req("POST", "/approve", {"mac": EVIL[1]})[0].status, 403)
        self.assertEqual(self.req("POST", "/approve", {"mac": EVIL[1], "csrf": "sbagliato"})[0].status, 403)
        token = self.csrf()
        resp, _ = self.req("POST", "/approve", {"mac": EVIL[1], "csrf": token}, headers={"Origin": "http://evil.example"})
        self.assertEqual(resp.status, 403)
        db = Database(self.path)
        self.assertEqual(db.get_device(EVIL[1])["status"], "unknown")
        db.close()

    def test_approve_and_ack_flow(self):
        token = self.csrf()
        resp, _ = self.req("POST", "/approve", {"mac": EVIL[1], "label": "ospite", "csrf": token})
        self.assertEqual((resp.status, resp.getheader("Location")), (303, "/"))
        db = Database(self.path)
        self.assertEqual((db.get_device(EVIL[1])["status"], db.get_device(EVIL[1])["label"]), ("approved", "ospite"))
        self.assertEqual(db.list_alerts(), [])  # approvare chiude anche l'alert
        db.close()
        self.assertEqual(self.req("POST", "/approve", {"mac": "aa:bb:cc:00:00:99", "csrf": token})[0].status, 404)
        self.assertEqual(self.req("POST", "/approve", {"mac": "zz", "csrf": token})[0].status, 400)
        self.assertEqual(self.req("POST", "/ack", {"id": "abc", "csrf": token})[0].status, 400)
        self.assertEqual(self.req("POST", "/ack", {"all": "1", "csrf": token})[0].status, 303)
        self.assertEqual(self.req("GET", "/nope")[0].status, 404)

    def test_remote_bind_needs_opt_in(self):
        self.assertTrue(is_loopback("127.0.0.1") and is_loopback("::1") and is_loopback("localhost"))
        self.assertFalse(is_loopback("0.0.0.0") or is_loopback("192.168.1.5"))
        with self.assertRaises(ValueError):
            make_server(self.path, "0.0.0.0", 0)


if __name__ == "__main__":
    unittest.main()
