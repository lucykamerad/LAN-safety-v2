import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from lan_safety.alerts import Notifier, WebhookNotifier, deliver
from lan_safety.db import Database
from lan_safety.oui import OuiDatabase
from lan_safety.scanner import run_scan

from .helpers import CFG, sources

GW = ("192.168.1.1", "aa:bb:cc:00:00:01")
NEW = ("192.168.1.99", "aa:bb:cc:99:99:99")


class Flaky(Notifier):
    name = "flaky"

    def __init__(self):
        self.fail, self.sent = True, []

    def send(self, alert):
        if self.fail:
            raise OSError("giù")
        self.sent.append(alert.id)


class AlertDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.addCleanup(self.db.close)
        run_scan(self.db, CFG, OuiDatabase({}), sources([GW]))
        run_scan(self.db, CFG, OuiDatabase({}), sources([GW, NEW]))  # alert unknown_device

    def test_failed_delivery_is_retried_next_time(self):
        n = Flaky()
        self.assertEqual(deliver(self.db, [n]), [])
        n.fail = False
        delivered = deliver(self.db, [n])
        self.assertEqual(len(delivered), 1)
        self.assertEqual(deliver(self.db, [n]), [])  # niente duplicati
        self.assertEqual(len(n.sent), 1)

    def test_info_alerts_are_not_forwarded(self):
        run_scan(self.db, CFG, OuiDatabase({}), sources([GW, ("192.168.1.100", NEW[1])]))  # cambio IP -> info
        n = Flaky()
        n.fail = False
        deliver(self.db, [n])
        kinds = [a.kind for a in self.db.list_alerts() if a.id in n.sent]
        self.assertEqual(kinds, ["unknown_device"])

    def test_no_notifiers_does_not_queue_forever(self):
        deliver(self.db, [])
        n = Flaky()
        n.fail = False
        self.assertEqual(deliver(self.db, [n]), [])

    def test_webhook_posts_json(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            deliver(self.db, [WebhookNotifier(f"http://127.0.0.1:{server.server_port}/hook")])
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(len(received), 1)
        body = received[0]
        self.assertEqual((body["kind"], body["mac"], body["ip"]), ("unknown_device", NEW[1], NEW[0]))
        self.assertIn("Device sconosciuto in LAN", body["text"])

    def test_webhook_rejects_non_http(self):
        with self.assertRaises(ValueError):
            WebhookNotifier("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
