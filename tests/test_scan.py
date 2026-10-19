import unittest

from lan_safety import mdns, snmp
from lan_safety.db import STATUS_APPROVED, STATUS_UNKNOWN, Database
from lan_safety.models import KIND_IP_CHANGED, KIND_UNKNOWN_DEVICE
from lan_safety.oui import OuiDatabase
from lan_safety.scanner import ScanConfig, run_scan

from .helpers import CFG, sources

OUI = OuiDatabase({"B827EB": "Raspberry Pi Foundation"})
GW = ("192.168.1.1", "aa:bb:cc:00:00:01")
PI = ("192.168.1.20", "b8:27:eb:12:34:56")
INTRUDER = ("192.168.1.99", "aa:bb:cc:99:99:99")


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.addCleanup(self.db.close)

    def scan(self, devices, cfg=CFG, **kw):
        return run_scan(self.db, cfg, OUI, sources(devices, **kw))

    def test_first_scan_learns_baseline_without_alerts(self):
        res = self.scan([GW, PI])
        self.assertTrue(res.learned)
        self.assertEqual(res.alerts, [])
        self.assertEqual({d["status"] for d in self.db.list_devices()}, {STATUS_APPROVED})
        self.assertEqual(self.db.get_device(PI[1])["vendor"], "Raspberry Pi Foundation")

    def test_new_device_raises_unknown_alert_once(self):
        self.scan([GW, PI])
        res = self.scan([GW, PI, INTRUDER])
        self.assertFalse(res.learned)
        self.assertEqual([a.kind for a in res.alerts], [KIND_UNKNOWN_DEVICE])
        alert = res.alerts[0]
        self.assertIn("Device sconosciuto in LAN", alert.message)
        self.assertIn("aa:bb:cc:99:99:99", alert.message)
        self.assertEqual(alert.severity, "critical")
        self.assertEqual(self.db.get_device(INTRUDER[1])["status"], STATUS_UNKNOWN)
        # visto di nuovo: nessun secondo alert
        self.assertEqual(self.scan([GW, PI, INTRUDER]).alerts, [])
        self.assertEqual(len(self.db.list_alerts()), 1)

    def test_approved_device_stops_being_unknown(self):
        self.scan([GW])
        self.scan([GW, INTRUDER])
        self.assertEqual(self.db.approve(INTRUDER[1], label="ospite"), 1)
        self.assertEqual(self.db.get_device(INTRUDER[1])["label"], "ospite")
        self.assertEqual(self.db.list_devices(STATUS_UNKNOWN), [])

    def test_strict_mode_alerts_on_first_scan(self):
        cfg = ScanConfig(network=CFG.network, strict=True)
        res = self.scan([GW, PI], cfg=cfg)
        self.assertFalse(res.learned)
        self.assertEqual(len(res.alerts), 2)

    def test_empty_first_scan_does_not_consume_learning(self):
        self.assertFalse(self.scan([]).learned)
        self.assertTrue(self.scan([GW]).learned)

    def test_ip_change_is_info_alert_and_updates_ip(self):
        self.scan([GW, PI])
        res = self.scan([GW, ("192.168.1.77", PI[1])])
        self.assertEqual([(a.kind, a.severity) for a in res.alerts], [(KIND_IP_CHANGED, "info")])
        self.assertEqual(self.db.get_device(PI[1])["ip"], "192.168.1.77")

    def test_enrichment_is_merged_and_not_lost(self):
        m = {PI[0]: mdns.MdnsDevice("raspberrypi", {"_ssh._tcp"})}
        s = {PI[0]: snmp.SnmpInfo(name="pi-snmp", descr="Linux", object_id="1.3.6.1.4.1.8072")}
        self.scan([GW, PI], mdns_info=m, snmp_info=s)
        dev = self.db.get_device(PI[1])
        self.assertEqual((dev["hostname"], dev["snmp_name"], dev["snmp_object_id"]), ("raspberrypi", "pi-snmp", "1.3.6.1.4.1.8072"))
        self.assertEqual(dev["services"], '["_ssh._tcp"]')
        self.scan([GW, PI])  # stavolta mDNS/SNMP non rispondono
        dev = self.db.get_device(PI[1])
        self.assertEqual((dev["hostname"], dev["snmp_name"], dev["services"]), ("raspberrypi", "pi-snmp", '["_ssh._tcp"]'))

    def test_randomized_mac_is_flagged_and_has_no_vendor(self):
        self.scan([GW])
        res = self.scan([GW, ("192.168.1.50", "da:a1:19:00:00:01")])
        dev = self.db.get_device("da:a1:19:00:00:01")
        self.assertEqual((dev["randomized"], dev["vendor"]), (1, None))
        self.assertIn("randomizzato", res.alerts[0].message)

    def test_alert_ack(self):
        self.scan([GW])
        self.scan([GW, INTRUDER])
        alert_id = self.db.list_alerts()[0].id
        self.assertEqual(self.db.ack_alerts([alert_id]), 1)
        self.assertEqual(self.db.list_alerts(), [])
        self.assertEqual(len(self.db.list_alerts(include_acked=True)), 1)

    def test_remove_device_makes_it_new_again(self):
        self.scan([GW, PI])
        self.assertEqual(self.db.remove(PI[1]), 1)
        self.assertEqual(len(self.scan([GW, PI]).alerts), 1)

    def test_invalid_mac_rejected(self):
        with self.assertRaises(ValueError):
            self.db.get_device("zz")


class PersistenceTests(unittest.TestCase):
    def test_schema_survives_reopen(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "inv.db")
            db = Database(path)
            run_scan(db, CFG, OUI, sources([GW]))
            db.close()
            db = Database(path)
            self.assertEqual(db.device_count(), 1)
            self.assertEqual(db.conn.execute("PRAGMA user_version").fetchone()[0], 1)
            db.close()


if __name__ == "__main__":
    unittest.main()


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.addCleanup(self.db.close)

    def test_untrusted_strings_are_sanitized(self):
        from lan_safety.models import clean_text

        self.assertEqual(clean_text("pwn\x1b[2J\x1b[H\r\nok"), "pwn [2J [H ok")
        self.assertIsNone(clean_text("\x00\x07  "))
        self.assertEqual(len(clean_text("a" * 500)), 120)
        m = {PI[0]: mdns.MdnsDevice("evil\x1b[2Jhost", {"_ssh\x07._tcp"})}
        s = {PI[0]: snmp.SnmpInfo(name="n\x1b]0;x\x07", descr="d\x1b[31m")}
        run_scan(self.db, CFG, OUI, sources([GW], ))
        res = run_scan(self.db, CFG, OUI, sources([GW, PI], mdns_info=m, snmp_info=s))
        for text in (res.alerts[0].message, str(self.db.get_device(PI[1])["snmp_name"]),
                     self.db.get_device(PI[1])["hostname"], self.db.get_device(PI[1])["services"]):
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\x07", text)

    def test_approve_acks_related_unknown_alert(self):
        run_scan(self.db, CFG, OUI, sources([GW]))
        run_scan(self.db, CFG, OUI, sources([GW, INTRUDER, PI]))
        self.assertEqual(len(self.db.list_alerts()), 2)
        self.db.approve(INTRUDER[1])
        self.assertEqual([a.mac for a in self.db.list_alerts()], [PI[1]])
        self.db.approve()
        self.assertEqual(self.db.list_alerts(), [])

    def test_database_file_is_private(self):
        import os
        import stat
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "inv.db")
            Database(path).close()
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
