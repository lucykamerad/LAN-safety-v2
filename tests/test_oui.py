import tempfile
import unittest
from pathlib import Path

from lan_safety import oui

IEEE_CSV = (
    "Registry,Assignment,Organization Name,Organization Address\n"
    'MA-L,B827EB,Raspberry Pi Foundation,"Mitchell Wood House Caldecote GB CB23 7NU"\n'
    'MA-L,00000C,"Cisco Systems, Inc",170 West Tasman Drive San Jose CA US 94134\n'
    "MA-M,70B3D5A,Qualcosa,Altrove\n"
)
MANUF = "# commento\n00:00:0C\tCisco\tCisco Systems, Inc\n00:55:DA:00:00:00/28\tShinko\tShinko Technos\nB8:27:EB\tRaspberr\n"


class OuiTests(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(oui.normalize_mac("AA-BB-CC-DD-EE-FF"), "aa:bb:cc:dd:ee:ff")
        self.assertEqual(oui.normalize_mac("aabb.ccdd.eeff"), "aa:bb:cc:dd:ee:ff")
        with self.assertRaises(ValueError):
            oui.normalize_mac("non-un-mac")

    def test_randomized(self):
        self.assertTrue(oui.is_randomized("da:a1:19:00:00:01"))
        self.assertFalse(oui.is_randomized("b8:27:eb:00:00:01"))

    def test_parse_ieee_csv_ignores_non_oui_blocks(self):
        table = oui.parse_ieee_csv(IEEE_CSV)
        self.assertEqual(table, {"B827EB": "Raspberry Pi Foundation", "00000C": "Cisco Systems, Inc"})

    def test_parse_manuf_only_24bit(self):
        self.assertEqual(oui.parse_manuf(MANUF), {"00000C": "Cisco Systems, Inc", "B827EB": "Raspberr"})

    def test_autodetect_and_roundtrip(self):
        for text in (IEEE_CSV, MANUF):
            self.assertIn("00000C", oui.parse_oui_text(text))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oui.csv"
            oui.save_table(oui.parse_ieee_csv(IEEE_CSV), path)
            self.assertEqual(oui.parse_oui_text(path.read_text()), oui.parse_ieee_csv(IEEE_CSV))

    def test_seed_is_loaded_and_user_file_overrides(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "oui.csv"
            path.write_text("B827EB,Altro Nome\n")
            db = oui.OuiDatabase.load(path)
            self.assertEqual(db.lookup("b8:27:eb:12:34:56"), "Altro Nome")
            self.assertIn("VMware", db.lookup("00:0c:29:aa:bb:cc"))  # dal seed
            self.assertIsNone(db.lookup("01:02:03:04:05:06"))

    def test_missing_user_file_is_ok(self):
        self.assertGreater(len(oui.OuiDatabase.load(Path("/nonexistent/oui.csv"))), 10)


if __name__ == "__main__":
    unittest.main()
