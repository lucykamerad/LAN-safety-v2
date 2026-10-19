import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from lan_safety import cli, oui

from .helpers import sources

GW = ("192.168.1.1", "aa:bb:cc:00:00:01")
NEW = ("192.168.1.99", "aa:bb:cc:99:99:99")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = os.path.join(tmp.name, "t.db")
        self.tmp = tmp.name
        env = mock.patch.dict(os.environ, {"LAN_SAFETY_OUI": os.path.join(tmp.name, "oui.csv")})
        env.start()
        self.addCleanup(env.stop)

    def scan(self, devices, *extra):
        with mock.patch("lan_safety.scanner.default_sources", lambda cfg: sources(devices)):
            return run("scan", "--db", self.db, "--network", "192.168.1.0/24", *extra)

    def test_full_flow(self):
        code, out, _ = self.scan([GW])
        self.assertEqual(code, 0)
        self.assertIn("baseline", out)

        code, out, _ = self.scan([GW, NEW], "--fail-on-unknown")
        self.assertEqual(code, 2)
        self.assertIn("Device sconosciuto in LAN", out)

        _, out, _ = run("devices", "--db", self.db, "--status", "unknown")
        self.assertIn("aa:bb:cc:99:99:99", out)
        self.assertIn("SCONOSCIUTO", out)
        self.assertNotIn("aa:bb:cc:00:00:01", out)

        _, out, _ = run("alerts", "--db", self.db)
        self.assertIn("Device sconosciuto in LAN", out)

        self.assertEqual(run("approve", "AA-BB-CC-99-99-99", "--db", self.db, "--label", "ospite")[0], 0)
        self.assertEqual(self.scan([GW, NEW], "--fail-on-unknown")[0], 0)
        self.assertIn("ospite", run("devices", "--db", self.db)[1])

        self.assertEqual(run("ack", "--all", "--db", self.db)[0], 0)
        self.assertIn("Nessun alert", run("alerts", "--db", self.db)[1])

    def test_json_outputs(self):
        self.scan([GW])
        import json

        devices = json.loads(run("devices", "--db", self.db, "--json")[1])
        self.assertEqual(devices[0]["mac"], GW[1])
        self.assertEqual(devices[0]["services"], [])

    def test_errors(self):
        self.assertEqual(run("approve", "--db", self.db)[0], 1)
        code, _, err = run("approve", "aa:bb:cc:00:00:09", "--db", self.db)
        self.assertEqual(code, 1)
        self.assertIn("non trovato", err)
        self.assertEqual(run("ack", "--db", self.db)[0], 1)
        self.assertEqual(run("scan", "--db", self.db, "--network", "10.0.0.0/8")[0], 1)
        self.assertEqual(run("scan", "--db", self.db, "--network", "2001:db8::/64")[0], 1)
        self.assertEqual(run("scan", "--db", self.db, "--network", "10.0.0.0/24", "--webhook", "ftp://x")[0], 1)

    def test_update_oui_from_file(self):
        src = os.path.join(self.tmp, "ieee.csv")
        with open(src, "w") as fh:
            fh.write("Registry,Assignment,Organization Name,Organization Address\nMA-L,AABBCC,Acme Corp,Qui\n")
        code, out, _ = run("update-oui", "--from-file", src)
        self.assertEqual(code, 0)
        self.assertEqual(oui.OuiDatabase.load().lookup("aa:bb:cc:00:00:01"), "Acme Corp")


if __name__ == "__main__":
    unittest.main()


class NetworkResolutionTests(unittest.TestCase):
    def parse(self, *argv):
        return cli.build_parser().parse_args(["scan", *argv])

    def test_explicit_network_does_not_inherit_default_iface(self):
        with mock.patch("lan_safety.netinfo.default_interface", return_value="eth0") as d:
            cfg = cli._resolve_network(self.parse("--network", "10.9.8.0/24"))
        d.assert_not_called()
        self.assertIsNone(cfg.iface)
        self.assertEqual(str(cfg.network), "10.9.8.0/24")

    def test_explicit_iface_is_kept_with_network(self):
        with mock.patch("lan_safety.netinfo.interface_address", return_value=None):
            cfg = cli._resolve_network(self.parse("--network", "10.9.8.0/24", "--iface", "eth1"))
        self.assertEqual(cfg.iface, "eth1")
