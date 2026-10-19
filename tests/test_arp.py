import ipaddress
import tempfile
import unittest
from unittest import mock

from lan_safety import arp

TABLE = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         AA:BB:CC:00:00:01     *        eth0
192.168.1.20     0x1         0x2         aa:bb:cc:00:00:20     *        eth0
192.168.1.30     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.40     0x1         0x2         aa:bb:cc:00:00:40     *        wlan0
10.0.0.5         0x1         0x2         aa:bb:cc:00:00:05     *        eth0
broken line
"""


class ArpTests(unittest.TestCase):
    def test_parse_skips_incomplete_and_lowercases(self):
        entries = arp.parse_arp_table(TABLE)
        self.assertEqual([e.ip for e in entries], ["192.168.1.1", "192.168.1.20", "192.168.1.40", "10.0.0.5"])
        self.assertEqual(entries[0].mac, "aa:bb:cc:00:00:01")

    def test_parse_filters_iface(self):
        self.assertEqual([e.ip for e in arp.parse_arp_table(TABLE, "wlan0")], ["192.168.1.40"])

    def test_mac_with_several_ips_gets_stable_lowest_ip(self):
        rows = ["192.168.1.2      0x1         0x2         aa:bb:cc:00:00:01     *        eth0",
                "192.168.1.10     0x1         0x2         aa:bb:cc:00:00:01     *        eth0",
                "192.168.1.1      0x1         0x2         aa:bb:cc:00:00:01     *        eth0"]
        header = TABLE.splitlines()[0]
        for order in (rows, rows[::-1]):
            with tempfile.NamedTemporaryFile("w", suffix=".arp") as fh:
                fh.write("\n".join([header] + order) + "\n")
                fh.flush()
                with mock.patch("lan_safety.arp.time.sleep"):
                    found = arp.sweep(ipaddress.ip_network("192.168.1.0/24"), passes=1, arp_path=fh.name)
            self.assertEqual([e.ip for e in found], ["192.168.1.1"])

    def test_sweep_filters_to_network_and_rejects_huge(self):
        with tempfile.NamedTemporaryFile("w", suffix=".arp") as fh:
            fh.write(TABLE)
            fh.flush()
            with mock.patch("lan_safety.arp.time.sleep"):
                found = arp.sweep(ipaddress.ip_network("192.168.1.0/29"), "eth0", passes=1, arp_path=fh.name)
            self.assertEqual([e.ip for e in found], ["192.168.1.1"])
        with self.assertRaises(ValueError):
            arp.sweep(ipaddress.ip_network("10.0.0.0/8"))


if __name__ == "__main__":
    unittest.main()
