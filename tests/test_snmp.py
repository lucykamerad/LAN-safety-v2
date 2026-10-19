import socket
import threading
import unittest

from lan_safety import snmp


def make_response(request_id: int, values: dict, error_status: int = 0) -> bytes:
    """Costruisce una GetResponse SNMPv2c (usa le stesse primitive BER del client)."""
    tlv = snmp._tlv
    binds = b""
    for oid, (tag, body) in values.items():
        binds += tlv(0x30, snmp.encode_oid(oid) + tlv(tag, body))
    pdu = tlv(0xA2, snmp.encode_int(request_id) + snmp.encode_int(error_status) + snmp.encode_int(0) + tlv(0x30, binds))
    return tlv(0x30, snmp.encode_int(1) + tlv(0x04, b"public") + pdu)


SYS = {
    snmp.OIDS["descr"]: (0x04, b"Linux router\r\n 5.15"),
    snmp.OIDS["object_id"]: (0x06, bytes([0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x01])),  # 1.3.6.1.4.1.311.1
    snmp.OIDS["name"]: (0x04, b"gw1"),
    snmp.OIDS["location"]: (0x80, b""),  # noSuchObject
}


class FakeAgent(threading.Thread):
    def __init__(self, community="public"):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(3)
        self.port = self.sock.getsockname()[1]
        self.community = community.encode()
        self.requests = 0
        self.sock.settimeout(3)

    def run(self):
        try:
            while True:
                data, addr = self.sock.recvfrom(4096)
                self.requests += 1
                if self.community not in data:
                    continue  # community errata: l'agente tace
                _, msg, _ = snmp._read_tlv(data, 0)
                pos = snmp._read_tlv(msg, 0)[2]
                pos = snmp._read_tlv(msg, pos)[2]
                _, pdu, _ = snmp._read_tlv(msg, pos)
                rid = int.from_bytes(snmp._read_tlv(pdu, 0)[1], "big")
                self.sock.sendto(make_response(rid, SYS), addr)
        except OSError:
            pass


class SnmpTests(unittest.TestCase):
    def test_encode_oid_known_bytes(self):
        self.assertEqual(snmp.encode_oid("1.3.6.1.2.1.1.1.0"), bytes.fromhex("06082b06010201010100"))
        self.assertEqual(snmp.encode_oid("1.3.6.1.4.1.311.1"), bytes.fromhex("06082b0601040182370 1".replace(" ", "")))

    def test_encode_int(self):
        self.assertEqual(snmp.encode_int(0), b"\x02\x01\x00")
        self.assertEqual(snmp.encode_int(128), b"\x02\x02\x00\x80")
        self.assertEqual(snmp.encode_int(300), b"\x02\x02\x01\x2c")

    def test_request_is_well_formed(self):
        pkt = snmp.build_get_request("public", 42, list(snmp.OIDS.values()))
        self.assertEqual(pkt[0], 0x30)
        self.assertIn(b"public", pkt)
        self.assertIn(bytes.fromhex("06082b06010201010100"), pkt)

    def test_parse_response(self):
        values = snmp.parse_response(make_response(7, SYS), 7)
        self.assertEqual(values[snmp.OIDS["name"]], "gw1")
        self.assertEqual(values[snmp.OIDS["descr"]], "Linux router 5.15")  # spazi normalizzati
        self.assertEqual(values[snmp.OIDS["object_id"]], "1.3.6.1.4.1.311.1")
        self.assertNotIn(snmp.OIDS["location"], values)

    def test_parse_response_wrong_id_and_garbage(self):
        self.assertIsNone(snmp.parse_response(make_response(7, SYS), 8))
        self.assertEqual(snmp.parse_response(make_response(7, SYS, error_status=2), 7), {})
        with self.assertRaises(ValueError):
            snmp.parse_response(b"\x30\x05\x01", 1)

    def test_query_against_fake_agent(self):
        agent = FakeAgent()
        agent.start()
        info = snmp.query("127.0.0.1", ["public"], timeout=1, port=agent.port)
        self.assertEqual((info.name, info.object_id, info.location), ("gw1", "1.3.6.1.4.1.311.1", None))

    def test_query_tries_next_community(self):
        agent = FakeAgent(community="segreta")
        agent.start()
        info = snmp.query("127.0.0.1", ["public", "segreta"], timeout=0.3, retries=0, port=agent.port)
        self.assertEqual(info.name, "gw1")

    def test_query_no_agent_returns_none_quickly(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()  # porta chiusa -> ICMP unreachable
        self.assertIsNone(snmp.query("127.0.0.1", ["public"], timeout=0.5, port=port))

    def test_query_many(self):
        agent = FakeAgent()
        agent.start()
        res = snmp.query_many(["127.0.0.1"], ["public"], timeout=1, port=agent.port)
        self.assertEqual(res["127.0.0.1"].name, "gw1")
        self.assertEqual(snmp.query_many([], ["public"]), {})


if __name__ == "__main__":
    unittest.main()
