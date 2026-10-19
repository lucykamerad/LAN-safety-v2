import socket
import struct
import unittest

from lan_safety import mdns
from lan_safety.mdns import META_QUERY, TYPE_A, TYPE_PTR, TYPE_SRV, Record


def rr(name: bytes, rtype: int, rdata: bytes) -> bytes:
    return name + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def response(*rrs: bytes) -> bytes:
    return struct.pack("!HHHHHH", 0, 0x8400, 0, len(rrs), 0, 0) + b"".join(rrs)


class MdnsTests(unittest.TestCase):
    def test_build_query_roundtrip_header(self):
        pkt = mdns.build_query([META_QUERY, "_ipp._tcp.local"])
        self.assertEqual(struct.unpack("!HHHHHH", pkt[:12]), (0, 0, 2, 0, 0, 0))
        self.assertEqual(mdns._read_name(pkt, 12)[0], META_QUERY)

    def test_parse_and_summarize_with_compression(self):
        host = mdns.encode_name("printer.local")
        inst = mdns.encode_name("Ufficio._ipp._tcp.local")
        stype = mdns.encode_name("_ipp._tcp.local")
        data = response(
            rr(host, TYPE_A, socket.inet_aton("192.168.1.50")),
            rr(stype, TYPE_PTR, inst),
            rr(inst, TYPE_SRV, struct.pack("!HHH", 0, 0, 631) + host),
        )
        records = mdns.parse_message(data)
        self.assertEqual(len(records), 3)
        info = mdns.summarize(records)["192.168.1.50"]
        self.assertEqual(info.hostname, "printer")
        self.assertEqual(info.services, {"_ipp._tcp"})

    def test_compression_pointer(self):
        # il secondo record usa un puntatore (0xC00C) al nome del primo, a offset 12
        name = mdns.encode_name("pc.local")
        first = rr(name, TYPE_A, socket.inet_aton("10.0.0.2"))
        second = rr(b"\xc0\x0c", TYPE_A, socket.inet_aton("10.0.0.3"))
        records = mdns.parse_message(response(first, second))
        self.assertEqual([r.name for r in records], ["pc.local", "pc.local"])

    def test_service_type_falls_back_to_instance_name(self):
        host = mdns.encode_name("tv.local")
        inst = mdns.encode_name("Salotto._googlecast._tcp.local")
        records = mdns.parse_message(response(
            rr(host, TYPE_A, socket.inet_aton("10.0.0.9")),
            rr(inst, TYPE_SRV, struct.pack("!HHH", 0, 0, 8009) + host),
        ))
        self.assertEqual(mdns.summarize(records)["10.0.0.9"].services, {"_googlecast._tcp"})

    def test_meta_query_ptr_is_not_a_service_instance(self):
        records = [Record(META_QUERY, TYPE_PTR, "_ipp._tcp.local")]
        self.assertEqual(mdns.summarize(records), {})

    def test_queries_and_garbage_are_rejected_safely(self):
        self.assertEqual(mdns.parse_message(mdns.build_query([META_QUERY])), [])  # è una query
        for bad in (b"", b"\x00" * 5, response(rr(mdns.encode_name("a.local"), TYPE_A, b"\x01\x02\x03\x04"))[:-2]):
            with self.assertRaises(ValueError):
                mdns.parse_message(bad)
        loop = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\xc0\x0c" + b"\x00" * 10
        with self.assertRaises(ValueError):
            mdns.parse_message(loop)


if __name__ == "__main__":
    unittest.main()
