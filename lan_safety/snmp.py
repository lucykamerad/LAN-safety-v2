"""Client SNMPv2c minimale (solo GET di sysDescr/sysObjectID/sysName/sysLocation)."""

from __future__ import annotations

import random
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

OIDS = {
    "descr": "1.3.6.1.2.1.1.1.0",
    "object_id": "1.3.6.1.2.1.1.2.0",
    "name": "1.3.6.1.2.1.1.5.0",
    "location": "1.3.6.1.2.1.1.6.0",
}


@dataclass
class SnmpInfo:
    name: Optional[str] = None
    descr: Optional[str] = None
    object_id: Optional[str] = None
    location: Optional[str] = None


# --- BER -------------------------------------------------------------------

def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _length(len(value)) + value


def encode_int(value: int) -> bytes:
    size = (value.bit_length() + 8) // 8
    return _tlv(0x02, value.to_bytes(size, "big"))


def encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(".").split(".")]
    if len(parts) < 2:
        raise ValueError("OID troppo corto")
    body = bytearray([40 * parts[0] + parts[1]])
    for sub in parts[2:]:
        chunk = [sub & 0x7F]
        sub >>= 7
        while sub:
            chunk.append(0x80 | (sub & 0x7F))
            sub >>= 7
        body.extend(reversed(chunk))
    return _tlv(0x06, bytes(body))


def build_get_request(community: str, request_id: int, oids: Sequence[str]) -> bytes:
    varbinds = b"".join(_tlv(0x30, encode_oid(o) + b"\x05\x00") for o in oids)
    pdu = _tlv(0xA0, encode_int(request_id) + encode_int(0) + encode_int(0) + _tlv(0x30, varbinds))
    return _tlv(0x30, encode_int(1) + _tlv(0x04, community.encode()) + pdu)  # version 1 = SNMPv2c


def _read_tlv(data: bytes, pos: int) -> Tuple[int, bytes, int]:
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4:
            raise ValueError("lunghezza BER non supportata")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + length > len(data):
        raise ValueError("TLV oltre la fine del pacchetto")
    return tag, data[pos : pos + length], pos + length


def _decode_oid(body: bytes) -> str:
    if not body:
        return ""
    parts = [body[0] // 40, body[0] % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _decode_value(tag: int, body: bytes) -> Optional[str]:
    if tag in (0x80, 0x81, 0x82):  # noSuchObject / noSuchInstance / endOfMibView
        return None
    if tag == 0x04:
        return re.sub(r"\s+", " ", body.decode("utf-8", "replace")).strip()[:200]
    if tag == 0x06:
        return _decode_oid(body)
    if tag in (0x02, 0x41, 0x42, 0x43, 0x46):
        return str(int.from_bytes(body, "big", signed=(tag == 0x02)))
    if tag == 0x40 and len(body) == 4:
        return socket.inet_ntoa(body)
    return None


def parse_response(data: bytes, request_id: int) -> Optional[Dict[str, str]]:
    """Restituisce ``{oid: valore}`` oppure None se non è la risposta attesa. ValueError se malformata."""
    try:
        tag, msg, _ = _read_tlv(data, 0)
        if tag != 0x30:
            raise ValueError("messaggio SNMP non valido")
        _, _version, pos = _read_tlv(msg, 0)
        _, _community, pos = _read_tlv(msg, pos)
        tag, pdu, _ = _read_tlv(msg, pos)
        if tag != 0xA2:  # GetResponse
            return None
        _, rid, pos = _read_tlv(pdu, 0)
        if int.from_bytes(rid, "big") != request_id:
            return None
        _, error_status, pos = _read_tlv(pdu, pos)
        _, _error_index, pos = _read_tlv(pdu, pos)
        if int.from_bytes(error_status, "big") != 0:
            return {}
        _, varbinds, _ = _read_tlv(pdu, pos)
        result: Dict[str, str] = {}
        pos = 0
        while pos < len(varbinds):
            _, vb, pos = _read_tlv(varbinds, pos)
            _, oid_body, vpos = _read_tlv(vb, 0)
            vtag, vbody, _ = _read_tlv(vb, vpos)
            value = _decode_value(vtag, vbody)
            if value:
                result[_decode_oid(oid_body)] = value
        return result
    except (IndexError, ValueError) as exc:
        raise ValueError(f"risposta SNMP malformata: {exc}") from exc


# --- rete ------------------------------------------------------------------

def query(
    ip: str,
    communities: Sequence[str],
    timeout: float = 0.8,
    retries: int = 1,
    port: int = 161,
) -> Optional[SnmpInfo]:
    """Prova ogni community in ordine; restituisce SnmpInfo se l'agente risponde, altrimenti None."""
    oids = list(OIDS.values())
    for community in communities:
        request_id = random.getrandbits(30) or 1
        packet = build_get_request(community, request_id, oids)
        for _ in range(retries + 1):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(timeout)
                try:
                    sock.connect((ip, port))
                    sock.send(packet)
                    deadline = time.monotonic() + timeout
                    while True:
                        data = sock.recv(65535)
                        try:
                            values = parse_response(data, request_id)
                        except ValueError:
                            values = None
                        if values is not None:
                            break
                        if time.monotonic() >= deadline:
                            raise socket.timeout()
                except ConnectionRefusedError:
                    return None  # porta 161 chiusa: inutile riprovare
                except (socket.timeout, OSError):
                    continue
            if values:
                return SnmpInfo(
                    name=values.get(OIDS["name"]),
                    descr=values.get(OIDS["descr"]),
                    object_id=values.get(OIDS["object_id"]),
                    location=values.get(OIDS["location"]),
                )
            break  # risposta valida ma senza dati (community errata/vista ristretta): prossima community
    return None


def query_many(
    ips: Iterable[str],
    communities: Sequence[str],
    timeout: float = 0.8,
    workers: int = 64,
    port: int = 161,
) -> Dict[str, SnmpInfo]:
    ips = list(ips)
    if not ips or not communities:
        return {}
    with ThreadPoolExecutor(max_workers=min(workers, len(ips))) as pool:
        infos = list(pool.map(lambda ip: query(ip, communities, timeout=timeout, port=port), ips))
    return {ip: info for ip, info in zip(ips, infos) if info}
