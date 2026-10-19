"""Scoperta mDNS / DNS-SD minimale (solo libreria standard).

Invia query multicast da una porta effimera (le risposte tornano in unicast,
modalità "legacy unicast" di RFC 6762 §6.7), poi associa nomi host e servizi
agli indirizzi IPv4 trovati nei record A.
"""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353
META_QUERY = "_services._dns-sd._udp.local"

TYPE_A, TYPE_PTR, TYPE_TXT, TYPE_AAAA, TYPE_SRV = 1, 12, 16, 28, 33

COMMON_SERVICES = [
    "_workstation._tcp", "_device-info._tcp", "_http._tcp", "_https._tcp", "_ssh._tcp",
    "_smb._tcp", "_afpovertcp._tcp", "_ipp._tcp", "_ipps._tcp", "_printer._tcp",
    "_pdl-datastream._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp",
    "_hap._tcp", "_homekit._tcp", "_companion-link._tcp", "_spotify-connect._tcp",
]
_MAX_QUESTIONS = 20


@dataclass
class Record:
    name: str
    rtype: int
    data: object  # A: str, PTR: str, SRV: (port, target), TXT: list[str]


@dataclass
class MdnsDevice:
    hostname: Optional[str] = None
    services: Set[str] = field(default_factory=set)


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        if not 0 < len(raw) < 64:
            raise ValueError(f"label DNS non valida: {label!r}")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(names: Iterable[str], qtype: int = TYPE_PTR) -> bytes:
    names = list(names)
    packet = struct.pack("!HHHHHH", 0, 0, len(names), 0, 0, 0)
    for name in names:
        packet += encode_name(name) + struct.pack("!HH", qtype, 0x8001)  # QU + classe IN
    return packet


def _read_name(data: bytes, pos: int) -> Tuple[str, int]:
    labels: List[str] = []
    end: Optional[int] = None
    hops = 0
    while True:
        length = data[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            hops += 1
            if hops > 32:
                raise ValueError("puntatori di compressione ciclici")
            continue
        if length & 0xC0:
            raise ValueError("tipo di label non supportato")
        pos += 1
        if pos + length > len(data):
            raise ValueError("label oltre la fine del pacchetto")
        labels.append(data[pos : pos + length].decode("utf-8", "replace"))
        pos += length
    return ".".join(labels), (end if end is not None else pos)


def parse_message(data: bytes) -> List[Record]:
    """Decodifica una risposta mDNS e restituisce i record A/PTR/SRV/TXT. ValueError se malformata."""
    try:
        if len(data) < 12:
            raise ValueError("pacchetto troppo corto")
        _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        if not flags & 0x8000:
            return []  # è una query, non una risposta
        pos = 12
        for _ in range(qd):
            _, pos = _read_name(data, pos)
            pos += 4
        records: List[Record] = []
        for _ in range(an + ns + ar):
            name, pos = _read_name(data, pos)
            rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
            pos += 10
            rdata_end = pos + rdlen
            if rdata_end > len(data):
                raise ValueError("rdata oltre la fine del pacchetto")
            if rtype == TYPE_A and rdlen == 4:
                records.append(Record(name, rtype, socket.inet_ntoa(data[pos:rdata_end])))
            elif rtype == TYPE_PTR:
                records.append(Record(name, rtype, _read_name(data, pos)[0]))
            elif rtype == TYPE_SRV and rdlen >= 7:
                port = struct.unpack("!H", data[pos + 4 : pos + 6])[0]
                records.append(Record(name, rtype, (port, _read_name(data, pos + 6)[0])))
            pos = rdata_end
        return records
    except (IndexError, struct.error) as exc:
        raise ValueError(f"pacchetto mDNS malformato: {exc}") from exc


def _strip_local(name: str) -> str:
    return name[: -len(".local")] if name.lower().endswith(".local") else name


def summarize(records: Iterable[Record]) -> Dict[str, MdnsDevice]:
    """Raggruppa i record per indirizzo IPv4: nome host e tipi di servizio annunciati."""
    host_ips: Dict[str, Set[str]] = {}
    instance_type: Dict[str, str] = {}
    instance_host: Dict[str, str] = {}
    for rec in records:
        if rec.rtype == TYPE_A:
            host_ips.setdefault(rec.name.lower(), set()).add(rec.data)  # type: ignore[arg-type]
        elif rec.rtype == TYPE_PTR and rec.name.lower() != META_QUERY:
            instance_type[str(rec.data)] = rec.name
        elif rec.rtype == TYPE_SRV:
            instance_host[rec.name] = str(rec.data[1]).lower()  # type: ignore[index]

    devices: Dict[str, MdnsDevice] = {}
    for host, ips in host_ips.items():
        for ip in ips:
            devices.setdefault(ip, MdnsDevice()).hostname = _strip_local(host)
    for instance, host in instance_host.items():
        stype = instance_type.get(instance)
        if stype is None and "._" in instance:
            stype = "_" + instance.split("._", 1)[1]
        if stype is None:
            continue
        stype = _strip_local(stype)
        for ip in host_ips.get(host, ()):
            devices.setdefault(ip, MdnsDevice()).services.add(stype)
    return devices


def _collect(sock: socket.socket, seconds: float, sink: List[Record]) -> None:
    deadline = time.monotonic() + seconds
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        sock.settimeout(remaining)
        try:
            data, _addr = sock.recvfrom(9000)
        except (socket.timeout, BlockingIOError):
            return
        except OSError:
            return
        try:
            sink.extend(parse_message(data))
        except ValueError:
            continue


def discover(timeout: float = 3.0, local_ip: Optional[str] = None) -> Dict[str, MdnsDevice]:
    """Interroga la LAN via mDNS e restituisce ``{ip: MdnsDevice}``. Ritorna {} se il multicast non è disponibile."""
    records: List[Record] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return {}
    with sock:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            if local_ip:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            sock.bind(("", 0))
            dest = (MDNS_GROUP, MDNS_PORT)
            queried = [f"{s}.local" for s in COMMON_SERVICES]
            first = [META_QUERY] + queried
            for i in range(0, len(first), _MAX_QUESTIONS):
                sock.sendto(build_query(first[i : i + _MAX_QUESTIONS]), dest)
            _collect(sock, timeout / 2, records)

            # secondo giro: chiede le istanze dei tipi di servizio scoperti con la meta-query
            discovered = {
                str(r.data) for r in records if r.rtype == TYPE_PTR and r.name.lower() == META_QUERY
            } - set(queried)
            extra = sorted(discovered)[:100]
            for i in range(0, len(extra), _MAX_QUESTIONS):
                sock.sendto(build_query(extra[i : i + _MAX_QUESTIONS]), dest)
            _collect(sock, timeout / 2, records)
        except OSError:
            pass  # nessuna route multicast: si usano i dati eventualmente già raccolti
    return summarize(records)
