"""Scoperta ARP senza privilegi.

Si inviano piccoli datagrammi UDP a tutti gli host della subnet: per consegnarli
il kernel esegue la risoluzione ARP, e le risposte finiscono in /proc/net/arp,
che poi si legge. Non servono root, raw socket né librerie esterne.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import List, Optional

ARP_PATH = "/proc/net/arp"
MAX_HOSTS = 4096
_ZERO_MAC = "00:00:00:00:00:00"
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
ATF_COM = 0x2  # entry completa (risolta)


@dataclass(frozen=True)
class ArpEntry:
    ip: str
    mac: str
    iface: str


def parse_arp_table(text: str, iface: Optional[str] = None) -> List[ArpEntry]:
    entries: List[ArpEntry] = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 6:
            continue
        ip, _hw_type, flags, mac, _mask, dev = cols[:6]
        try:
            complete = int(flags, 16) & ATF_COM
        except ValueError:
            continue
        mac = mac.lower()
        if not complete or mac in (_ZERO_MAC, _BROADCAST_MAC):
            continue
        if iface and dev != iface:
            continue
        entries.append(ArpEntry(ip=ip, mac=mac, iface=dev))
    return entries


def read_arp_table(path: str = ARP_PATH, iface: Optional[str] = None) -> List[ArpEntry]:
    with open(path, encoding="utf-8") as fh:
        return parse_arp_table(fh.read(), iface)


def sweep(
    network: ipaddress.IPv4Network,
    iface: Optional[str] = None,
    passes: int = 2,
    settle: float = 1.5,
    arp_path: str = ARP_PATH,
    max_hosts: int = MAX_HOSTS,
) -> List[ArpEntry]:
    """Forza la risoluzione ARP di ogni host della subnet e restituisce i device che hanno risposto."""
    if network.num_addresses - 2 > max_hosts:  # controllo prima di creare la lista degli host
        raise ValueError(
            f"la rete {network} ha troppi host (massimo {max_hosts}): indica una subnet più piccola con --network"
        )
    hosts = [str(h) for h in network.hosts()]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.2)
        if iface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
            except (OSError, AttributeError):
                pass  # richiede privilegi su alcuni kernel: la route di default basta
        for _ in range(passes):
            for host in hosts:
                try:
                    sock.sendto(b"\x00", (host, 9))  # porta "discard": serve solo a far partire l'ARP
                except OSError:
                    pass
            time.sleep(settle)
    # Un MAC può comparire con più IP (alias del router, proxy-ARP): si tiene il più basso, così
    # l'IP registrato non dipende dall'ordine della tabella e non genera falsi "cambio IP".
    found = {}
    for entry in read_arp_table(arp_path, iface):
        addr = ipaddress.ip_address(entry.ip)
        if addr in network and (entry.mac not in found or addr < ipaddress.ip_address(found[entry.mac].ip)):
            found[entry.mac] = entry
    return list(found.values())
