"""Rilevamento dell'interfaccia di default e della sua subnet IPv4 (solo Linux)."""

from __future__ import annotations

import ipaddress
import socket
import struct
from typing import Optional

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B


def parse_default_interface(route_text: str) -> Optional[str]:
    """Interfaccia della route di default (la con metrica più bassa) da /proc/net/route."""
    best = None
    for line in route_text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 8 or cols[1] != "00000000" or cols[7] != "00000000":
            continue
        if not int(cols[3], 16) & 0x2:  # RTF_GATEWAY
            continue
        metric = int(cols[6])
        if best is None or metric < best[0]:
            best = (metric, cols[0])
    return best[1] if best else None


def default_interface(route_path: str = "/proc/net/route") -> Optional[str]:
    try:
        with open(route_path, encoding="utf-8") as fh:
            return parse_default_interface(fh.read())
    except OSError:
        return None


def _ioctl_ipv4(iface: str, request: int) -> str:
    import fcntl

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        packed = fcntl.ioctl(sock.fileno(), request, struct.pack("256s", iface.encode()[:15]))
    return socket.inet_ntoa(packed[20:24])


def interface_address(iface: str) -> Optional[ipaddress.IPv4Interface]:
    """Indirizzo/netmask IPv4 dell'interfaccia (es. 192.168.1.10/24) oppure None."""
    try:
        addr = _ioctl_ipv4(iface, SIOCGIFADDR)
        mask = _ioctl_ipv4(iface, SIOCGIFNETMASK)
        return ipaddress.IPv4Interface(f"{addr}/{mask}")
    except (OSError, ImportError, ValueError):
        return None
