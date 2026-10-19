"""Strutture dati condivise tra i moduli."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def clean_text(value: Optional[str], limit: int = 120) -> Optional[str]:
    """Rende sicuro per terminale/log/e-mail un testo ricevuto dalla rete (mDNS, SNMP).

    Rimuove caratteri di controllo (incluse le sequenze ESC) e tronca. Restituisce None se non resta nulla.
    """
    if value is None:
        return None
    text = "".join(ch if ch.isprintable() else " " for ch in value)
    text = " ".join(text.split())[:limit]
    return text or None


@dataclass
class Observation:
    """Un device visto durante una scansione, con tutte le informazioni raccolte."""

    mac: str
    ip: str
    vendor: Optional[str] = None
    randomized: bool = False
    hostname: Optional[str] = None
    services: List[str] = field(default_factory=list)
    snmp_name: Optional[str] = None
    snmp_descr: Optional[str] = None
    snmp_object_id: Optional[str] = None
    snmp_location: Optional[str] = None


SEVERITY_INFO = "info"
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"

KIND_UNKNOWN_DEVICE = "unknown_device"
KIND_IP_CHANGED = "ip_changed"


@dataclass
class Alert:
    id: int
    ts: str
    kind: str
    severity: str
    mac: str
    ip: Optional[str]
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
