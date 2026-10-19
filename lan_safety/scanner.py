"""Orchestrazione di una scansione: ARP -> mDNS -> SNMP -> MAC vendor -> database."""

from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

from . import arp, mdns, snmp
from .db import Database
from .models import Alert, Observation, clean_text
from .oui import OuiDatabase, is_randomized, normalize_mac


@dataclass
class ScanConfig:
    network: ipaddress.IPv4Network
    iface: Optional[str] = None
    local_ip: Optional[str] = None
    use_mdns: bool = True
    mdns_timeout: float = 3.0
    use_snmp: bool = True
    snmp_communities: Sequence[str] = ("public",)
    snmp_timeout: float = 0.8
    strict: bool = False  # True: niente apprendimento automatico al primo avvio


@dataclass
class Sources:
    """Sorgenti dati, sostituibili nei test."""

    arp: Callable[[], List[arp.ArpEntry]]
    mdns: Callable[[], Dict[str, mdns.MdnsDevice]]
    snmp: Callable[[List[str]], Dict[str, snmp.SnmpInfo]]


def default_sources(cfg: ScanConfig) -> Sources:
    return Sources(
        arp=lambda: arp.sweep(cfg.network, cfg.iface),
        mdns=lambda: mdns.discover(cfg.mdns_timeout, cfg.local_ip) if cfg.use_mdns else {},
        snmp=lambda ips: snmp.query_many(ips, cfg.snmp_communities, cfg.snmp_timeout) if cfg.use_snmp else {},
    )


@dataclass
class ScanResult:
    observations: List[Observation] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    learned: bool = False  # primo avvio: i device trovati sono stati approvati automaticamente


def collect(sources: Sources, oui: OuiDatabase) -> List[Observation]:
    entries = sources.arp()
    ips = [e.ip for e in entries]
    mdns_info: Dict[str, mdns.MdnsDevice] = {}
    snmp_info: Dict[str, snmp.SnmpInfo] = {}
    if entries:  # mDNS (attesa passiva) e SNMP (query per host) sono indipendenti: si sovrappongono
        with ThreadPoolExecutor(max_workers=2) as pool:
            f_mdns, f_snmp = pool.submit(sources.mdns), pool.submit(sources.snmp, ips)
            mdns_info, snmp_info = f_mdns.result(), f_snmp.result()

    observations = []
    for entry in entries:
        mac = normalize_mac(entry.mac)
        randomized = is_randomized(mac)
        m = mdns_info.get(entry.ip)
        s = snmp_info.get(entry.ip)
        observations.append(Observation(
            mac=mac, ip=entry.ip,
            vendor=None if randomized else oui.lookup(mac),
            randomized=randomized,
            hostname=clean_text(m.hostname) if m else None,
            services=sorted(filter(None, (clean_text(x, 60) for x in m.services))) if m else [],
            snmp_name=clean_text(s.name) if s else None, snmp_descr=clean_text(s.descr, 200) if s else None,
            snmp_object_id=clean_text(s.object_id) if s else None, snmp_location=clean_text(s.location) if s else None,
        ))
    return observations


def run_scan(db: Database, cfg: ScanConfig, oui: OuiDatabase, sources: Optional[Sources] = None) -> ScanResult:
    observations = collect(sources or default_sources(cfg), oui)
    # Primo avvio (DB vuoto): i device presenti diventano la baseline fidata, senza alert.
    learning = db.device_count() == 0 and not cfg.strict
    result = ScanResult(observations=observations, learned=learning and bool(observations))
    for obs in observations:
        result.alerts.extend(db.record_observation(obs, learning=learning))
    return result
