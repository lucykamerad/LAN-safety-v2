import ipaddress

from lan_safety import arp, mdns, snmp
from lan_safety.scanner import ScanConfig, Sources

CFG = ScanConfig(network=ipaddress.ip_network("192.168.1.0/24"))


def sources(devices, mdns_info=None, snmp_info=None):
    """``devices``: lista di (ip, mac). Simula ARP/mDNS/SNMP senza toccare la rete."""
    entries = [arp.ArpEntry(ip, mac, "eth0") for ip, mac in devices]
    return Sources(arp=lambda: entries, mdns=lambda: mdns_info or {}, snmp=lambda ips: snmp_info or {})
