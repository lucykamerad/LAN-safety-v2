"""Interfaccia a riga di comando: ``lan-safety scan|watch|devices|approve|alerts|ack|remove|update-oui``."""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import signal
import sqlite3
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, netinfo, oui
from .alerts import EmailNotifier, Notifier, WebhookNotifier, deliver, print_alert
from .arp import MAX_HOSTS
from .db import STATUS_APPROVED, STATUS_UNKNOWN, Database
from .models import KIND_UNKNOWN_DEVICE
from .scanner import ScanConfig, ScanResult, run_scan

log = logging.getLogger("lan_safety")


def default_db_path() -> str:
    return os.environ.get("LAN_SAFETY_DB") or str(oui.data_dir() / "lan-safety.db")


def _common_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--db", default=default_db_path(), help="file SQLite (default: %(default)s, o $LAN_SAFETY_DB)")
    return p


def _scan_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--network", help="subnet da scansionare, es. 192.168.1.0/24 (default: quella dell'interfaccia di default)")
    p.add_argument("--iface", help="interfaccia di rete (default: quella della route di default)")
    p.add_argument("--no-mdns", action="store_true", help="disattiva la scoperta mDNS")
    p.add_argument("--mdns-timeout", type=float, default=3.0, help="secondi di ascolto mDNS (default: 3)")
    p.add_argument("--no-snmp", action="store_true", help="disattiva le query SNMP")
    p.add_argument("--snmp-community", action="append", metavar="NOME",
                   help="community SNMPv2c da provare (ripetibile, default: public)")
    p.add_argument("--strict", action="store_true",
                   help="non imparare automaticamente i device al primo avvio: segnala anche quelli")
    p.add_argument("--webhook", default=os.environ.get("LAN_SAFETY_WEBHOOK"),
                   help="URL a cui inviare gli alert in POST JSON (o $LAN_SAFETY_WEBHOOK)")
    p.add_argument("--smtp-host", help="server SMTP per gli alert via e-mail")
    p.add_argument("--smtp-port", type=int, help="porta SMTP (default: 25, 587 con --smtp-starttls, 465 con --smtp-ssl)")
    p.add_argument("--smtp-user", help="utente SMTP (la password va in $LAN_SAFETY_SMTP_PASSWORD)")
    p.add_argument("--smtp-starttls", action="store_true")
    p.add_argument("--smtp-ssl", action="store_true")
    p.add_argument("--mail-from", help="mittente e-mail")
    p.add_argument("--mail-to", action="append", metavar="INDIRIZZO", help="destinatario e-mail (ripetibile)")
    return p


def build_parser() -> argparse.ArgumentParser:
    common, scan = _common_parser(), _scan_parser()
    parser = argparse.ArgumentParser(prog="lan-safety", description="Inventario della LAN con rilevamento di device sconosciuti.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", parents=[common, scan], help="esegue una scansione")
    p.add_argument("--fail-on-unknown", action="store_true", help="exit code 2 se compaiono device sconosciuti (per cron/script)")

    p = sub.add_parser("watch", parents=[common, scan], help="scansiona a intervalli regolari")
    p.add_argument("--interval", type=int, default=300, help="secondi tra una scansione e l'altra (default: 300)")

    p = sub.add_parser("devices", parents=[common], help="elenca l'inventario")
    p.add_argument("--status", choices=[STATUS_UNKNOWN, STATUS_APPROVED], help="filtra per stato")
    p.add_argument("--json", action="store_true", help="output JSON")

    p = sub.add_parser("approve", parents=[common], help="segna un device come noto/fidato")
    p.add_argument("mac", nargs="?")
    p.add_argument("--all", action="store_true", help="approva tutti i device sconosciuti")
    p.add_argument("--label", help="etichetta descrittiva, es. 'stampante ufficio'")

    p = sub.add_parser("remove", parents=[common], help="elimina un device dall'inventario")
    p.add_argument("mac")

    p = sub.add_parser("alerts", parents=[common], help="elenca gli alert non ancora letti")
    p.add_argument("--all", action="store_true", help="include quelli già letti")
    p.add_argument("--json", action="store_true", help="output JSON")

    p = sub.add_parser("ack", parents=[common], help="segna alert come letti")
    p.add_argument("ids", nargs="*", type=int)
    p.add_argument("--all", action="store_true")

    p = sub.add_parser("ui", parents=[common], help="avvia la dashboard web")
    p.add_argument("--host", default="127.0.0.1", help="indirizzo di ascolto (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8080, help="porta (default: 8080)")
    p.add_argument("--allow-remote", action="store_true",
                   help="consente un indirizzo non locale (la dashboard non ha autenticazione né HTTPS)")

    p = sub.add_parser("update-oui", help="scarica/importa il database dei produttori (OUI)")
    p.add_argument("--from-file", type=Path, help="importa da un file (CSV IEEE o 'manuf' di Wireshark) invece di scaricare")
    p.add_argument("--url", default=oui.IEEE_OUI_URL)
    return parser


# --- helpers ---------------------------------------------------------------

def _table(headers: Sequence[str], rows: List[Sequence[str]]) -> str:
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows)] if rows else [len(h) for h in headers]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    return "\n".join([fmt.format(*headers), fmt.format(*("-" * w for w in widths))] + [fmt.format(*map(str, r)) for r in rows])


def _resolve_network(args: argparse.Namespace) -> ScanConfig:
    # Con --network esplicito l'interfaccia di default non va presupposta: la subnet potrebbe essere un'altra.
    iface = args.iface or (None if args.network else netinfo.default_interface())
    addr = netinfo.interface_address(iface) if iface else None
    if args.network:
        network = ipaddress.ip_network(args.network, strict=False)
        if network.version != 4:
            raise ValueError("è supportato solo IPv4")
    elif addr:
        network = addr.network
    else:
        raise ValueError("impossibile determinare la rete: usa --network (es. --network 192.168.1.0/24)")
    if network.num_addresses - 2 > MAX_HOSTS:
        raise ValueError(f"la rete {network} è troppo grande (massimo {MAX_HOSTS} host): usa una subnet più piccola")
    return ScanConfig(
        network=network, iface=iface,
        local_ip=str(addr.ip) if addr and addr.ip in network else None,
        use_mdns=not args.no_mdns, mdns_timeout=args.mdns_timeout,
        use_snmp=not args.no_snmp, snmp_communities=tuple(args.snmp_community or ["public"]),
        strict=args.strict,
    )


def _build_notifiers(args: argparse.Namespace) -> List[Notifier]:
    notifiers: List[Notifier] = []
    if args.webhook:
        notifiers.append(WebhookNotifier(args.webhook))
    if args.smtp_host:
        if not args.mail_from or not args.mail_to:
            raise ValueError("per l'e-mail servono --mail-from e --mail-to")
        port = args.smtp_port or (465 if args.smtp_ssl else 587 if args.smtp_starttls else 25)
        notifiers.append(EmailNotifier(args.smtp_host, port, args.mail_from, args.mail_to, args.smtp_user,
                                       os.environ.get("LAN_SAFETY_SMTP_PASSWORD"), args.smtp_starttls, args.smtp_ssl))
    return notifiers


def _scan_once(db: Database, cfg: ScanConfig, db_oui: oui.OuiDatabase, notifiers: List[Notifier]) -> ScanResult:
    result = run_scan(db, cfg, db_oui)
    unknown_new = [a for a in result.alerts if a.kind == KIND_UNKNOWN_DEVICE]
    print(f"Scansione {cfg.network}: {len(result.observations)} device attivi, {len(unknown_new)} nuovi sconosciuti.")
    if result.learned:
        print(f"Primo avvio: {len(result.observations)} device registrati come baseline fidata (approvati). "
              "Da ora ogni nuovo MAC genera un alert.")
    for alert in result.alerts:
        print_alert(alert)
    deliver(db, notifiers)
    return result


# --- comandi ---------------------------------------------------------------

def cmd_scan(args: argparse.Namespace) -> int:
    cfg, notifiers = _resolve_network(args), _build_notifiers(args)
    db = Database(args.db)
    try:
        result = _scan_once(db, cfg, oui.OuiDatabase.load(), notifiers)
    finally:
        db.close()
    if args.fail_on_unknown and any(a.kind == KIND_UNKNOWN_DEVICE for a in result.alerts):
        return 2
    return 0


def _raise_interrupt(signum, frame) -> None:
    raise KeyboardInterrupt


def cmd_watch(args: argparse.Namespace) -> int:
    if args.interval < 5:
        raise ValueError("--interval deve essere almeno 5 secondi")
    cfg, notifiers = _resolve_network(args), _build_notifiers(args)
    db_oui = oui.OuiDatabase.load()
    db = Database(args.db)
    print(f"Monitoraggio di {cfg.network} ogni {args.interval}s (Ctrl+C per fermare)")
    # systemd/docker fermano con SIGTERM: lo trattiamo come Ctrl+C per chiudere il DB in modo pulito
    signal.signal(signal.SIGTERM, _raise_interrupt)
    try:
        while True:
            try:
                _scan_once(db, cfg, db_oui, notifiers)
            except Exception as exc:  # una scansione fallita non deve fermare il monitoraggio
                log.warning("scansione fallita: %s", exc)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nInterrotto.")
        return 0
    finally:
        db.close()


def cmd_devices(args: argparse.Namespace) -> int:
    db = Database(args.db)
    try:
        rows = db.list_devices(args.status)
    finally:
        db.close()
    if args.json:
        print(json.dumps([{**dict(r), "services": json.loads(r["services"])} for r in rows], indent=2, ensure_ascii=False))
        return 0
    if not rows:
        print("Nessun device in inventario. Esegui prima: lan-safety scan")
        return 0
    print(_table(
        ["MAC", "IP", "STATO", "PRODUTTORE", "NOME", "ETICHETTA", "ULTIMA VISTA"],
        [[r["mac"], r["ip"] or "-", "approvato" if r["status"] == STATUS_APPROVED else "SCONOSCIUTO",
          r["vendor"] or ("(MAC privato)" if r["randomized"] else "-"),
          r["hostname"] or r["snmp_name"] or "-", r["label"] or "-", r["last_seen"]] for r in rows],
    ))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    if bool(args.mac) == args.all:
        raise ValueError("indica un MAC oppure --all")
    db = Database(args.db)
    try:
        n = db.approve(None if args.all else args.mac, args.label)
    finally:
        db.close()
    if n == 0 and args.mac:
        print(f"Device {args.mac} non trovato in inventario.", file=sys.stderr)
        return 1
    print(f"{n} device approvati.")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    db = Database(args.db)
    try:
        n = db.remove(args.mac)
    finally:
        db.close()
    if n == 0:
        print(f"Device {args.mac} non trovato in inventario.", file=sys.stderr)
        return 1
    print("Device eliminato.")
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    db = Database(args.db)
    try:
        alerts = db.list_alerts(include_acked=args.all)
    finally:
        db.close()
    if args.json:
        print(json.dumps([a.__dict__ for a in alerts], indent=2, ensure_ascii=False))
        return 0
    if not alerts:
        print("Nessun alert.")
    for a in alerts:
        print(f"#{a.id} ", end="")
        print_alert(a)
    return 0


def cmd_ack(args: argparse.Namespace) -> int:
    if bool(args.ids) == args.all:
        raise ValueError("indica uno o più ID oppure --all")
    db = Database(args.db)
    try:
        n = db.ack_alerts(None if args.all else args.ids)
    finally:
        db.close()
    print(f"{n} alert segnati come letti.")
    return 0


def cmd_ui(args: argparse.Namespace) -> int:
    from .web import make_server

    server = make_server(args.db, args.host, args.port, args.allow_remote)
    print(f"Dashboard su http://{args.host}:{server.server_address[1]}/  (Ctrl+C per fermare)")
    signal.signal(signal.SIGTERM, _raise_interrupt)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nInterrotto.")
    finally:
        server.server_close()
    return 0


def cmd_update_oui(args: argparse.Namespace) -> int:
    if args.from_file:
        table = oui.parse_oui_text(args.from_file.read_text(encoding="utf-8", errors="replace"))
        if not table:
            raise ValueError(f"nessuna voce OUI riconosciuta in {args.from_file}")
    else:
        print(f"Scarico {args.url} ...")
        table = oui.download_ieee(args.url)
    oui.save_table(table, oui.oui_path())
    print(f"{len(table)} produttori salvati in {oui.oui_path()}")
    return 0


COMMANDS = {
    "scan": cmd_scan, "watch": cmd_watch, "devices": cmd_devices, "approve": cmd_approve,
    "remove": cmd_remove, "alerts": cmd_alerts, "ack": cmd_ack, "ui": cmd_ui, "update-oui": cmd_update_oui,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except (ValueError, OSError, RuntimeError, sqlite3.Error) as exc:
        print(f"Errore: {exc}", file=sys.stderr)
        return 1
