"""Dashboard web locale (solo libreria standard) per consultare l'inventario e gestire gli alert.

Pensata per l'uso su localhost. Difese: bind su loopback di default, controllo dell'header Host
(anti DNS-rebinding), token anti-CSRF sui POST, CSP restrittiva ed escape di ogni valore mostrato.
"""

from __future__ import annotations

import hmac
import html
import ipaddress
import json
import secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlsplit

from .db import STATUS_APPROVED, STATUS_UNKNOWN, Database
from .models import KIND_UNKNOWN_DEVICE, Alert

MAX_BODY = 4096
REFRESH_SECONDS = 60

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#16191d;--muted:#5d6672;--line:#e1e5ea;--accent:#1f5eff;
--bad:#b42318;--bad-bg:#fee4e2;--ok:#067647;--ok-bg:#d1fadf;--warn:#93370d;--warn-bg:#fef0c7;--info-bg:#e8eef9}
@media(prefers-color-scheme:dark){:root{--bg:#0f1216;--card:#171b21;--ink:#e8ebef;--muted:#9aa4b0;--line:#2a313a;
--accent:#6b9bff;--bad:#ffb4ab;--bad-bg:#4a1d1a;--ok:#75e0a7;--ok-bg:#12372a;--warn:#fdb022;--warn-bg:#3d2a0b;--info-bg:#1d2736}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
header{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:baseline;justify-content:space-between;margin-bottom:20px}
h1{font-size:22px;margin:0}h2{font-size:16px;margin:0 0 12px}
.sub{color:var(--muted);font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.tile,.card{background:var(--card);border:1px solid var(--line);border-radius:10px}
.tile{padding:14px 16px}.tile b{display:block;font-size:28px;line-height:1.1}.tile span{color:var(--muted);font-size:13px}
.tile.alert b{color:var(--bad)}
.card{padding:16px;margin-bottom:24px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;padding:6px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:10px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}
tr.unknown td:first-child{box-shadow:inset 3px 0 0 var(--bad)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--muted)}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.b-unknown,.b-critical{background:var(--bad-bg);color:var(--bad)}.b-approved{background:var(--ok-bg);color:var(--ok)}
.b-warning{background:var(--warn-bg);color:var(--warn)}.b-info{background:var(--info-bg);color:var(--muted)}
.chip{display:inline-block;white-space:nowrap;background:var(--info-bg);border-radius:4px;padding:0 6px;margin:0 4px 2px 0;font-size:12px}
.muted{color:var(--muted)}
.alert-row{display:flex;flex-wrap:wrap;gap:8px 12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--line)}
.alert-row:last-child{border-bottom:0}.alert-row .msg{flex:1 1 320px;min-width:0;overflow-wrap:anywhere}
form{display:inline-flex;gap:6px;align-items:center;margin:0}
input[type=text]{font:inherit;padding:4px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);width:150px}
button{font:inherit;font-size:13px;padding:4px 12px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:var(--ink);cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button:hover{filter:brightness(.95)}button:focus-visible,input:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
a{color:var(--accent)}
.empty{color:var(--muted);padding:8px 0}
"""


def _ago(ts: str, now: Optional[datetime] = None) -> str:
    try:
        then = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return ts
    secs = int(((now or datetime.now(timezone.utc)) - then).total_seconds())
    if secs < 60:
        return "adesso"
    if secs < 3600:
        return f"{secs // 60} min fa"
    if secs < 86400:
        return f"{secs // 3600} h fa"
    return f"{secs // 86400} g fa"


def _e(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render_page(db: Database, csrf: str, now: Optional[datetime] = None) -> str:
    devices = sorted(db.list_devices(), key=lambda r: r["last_seen"], reverse=True)
    devices.sort(key=lambda r: r["status"] != STATUS_UNKNOWN)  # ordinamento stabile: gli sconosciuti per primi
    alerts = db.list_alerts()
    unknown_macs = {r["mac"] for r in devices if r["status"] == STATUS_UNKNOWN}
    n_unknown = len(unknown_macs)
    hidden = f'<input type="hidden" name="csrf" value="{_e(csrf)}">'

    def tile(value: int, label: str, cls: str = "") -> str:
        return f'<div class="tile {cls}"><b>{value}</b><span>{_e(label)}</span></div>'

    rows = []
    for r in devices:
        unknown = r["status"] == STATUS_UNKNOWN
        name = r["label"] or r["hostname"] or r["snmp_name"]
        vendor = r["vendor"] or ("MAC privato/randomizzato" if r["randomized"] else "—")
        services = "".join(f'<span class="chip">{_e(s.lstrip("_").split(".")[0])}</span>' for s in json.loads(r["services"]))
        action = (
            f'<form method="post" action="/approve">{hidden}<input type="hidden" name="mac" value="{_e(r["mac"])}">'
            f'<input type="text" name="label" maxlength="60" placeholder="Etichetta" aria-label="Etichetta per {_e(r["mac"])}">'
            f'<button class="primary">Approva</button></form>' if unknown else ""
        )
        rows.append(
            f'<tr class="{"unknown" if unknown else ""}">'
            f'<td><span class="badge b-{"unknown" if unknown else "approved"}">{"Sconosciuto" if unknown else "Approvato"}</span></td>'
            f'<td>{"<b>" + _e(name) + "</b><br>" if name else ""}<span class="mono">{_e(r["mac"])}</span></td>'
            f'<td class="mono">{_e(r["ip"] or "—")}</td><td>{_e(vendor)}</td>'
            f'<td>{services or "<span class=muted>—</span>"}</td>'
            f'<td class="muted" title="{_e(r["last_seen"])}">{_e(_ago(r["last_seen"], now))}</td><td>{action}</td></tr>'
        )

    alert_rows = []
    for a in alerts:
        approve = ""
        if a.kind == KIND_UNKNOWN_DEVICE and a.mac in unknown_macs:
            approve = (f'<form method="post" action="/approve">{hidden}<input type="hidden" name="mac" value="{_e(a.mac)}">'
                       f'<button class="primary">Approva device</button></form>')
        alert_rows.append(
            f'<div class="alert-row"><span class="badge b-{_e(a.severity)}">{_e(a.severity)}</span>'
            f'<span class="msg">{_e(a.message)}<br><span class="muted" title="{_e(a.ts)}">{_e(_ago(a.ts, now))}</span></span>'
            f'{approve}<form method="post" action="/ack">{hidden}<input type="hidden" name="id" value="{a.id}">'
            f'<button>Segna letto</button></form></div>'
        )
    ack_all = (f'<form method="post" action="/ack">{hidden}<input type="hidden" name="all" value="1"><button>Segna tutti come letti</button></form>'
               if len(alerts) > 1 else "")

    table = ('<div class="scroll"><table><thead><tr><th>Stato</th><th>Device</th><th>IP</th><th>Produttore</th>'
             f'<th>Servizi</th><th>Ultima vista</th><th></th></tr></thead><tbody>{"".join(rows)}</tbody></table></div>'
             if rows else '<p class="empty">Nessun device in inventario. Esegui <code>lan-safety scan</code>.</p>')
    return f"""<!doctype html>
<html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="{REFRESH_SECONDS}"><title>LAN Safety</title><style>{CSS}</style></head>
<body><main>
<header><h1>LAN Safety</h1><span class="sub">Inventario della rete · aggiornamento automatico ogni {REFRESH_SECONDS}s · <a href="/">Aggiorna ora</a></span></header>
<section class="tiles" aria-label="Riepilogo">
{tile(len(devices), "device in inventario")}{tile(n_unknown, "sconosciuti", "alert" if n_unknown else "")}
{tile(len(devices) - n_unknown, "approvati")}{tile(len(alerts), "alert da leggere", "alert" if alerts else "")}
</section>
<section class="card" aria-labelledby="h-alerts"><div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
<h2 id="h-alerts">Alert da leggere</h2>{ack_all}</div>
{"".join(alert_rows) or '<p class="empty">Nessun alert. Tutto tranquillo.</p>'}</section>
<section class="card" aria-labelledby="h-dev"><h2 id="h-dev">Device</h2>{table}</section>
</main></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server: "UiServer"
    server_version = "lan-safety"

    def log_message(self, fmt, *args):  # niente log di accesso rumorosi
        pass

    # --- sicurezza -------------------------------------------------------
    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        return host in self.server.allowed_hosts

    def _send(self, code: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra: Optional[Dict[str, str]] = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code: int, msg: str) -> None:
        self._send(code, msg.encode(), "text/plain; charset=utf-8")

    # --- GET -------------------------------------------------------------
    def do_GET(self) -> None:
        if not self._host_ok():
            return self._text(403, "Host non consentito")
        path = urlsplit(self.path).path
        db = Database(self.server.db_path)
        try:
            if path == "/":
                return self._send(200, render_page(db, self.server.csrf).encode())
            if path == "/api/devices":
                data = [{**dict(r), "services": json.loads(r["services"])} for r in db.list_devices()]
                return self._send(200, json.dumps(data, ensure_ascii=False).encode(), "application/json")
            if path == "/api/alerts":
                return self._send(200, json.dumps([a.__dict__ for a in db.list_alerts()], ensure_ascii=False).encode(), "application/json")
        finally:
            db.close()
        self._text(404, "Non trovato")

    # --- POST ------------------------------------------------------------
    def do_POST(self) -> None:
        if not self._host_ok():
            return self._text(403, "Host non consentito")
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc.lower() not in self.server.allowed_hosts:
            return self._text(403, "Origin non consentita")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._text(400, "Richiesta non valida")
        if not 0 <= length <= MAX_BODY:
            return self._text(413, "Richiesta troppo grande")
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode("utf-8", "replace")).items()}
        if not hmac.compare_digest(form.get("csrf", ""), self.server.csrf):
            return self._text(403, "Token CSRF non valido: ricarica la pagina")
        path = urlsplit(self.path).path
        db = Database(self.server.db_path)
        try:
            if path == "/approve":
                if db.approve(form.get("mac", ""), (form.get("label") or "").strip()[:60] or None) == 0:
                    return self._text(404, "Device non trovato")
            elif path == "/ack":
                if form.get("all"):
                    db.ack_alerts(None)
                else:
                    db.ack_alerts([int(form.get("id", ""))])
            else:
                return self._text(404, "Non trovato")
        except ValueError:
            return self._text(400, "Parametri non validi")
        finally:
            db.close()
        self._send(303, b"", extra={"Location": "/"})


class UiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, db_path: str, host: str, port: int):
        super().__init__((host, port), Handler)
        self.db_path = db_path
        self.csrf = secrets.token_urlsafe(32)
        bound = self.server_address[1]
        names = {"localhost", "127.0.0.1", "[::1]", host.lower()}
        self.allowed_hosts = {f"{n}:{bound}" for n in names} | ({"localhost", "127.0.0.1"} if bound == 80 else set())


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def make_server(db_path: str, host: str = "127.0.0.1", port: int = 8080, allow_remote: bool = False) -> UiServer:
    if not is_loopback(host) and not allow_remote:
        raise ValueError(
            f"{host} non è un indirizzo locale: la dashboard non ha autenticazione né HTTPS. "
            "Se sei sicuro, aggiungi --allow-remote"
        )
    Database(db_path).close()  # crea/migra il DB prima di accettare richieste
    return UiServer(db_path, host, port)
