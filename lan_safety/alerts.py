"""Canali di notifica: console, webhook HTTP(S), e-mail SMTP."""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import sys
import urllib.request
from email.message import EmailMessage
from typing import List, Optional, Sequence, TextIO
from urllib.parse import urlparse

from .db import Database
from .models import SEVERITY_CRITICAL, SEVERITY_WARNING, Alert

log = logging.getLogger("lan_safety")

# Gravità inoltrata ai canali esterni; "info" (es. cambio IP) resta solo nel database.
FORWARDED_SEVERITIES = (SEVERITY_WARNING, SEVERITY_CRITICAL)


class Notifier:
    name = "notifier"

    def send(self, alert: Alert) -> None:
        raise NotImplementedError


class WebhookNotifier(Notifier):
    """POST JSON. Il campo ``text`` è compatibile con Slack/Mattermost/Rocket.Chat."""

    def __init__(self, url: str, timeout: float = 10.0):
        if urlparse(url).scheme not in ("http", "https"):
            raise ValueError("il webhook deve essere un URL http:// o https://")
        self.url, self.timeout, self.name = url, timeout, "webhook"

    def send(self, alert: Alert) -> None:
        body = json.dumps({
            "text": f"[LAN-safety] {alert.message}",
            "id": alert.id, "timestamp": alert.ts, "kind": alert.kind, "severity": alert.severity,
            "mac": alert.mac, "ip": alert.ip, "message": alert.message, "details": alert.details,
        }).encode()
        req = urllib.request.Request(self.url, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 - schema validato in __init__
            resp.read()


class EmailNotifier(Notifier):
    def __init__(self, host: str, port: int, sender: str, recipients: Sequence[str],
                 username: Optional[str] = None, password: Optional[str] = None,
                 starttls: bool = False, ssl_: bool = False, timeout: float = 15.0):
        self.host, self.port, self.sender, self.recipients = host, port, sender, list(recipients)
        self.username, self.password = username, password
        self.starttls, self.ssl, self.timeout, self.name = starttls, ssl_, timeout, "email"

    def send(self, alert: Alert) -> None:
        msg = EmailMessage()
        msg["Subject"] = f"[LAN-safety] {alert.kind}: {alert.mac}"
        msg["From"], msg["To"] = self.sender, ", ".join(self.recipients)
        msg.set_content(f"{alert.message}\n\nQuando: {alert.ts} (UTC)\nGravità: {alert.severity}\n"
                        f"Dettagli: {json.dumps(alert.details, ensure_ascii=False)}\n")
        ctx = ssl.create_default_context()
        smtp = (smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx) if self.ssl
                else smtplib.SMTP(self.host, self.port, timeout=self.timeout))
        with smtp:
            if self.starttls:
                smtp.starttls(context=ctx)
            if self.username:
                smtp.login(self.username, self.password or "")
            smtp.send_message(msg)


def print_alert(alert: Alert, stream: Optional[TextIO] = None) -> None:
    stream = stream or sys.stdout
    print(f"[{alert.ts}] {alert.severity.upper():8} {alert.message}", file=stream, flush=True)


def deliver(db: Database, notifiers: Sequence[Notifier]) -> List[Alert]:
    """Invia agli esterni gli alert in coda. Quelli falliti restano in coda e si riprovano alla scansione dopo."""
    db.mark_all_notified_except(FORWARDED_SEVERITIES)
    pending = db.pending_notifications(FORWARDED_SEVERITIES)
    if not notifiers:
        db.mark_notified(a.id for a in pending)
        return []
    delivered: List[Alert] = []
    for alert in pending:
        ok = True
        for notifier in notifiers:
            try:
                notifier.send(alert)
            except Exception as exc:  # un canale rotto non deve fermare il monitoraggio
                ok = False
                log.warning("invio alert #%s via %s fallito: %s", alert.id, notifier.name, exc)
        if ok:
            db.mark_notified([alert.id])
            delivered.append(alert)
    return delivered
