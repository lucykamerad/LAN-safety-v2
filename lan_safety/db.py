"""Archivio SQLite: inventario dei device e registro degli alert."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from .models import (
    KIND_IP_CHANGED,
    KIND_UNKNOWN_DEVICE,
    SEVERITY_CRITICAL,
    SEVERITY_INFO,
    Alert,
    Observation,
)
from .oui import normalize_mac

STATUS_UNKNOWN = "unknown"
STATUS_APPROVED = "approved"

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE devices (
    mac            TEXT PRIMARY KEY,
    ip             TEXT,
    vendor         TEXT,
    randomized     INTEGER NOT NULL DEFAULT 0,
    hostname       TEXT,
    services       TEXT NOT NULL DEFAULT '[]',
    snmp_name      TEXT,
    snmp_descr     TEXT,
    snmp_object_id TEXT,
    snmp_location  TEXT,
    label          TEXT,
    status         TEXT NOT NULL CHECK (status IN ('unknown', 'approved')),
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL
);
CREATE INDEX devices_status ON devices(status);

CREATE TABLE alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    kind      TEXT NOT NULL,
    severity  TEXT NOT NULL,
    mac       TEXT NOT NULL,
    ip        TEXT,
    message   TEXT NOT NULL,
    details   TEXT NOT NULL DEFAULT '{}',
    acked     INTEGER NOT NULL DEFAULT 0,
    notified  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX alerts_pending ON alerts(acked, notified);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _describe(obs: Observation) -> str:
    parts = [f"MAC {obs.mac}", f"IP {obs.ip}"]
    if obs.vendor:
        parts.append(f"produttore {obs.vendor}")
    elif obs.randomized:
        parts.append("MAC randomizzato/privato")
    name = obs.hostname or obs.snmp_name
    if name:
        parts.append(f"nome {name}")
    return ", ".join(parts)


class Database:
    def __init__(self, path: str):
        if path != ":memory:":
            p = Path(path).expanduser()
            p.parent.mkdir(parents=True, exist_ok=True)
            if not p.exists():  # l'inventario della rete è un dato sensibile: solo il proprietario lo legge
                os.close(os.open(p, os.O_CREAT | os.O_WRONLY, 0o600))
            path = str(p)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._migrate()

    def close(self) -> None:
        self.conn.close()

    def _migrate(self) -> None:
        version = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(f"database creato da una versione più recente (schema {version})")
        if version == 0:
            with self.conn:
                self.conn.executescript(SCHEMA)
                self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    # --- device -----------------------------------------------------------

    def device_count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    def get_device(self, mac: str) -> Optional[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM devices WHERE mac = ?", (normalize_mac(mac),)).fetchone()

    def list_devices(self, status: Optional[str] = None) -> List[sqlite3.Row]:
        sql, args = "SELECT * FROM devices", ()
        if status:
            sql, args = sql + " WHERE status = ?", (status,)
        return self.conn.execute(sql + " ORDER BY last_seen DESC, mac", args).fetchall()

    def approve(self, mac: Optional[str] = None, label: Optional[str] = None) -> int:
        """Approva un device (o tutti quelli sconosciuti se ``mac`` è None). Restituisce quanti ne ha toccati."""
        with self.conn:
            if mac is None:
                cur = self.conn.execute("UPDATE devices SET status = ? WHERE status = ?", (STATUS_APPROVED, STATUS_UNKNOWN))
                self.conn.execute("UPDATE alerts SET acked = 1 WHERE kind = ?", (KIND_UNKNOWN_DEVICE,))
            else:
                mac = normalize_mac(mac)
                cur = self.conn.execute(
                    "UPDATE devices SET status = ?, label = COALESCE(?, label) WHERE mac = ?",
                    (STATUS_APPROVED, label, mac),
                )
                # l'alert "sconosciuto" di un device ormai approvato non è più da gestire
                self.conn.execute("UPDATE alerts SET acked = 1 WHERE mac = ? AND kind = ?", (mac, KIND_UNKNOWN_DEVICE))
        return cur.rowcount

    def remove(self, mac: str) -> int:
        with self.conn:
            return self.conn.execute("DELETE FROM devices WHERE mac = ?", (normalize_mac(mac),)).rowcount

    def record_observation(self, obs: Observation, *, learning: bool = False, now: Optional[str] = None) -> List[Alert]:
        """Registra un device visto. Genera alert se è nuovo (e non siamo in apprendimento) o ha cambiato IP."""
        now = now or utcnow()
        alerts: List[Alert] = []
        with self.conn:
            row = self.get_device(obs.mac)
            if row is None:
                self.conn.execute(
                    """INSERT INTO devices (mac, ip, vendor, randomized, hostname, services, snmp_name,
                           snmp_descr, snmp_object_id, snmp_location, status, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (obs.mac, obs.ip, obs.vendor, int(obs.randomized), obs.hostname,
                     json.dumps(sorted(obs.services)), obs.snmp_name, obs.snmp_descr, obs.snmp_object_id,
                     obs.snmp_location, STATUS_APPROVED if learning else STATUS_UNKNOWN, now, now),
                )
                if not learning:
                    alerts.append(self._add_alert(
                        now, KIND_UNKNOWN_DEVICE, SEVERITY_CRITICAL, obs,
                        f"Device sconosciuto in LAN: {_describe(obs)}",
                    ))
                return alerts

            if row["ip"] and row["ip"] != obs.ip:
                alerts.append(self._add_alert(
                    now, KIND_IP_CHANGED, SEVERITY_INFO, obs,
                    f"Il device {obs.mac} ha cambiato IP: {row['ip']} -> {obs.ip}",
                    {"old_ip": row["ip"], "new_ip": obs.ip},
                ))
            # i dati di arricchimento mancanti in questa scansione non cancellano quelli già noti
            self.conn.execute(
                """UPDATE devices SET ip = ?, last_seen = ?,
                       vendor = COALESCE(?, vendor), randomized = ?,
                       hostname = COALESCE(?, hostname),
                       services = CASE WHEN ? = '[]' THEN services ELSE ? END,
                       snmp_name = COALESCE(?, snmp_name), snmp_descr = COALESCE(?, snmp_descr),
                       snmp_object_id = COALESCE(?, snmp_object_id), snmp_location = COALESCE(?, snmp_location)
                   WHERE mac = ?""",
                (obs.ip, now, obs.vendor, int(obs.randomized), obs.hostname,
                 json.dumps(sorted(obs.services)), json.dumps(sorted(obs.services)),
                 obs.snmp_name, obs.snmp_descr, obs.snmp_object_id, obs.snmp_location, obs.mac),
            )
        return alerts

    # --- alert ------------------------------------------------------------

    def _add_alert(self, ts: str, kind: str, severity: str, obs: Observation, message: str, extra: Optional[dict] = None) -> Alert:
        details = {
            "vendor": obs.vendor, "randomized_mac": obs.randomized, "hostname": obs.hostname,
            "services": sorted(obs.services), "snmp_name": obs.snmp_name, "snmp_descr": obs.snmp_descr,
        }
        details.update(extra or {})
        cur = self.conn.execute(
            "INSERT INTO alerts (ts, kind, severity, mac, ip, message, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, kind, severity, obs.mac, obs.ip, message, json.dumps(details)),
        )
        return Alert(cur.lastrowid, ts, kind, severity, obs.mac, obs.ip, message, details)

    @staticmethod
    def _to_alert(row: sqlite3.Row) -> Alert:
        return Alert(row["id"], row["ts"], row["kind"], row["severity"], row["mac"], row["ip"],
                     row["message"], json.loads(row["details"]))

    def list_alerts(self, include_acked: bool = False) -> List[Alert]:
        sql = "SELECT * FROM alerts" + ("" if include_acked else " WHERE acked = 0") + " ORDER BY id"
        return [self._to_alert(r) for r in self.conn.execute(sql)]

    def ack_alerts(self, ids: Optional[Sequence[int]] = None) -> int:
        """Segna come letti gli alert indicati (o tutti se ``ids`` è None)."""
        with self.conn:
            if ids is None:
                return self.conn.execute("UPDATE alerts SET acked = 1 WHERE acked = 0").rowcount
            return sum(self.conn.execute("UPDATE alerts SET acked = 1 WHERE id = ?", (i,)).rowcount for i in ids)

    def pending_notifications(self, severities: Iterable[str]) -> List[Alert]:
        """Alert con gravità rilevante non ancora consegnati ai canali esterni."""
        severities = list(severities)
        marks = ",".join("?" * len(severities))
        rows = self.conn.execute(
            f"SELECT * FROM alerts WHERE notified = 0 AND severity IN ({marks}) ORDER BY id", severities
        ).fetchall()
        return [self._to_alert(r) for r in rows]

    def mark_notified(self, ids: Iterable[int]) -> None:
        with self.conn:
            self.conn.executemany("UPDATE alerts SET notified = 1 WHERE id = ?", [(i,) for i in ids])

    def mark_all_notified_except(self, severities: Iterable[str]) -> None:
        """Gli alert di gravità non inoltrata (info) non devono restare in coda per sempre."""
        severities = list(severities)
        marks = ",".join("?" * len(severities))
        with self.conn:
            self.conn.execute(f"UPDATE alerts SET notified = 1 WHERE severity NOT IN ({marks})", severities)
