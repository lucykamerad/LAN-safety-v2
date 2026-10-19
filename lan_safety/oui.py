"""Risoluzione MAC -> produttore (OUI).

Il database completo IEEE non è incluso nel repository: si scarica con
``lan-safety update-oui`` (o si importa da file con ``--from-file``) e viene
salvato in ``oui_path()``. In assenza di quel file si usa un piccolo elenco
base (``data/oui_seed.csv``) con i produttori più comuni.
"""

from __future__ import annotations

import csv
import io
import os
import re
import urllib.request
from pathlib import Path
from typing import Dict, Optional

IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.csv"
SEED_PATH = Path(__file__).parent / "data" / "oui_seed.csv"

_HEX12 = re.compile(r"^[0-9a-f]{12}$")


def data_dir() -> Path:
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return Path(base) / "lan-safety"


def oui_path() -> Path:
    return Path(os.environ.get("LAN_SAFETY_OUI") or data_dir() / "oui.csv")


def normalize_mac(mac: str) -> str:
    """Restituisce il MAC come ``aa:bb:cc:dd:ee:ff`` oppure solleva ValueError."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if not _HEX12.match(digits):
        raise ValueError(f"MAC non valido: {mac!r}")
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def is_randomized(mac: str) -> bool:
    """True se il bit "locally administered" è impostato (MAC privato/randomizzato)."""
    return bool(int(normalize_mac(mac)[:2], 16) & 0x02)


def _prefix(mac: str) -> str:
    return normalize_mac(mac)[:8].replace(":", "").upper()


def parse_ieee_csv(text: str) -> Dict[str, str]:
    """Formato IEEE: ``Registry,Assignment,Organization Name,Organization Address``."""
    table: Dict[str, str] = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 3 or not re.fullmatch(r"[0-9A-Fa-f]{6}", row[1].strip()):
            continue
        table[row[1].strip().upper()] = row[2].strip()
    return table


def parse_manuf(text: str) -> Dict[str, str]:
    """Formato Wireshark ``manuf``: ``00:00:0C<TAB>Cisco<TAB>Cisco Systems``. Solo prefissi a 24 bit."""
    table: Dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 2 or not re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){2}[0-9A-Fa-f]{2}", parts[0].strip()):
            continue
        table[parts[0].strip().replace(":", "").upper()] = (parts[2] if len(parts) > 2 and parts[2].strip() else parts[1]).strip()
    return table


def parse_oui_text(text: str) -> Dict[str, str]:
    """Riconosce da sé il formato (CSV IEEE, manuf Wireshark o ``PREFISSO,Vendor``)."""
    table = parse_ieee_csv(text)
    if not table:
        table = parse_manuf(text)
    if not table:  # formato interno: PREFISSO,Vendor
        for row in csv.reader(io.StringIO(text)):
            if len(row) >= 2 and re.fullmatch(r"[0-9A-Fa-f]{6}", row[0].strip()):
                table[row[0].strip().upper()] = row[1].strip()
    return table


def save_table(table: Dict[str, str], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        for prefix in sorted(table):
            writer.writerow([prefix, table[prefix]])
    os.replace(tmp, path)


def download_ieee(url: str = IEEE_OUI_URL, timeout: float = 60.0) -> Dict[str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": "lan-safety"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL fissato/scelto dall'utente
        table = parse_ieee_csv(resp.read().decode("utf-8", "replace"))
    if not table:
        raise ValueError("il file scaricato non contiene voci OUI")
    return table


class OuiDatabase:
    def __init__(self, table: Dict[str, str]):
        self._table = table

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "OuiDatabase":
        table: Dict[str, str] = {}
        for source in (SEED_PATH, path or oui_path()):
            try:
                table.update(parse_oui_text(Path(source).read_text(encoding="utf-8", errors="replace")))
            except OSError:
                continue
        return cls(table)

    def __len__(self) -> int:
        return len(self._table)

    def lookup(self, mac: str) -> Optional[str]:
        return self._table.get(_prefix(mac))
