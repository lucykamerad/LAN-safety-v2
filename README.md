# LAN-safety

Inventario della rete locale con rilevamento di **device sconosciuti**.

Ogni scansione combina quattro fonti, salva tutto in **SQLite** e genera un alert
`Device sconosciuto in LAN` quando compare un MAC mai visto prima.

| Fonte | Cosa fornisce |
|-------|---------------|
| **ARP** | MAC e IP di tutti i device attivi nella subnet |
| **mDNS / DNS-SD** | nome host e servizi annunciati (stampanti, Chromecast, Apple, NAS…) |
| **SNMP v2c** | `sysName`, `sysDescr`, `sysObjectID`, `sysLocation` (router, switch, AP, stampanti) |
| **MAC vendor (OUI)** | produttore dal prefisso del MAC; riconosce i MAC privati/randomizzati |

Solo libreria standard di Python (≥ 3.9), **nessuna dipendenza** e **nessun bisogno di root**:
la scoperta ARP fa risolvere gli indirizzi al kernel e legge `/proc/net/arp`, quindi funziona solo su Linux.

## Uso rapido

```bash
pip install -e .            # oppure: python -m lan_safety ...

lan-safety update-oui       # (consigliato) scarica l'elenco completo dei produttori IEEE
lan-safety scan             # primo avvio: impara i device presenti come baseline fidata
lan-safety watch --interval 300 --webhook https://hooks.example/xyz
```

Al **primo avvio** (database vuoto) tutti i device trovati vengono approvati automaticamente
(`--strict` lo disattiva). Da lì in poi ogni MAC nuovo è `SCONOSCIUTO` e genera un alert:

```
Scansione 192.168.1.0/24: 14 device attivi, 1 nuovi sconosciuti.
[2026-10-13T09:12:44Z] CRITICAL Device sconosciuto in LAN: MAC aa:bb:cc:99:99:99, IP 192.168.1.99, produttore Espressif Inc., nome esp-sensor
```

> ⚠️ Esegui il primo `scan` quando sei sicuro che in rete ci siano solo device tuoi: ciò che c'è in quel momento diventa fidato.

## Comandi

| Comando | Descrizione |
|---------|-------------|
| `scan` | una scansione. `--fail-on-unknown` esce con codice 2 se compaiono sconosciuti (cron/script) |
| `watch --interval S` | scansiona a ciclo continuo |
| `devices [--status unknown\|approved] [--json]` | inventario |
| `approve MAC [--label "stampante"]` / `approve --all` | segna come noto |
| `remove MAC` | toglie dall'inventario (se riappare sarà di nuovo "nuovo") |
| `alerts [--all] [--json]` / `ack ID… \| --all` | consulta e archivia gli alert |
| `ui [--port 8080]` | dashboard web locale (vedi sotto) |
| `update-oui [--from-file F]` | scarica da IEEE, o importa un CSV IEEE / file `manuf` di Wireshark |

Opzioni di scansione: `--network 192.168.1.0/24`, `--iface eth0` (default: route di default),
`--no-mdns`, `--mdns-timeout`, `--no-snmp`, `--snmp-community NOME` (ripetibile, default `public`).

Database: `~/.local/share/lan-safety/lan-safety.db` (o `--db` / `$LAN_SAFETY_DB`), creato con permessi `600`.
Un MAC con più IP (alias del router, proxy-ARP) viene registrato con l'IP più basso, per evitare falsi "cambio IP".

## Dashboard web

```bash
lan-safety ui            # http://127.0.0.1:8080/
```

Mostra riepilogo, alert da leggere e inventario (sconosciuti in cima), con i pulsanti **Approva** (con etichetta
opzionale) e **Segna letto**. Si aggiorna ogni 60 s; `/api/devices` e `/api/alerts` restituiscono JSON.
La dashboard legge lo stesso database di `scan`/`watch`: tienili in esecuzione a parte (`watch` + `ui`).

Sicurezza: ascolta solo su `127.0.0.1` (altri indirizzi richiedono `--allow-remote`, ma **non ha autenticazione né HTTPS**:
mettila dietro un reverse proxy o una VPN). Controlla l'header `Host` (anti DNS-rebinding), protegge i POST con token
CSRF e `Origin`, usa una CSP restrittiva e fa l'escape di ogni valore mostrato.

## Notifiche

Gli alert sono sempre stampati a console e salvati nel DB. In più (per gravità `critical`/`warning`):

* **Webhook**: `--webhook URL` (POST JSON; il campo `text` è compatibile con Slack/Mattermost/Rocket.Chat)
* **E-mail**: `--smtp-host H [--smtp-starttls|--smtp-ssl] --smtp-user U --mail-from A --mail-to B`,
  password in `$LAN_SAFETY_SMTP_PASSWORD`

Se un invio fallisce l'alert resta in coda e viene riprovato alla scansione successiva
(consegna *at-least-once*). I cambi di IP di un device noto (`ip_changed`, gravità `info`) sono solo registrati.

## Schema SQLite

* `devices(mac PK, ip, vendor, randomized, hostname, services, snmp_*, label, status, first_seen, last_seen)` — `status` = `unknown` | `approved`
* `alerts(id, ts, kind, severity, mac, ip, message, details, acked, notified)`

Date in UTC. Esempio: `sqlite3 lan-safety.db "SELECT mac, ip, vendor FROM devices WHERE status='unknown'"`

## Limiti noti

* **MAC randomizzati**: telefoni e PC moderni usano un MAC diverso per ogni rete (e a volte lo ruotano):
  vengono segnalati come sconosciuti ad ogni nuovo MAC. Sono marcati "MAC privato" nell'alert; per i
  device fidati disattiva l'indirizzo privato sul device per quella rete.
* **Testo dalla rete**: nomi host mDNS e stringhe SNMP provengono da device non fidati; vengono ripuliti da
  caratteri di controllo e troncati prima di finire in console, database o notifiche.
* **ARP è locale**: vede solo la propria subnet L2 (una per volta, max 4096 host), non VLAN diverse.
  Un attaccante può falsificare il MAC di un device noto: questo strumento rileva device *nuovi*, non impersonificazioni.
* **Device spenti o in sleep** possono non rispondere ad ARP durante la scansione; riappariranno alla successiva
  senza alert (sono già in inventario).
* **mDNS** usa il multicast: serve che la macchina sia sulla stessa LAN (non funziona dentro container con rete isolata).
* **SNMP**: solo v2c con community in chiaro; se non ne indichi, prova `public`.
* **OUI**: senza `update-oui` è incluso solo un piccolo elenco dei produttori più comuni
  (il database IEEE completo non è nel repository).

## Sviluppo

```bash
python -m unittest discover        # dalla radice del repo; nessuna rete necessaria
```

Moduli in `lan_safety/`: `arp`, `mdns`, `snmp`, `oui`, `db`, `scanner`, `alerts`, `web`, `cli`, `netinfo`.
