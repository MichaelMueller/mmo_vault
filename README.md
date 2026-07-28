# MMO Vault

**Lokaler Passwortmanager als eine einzige HTML-Datei.** Keine Server, keine Installation, keine Abhängigkeiten — der Vault ist eine verschlüsselte Datei, die dir gehört und die du selbst ablegst.

> **Version 1.2.0** · Funktional vollständig. Alle automatisiert prüfbaren Abnahmekriterien sind verifiziert — Kryptografie gegen die RFC-Testvektoren, Speicher-Roundtrip mit Rollback, Sperrverhalten, Container-Auslieferung und Layout von 320 px bis Desktop.
>
> **Sechs Prüfungen erfordern Handarbeit und stehen aus:** Ablauf der Auto-Sperre, Sichtprüfung der Übersetzungen auf Umbrüche, Bedienung allein mit Tastatur, Funktionsprüfung in Firefox und Safari, Ersatzverhalten ohne File System Access API und ohne `BarcodeDetector`, sowie die Prüfung mit dem Reverse Proxy der Zielumgebung. Der jeweils aktuelle Stand steht in [docs/requirements.md](docs/requirements.md#9-abnahmekriterien) als Kästchenliste.

---

## Loslegen

1. [mmo_vault/public_html/mmo_vault.html](mmo_vault/public_html/mmo_vault.html) herunterladen.
2. Datei im Browser öffnen (Doppelklick genügt — kein Webserver nötig).
3. **Neue Datei anlegen**, Master-Passwort vergeben, Einträge erfassen, **Speichern**.

Beim ersten Speichern fragt der Browser nach einem Speicherort. Ab dann schreibt die Anwendung direkt in diese Datei. Browser ohne File System Access API laden stattdessen jedes Mal eine Datei herunter.

---

## Ausliefern per Docker

```bash
docker compose up -d --build     # → http://127.0.0.1:4080/
```

Oder ohne Compose:

```bash
docker build -t mmo-vault:1.2.0 .
docker run -d --name mmo-vault --restart unless-stopped \
  -p 127.0.0.1:4080:8080 \
  --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true \
  mmo-vault:1.2.0
```

Port und Bind-Adresse lassen sich ohne Änderung der compose.yaml setzen:

```bash
VAULT_PORT=4080 VAULT_BIND=127.0.0.1 docker compose up -d
```

### Auf einem Server installieren

Es gibt keinen Build-Schritt und keine Registry-Abhängigkeit — vier Dateien reichen:

```bash
# Auf dem Server
mkdir -p /opt/mmo-vault && cd /opt/mmo-vault

# Vom Arbeitsplatz aus übertragen (Build-Kontext, ~140 KB)
rsync -av --relative \
  ./Dockerfile ./compose.yaml ./docker/nginx.conf ./mmo_vault/public_html/ \
  server:/opt/mmo-vault/

# Auf dem Server bauen und starten
cd /opt/mmo-vault
docker compose up -d --build
```

Wer auf dem Server nicht bauen will, überträgt stattdessen das fertige Abbild:

```bash
docker save mmo-vault:1.2.0 | gzip | ssh server 'gunzip | docker load'
```

**Start nach dem Reboot** kommt aus `restart: unless-stopped` in der compose.yaml — das greift aber nur, wenn der Docker-Dienst selbst beim Booten startet:

```bash
sudo systemctl enable --now docker
systemctl is-enabled docker        # muss "enabled" sagen
```

Damit braucht es keine eigene systemd-Unit. `unless-stopped` heißt: nach einem Absturz oder Reboot kommt der Container von selbst zurück, nach einem bewussten `docker compose stop` bleibt er aus.

### Nur von innen erreichbar

Die Bindung an `127.0.0.1` in der compose.yaml ist die eigentliche Zugriffsbeschränkung — nicht die Firewall:

> **Docker umgeht ufw und firewalld.** Bei einer Freigabe wie `-p 4080:8080` (ohne Adresse) trägt Docker eigene iptables-Regeln **vor** die Ketten der Firewall ein. Der Port wäre dann aus dem Netz erreichbar, obwohl `ufw status` ihn als gesperrt anzeigt. Mit `127.0.0.1:4080:8080` entsteht die Regel gar nicht.

Prüfen lässt sich das am Listen-Socket — die Adresse muss `127.0.0.1` sein, nicht `0.0.0.0`:

```bash
ss -tlnp | grep 4080
# richtig: 127.0.0.1:4080     falsch: 0.0.0.0:4080 oder *:4080
curl -sI http://127.0.0.1:4080/ | head -1        # von innen: 200
curl -sI --max-time 3 http://<server-ip>:4080/   # von außen: keine Verbindung
```

Der Reverse Proxy auf demselben Host zeigt dann auf `http://127.0.0.1:4080`. Läuft er in einem eigenen Container, erreicht er die Host-Loopback-Adresse **nicht** — in dem Fall die `ports`-Freigabe ganz entfernen, beide Dienste in dasselbe Docker-Netz legen und den Proxy auf `http://mmo-vault:8080` zeigen lassen. Die nötigen Zeilen stehen kommentiert in der [compose.yaml](compose.yaml); ohne veröffentlichten Port ist der Dienst dann von außen strukturell nicht erreichbar.

Ausgeliefert wird [mmo_vault/public_html/](mmo_vault/public_html/); Index ist `mmo_vault.html`, konfiguriert in [docker/nginx.conf](docker/nginx.conf). Das Image enthält nginx und diese eine Datei — keinen Quellcode, keine Dokumentation, keinen Build-Schritt.

Der Container läuft als unprivilegierter Benutzer, lauscht intern auf 8080 (veröffentlicht als 4080), mit read-only Wurzeldateisystem, ohne Capabilities und mit `no-new-privileges`. Der Server setzt zusätzlich `frame-ancestors 'none'` als echten HTTP-Header — im `<meta>`-Tag der Anwendung wird diese Direktive vom Browser ignoriert.

### Hinter dem Reverse Proxy

Der Dienst ist als Backend gedacht: der Proxy terminiert TLS und leitet auf `mmo-vault:8080` weiter. Läuft der Proxy auf demselben Host, passt die Loopback-Freigabe aus [compose.yaml](compose.yaml). Läuft er in einem eigenen Container, die Freigabe entfernen und beide Dienste in dasselbe Docker-Netz legen — die nötigen Zeilen stehen kommentiert in der compose.yaml.

Zwei Dinge gehören auf den Proxy, nicht in dieses Image: **HSTS** (`Strict-Transport-Security`) und, falls die echten Client-IPs im Log stehen sollen, `X-Forwarded-For` — der passende `set_real_ip_from`-Block liegt kommentiert in [docker/nginx.conf](docker/nginx.conf). Alle übrigen Security-Header setzt nginx selbst und sie gehen unverändert durch den Proxy.

> **HTTPS ist Pflicht, nicht Komfort.** Browser stellen `crypto.subtle` **nur in einem Secure Context** bereit. Über `http://` auf einer LAN-IP oder Domain fehlt die Web-Crypto-API vollständig — der Vault ließe sich weder anlegen noch entsperren. `http://localhost` gilt als sicher, alles andere nicht.

Die Anwendung erkennt das beim Laden und zeigt statt eines kryptischen Fehlers einen klaren Hinweis, mit gesperrten Bedienelementen.

### Was das Ausliefern nicht ändert

Der Server sieht nur die Anwendungsdatei. Vault-Dateien liegen weiter ausschließlich beim Anwender: sie werden im Browser entschlüsselt und über den Datei-Dialog gespeichert — nie hochgeladen. Die CSP mit `connect-src 'none'` verhindert, dass die Seite überhaupt eine Verbindung zurück aufbauen kann.

---

## Was drin ist

- **AES-256-GCM**, Schlüssel per PBKDF2-HMAC-SHA256 mit 600.000 Iterationen (OWASP-Empfehlung), 16-Byte-Salt, eigener 96-Bit-IV je Block
- **Zwei Eintragstypen** — Zugang (URL, Benutzername, Passwort, 2FA, Notizen) und Freitext
- **2FA/TOTP** nach RFC 6238, inklusive 8-stelliger sowie SHA-256/SHA-512-Konten. QR-Codes lassen sich als Bild importieren, über die native `BarcodeDetector`-API
- **Dateianhänge** in eigenen verschlüsselten Blöcken — sie werden erst beim Herunterladen entschlüsselt, nicht schon beim Entsperren
- **Tags, Volltextsuche und Typfilter**
- **Passwortgenerator** ohne Modulo-Bias, ohne optisch verwechselbare Zeichen
- **Auto-Sperre** mit sichtbarem Countdown, Vorgabe 5 Minuten
- **Änderungsverlauf**, mitverschlüsselt, ohne Geheimnisse
- **Deutsch und Englisch**, jederzeit umschaltbar — auch alle Fehlermeldungen
- Bedienbar von 320 px bis Desktop

---

## Sicherheitseigenschaften

**Keine Netzwerkverbindung — technisch erzwungen.** Die Seite setzt `default-src 'none'; connect-src 'none'`. Kein CDN, keine Web Fonts, keine Telemetrie. Das ist nicht nur eine Zusage, sondern vom Browser durchgesetzt.

**Beim Sperren wird aufgeräumt.** Schlüssel, Einträge, Verlauf, Datei-Handle und TOTP-Cache werden verworfen, alle Dialoge geschlossen und ihre Felder geleert, aufgedeckte Passwörter aus dem DOM entfernt. Auch dann, wenn die Auto-Sperre bei geöffnetem Bearbeitungsdialog zuschlägt.

**Speichern ist überprüft.** Nach dem Schreiben wird die Datei zurückgelesen, verglichen und erneut geparst. Schlägt etwas fehl, wird der vorherige Inhalt wiederhergestellt und der Vault bleibt als ungespeichert markiert. Ein abgebrochener Speichern-Dialog löst keinen stillen Download aus.

**Kopierte Geheimnisse verfallen.** Passwörter und 2FA-Codes verschwinden nach 30 Sekunden aus der Zwischenablage. URL und Benutzername bleiben liegen, damit die Anwendung keine fremden Kopier-Inhalte überschreibt.

**Alte Dateien werden angehoben.** Wird ein Vault mit veralteter Iterationszahl geöffnet, hebt die Anwendung ihn direkt nach dem Entsperren auf den aktuellen Standard und markiert ihn zum Speichern.

Das vollständige Bedrohungsmodell — samt dem, wogegen die Anwendung ausdrücklich **nicht** schützt — steht in [docs/requirements.md](docs/requirements.md#35-bedrohungsmodell).

---

## Wichtig vorher zu wissen

> **Backups sind Pflicht, nicht optional.** Die Anwendung versioniert nichts. Der Rollback-Schutz greift bei abgebrochenen Schreibvorgängen — nicht bei gelöschten Dateien, Datenträgerdefekten oder Sync-Konflikten.

> **Es gibt keine Passwort-Wiederherstellung.** Kein Reset, keine Hintertür. Ist das Master-Passwort weg, sind die Daten weg.

> **Cloud-Sync-Ordner:** Nextcloud, OneDrive und Dropbox tauschen Dateien intern aus, wodurch gespeicherte Datei-Verknüpfungen ins Leere zeigen können. Die Anwendung erkennt das und räumt die Verknüpfung auf. Paralleles Bearbeiten auf mehreren Geräten wird nicht unterstützt.

> **Ohne Gewähr.** Ein selbstgebautes Werkzeug für Eigenprojekte, keine geprüfte Sicherheitssoftware.

---

## Browser-Unterstützung

| Funktion | Chrome / Edge | Firefox | Safari |
|---|---|---|---|
| Ver- und Entschlüsselung, TOTP | ✅ | ✅ | ✅ |
| Direkt in Datei speichern (FSA) | ✅ | Download-Ersatz | Download-Ersatz |
| Letzte Datei merken | ✅ | — | — |
| QR-Code-Import (`BarcodeDetector`) | ✅ | — | — |

Fehlt eine optionale Fähigkeit, weicht die Anwendung aus und sagt es: Download statt Direktspeichern, manuelle Eingabe statt QR-Scan.

---

## Dateiformat

NDJSON, eine Zeile je Block — jede Zeile für sich parsbar:

```
{"type":"header","format":"mmo-vault-v2","salt":"…","iterations":600000}
{"type":"text","iv":"…","data":"…"}
{"type":"file","id":"…","iv":"…","data":"…"}
```

Der Header ist unverschlüsselt und enthält nur die Ableitungsparameter. Der Textblock trägt Einträge, Verlauf und Einstellungen. Anhänge liegen als eigene Blöcke daneben — deshalb geht das Entsperren schnell, auch wenn große Dateien im Vault stecken. Dateien im alten v1-Format werden gelesen und beim nächsten Speichern automatisch überführt.

Vollständige Spezifikation: [docs/requirements.md](docs/requirements.md#5-dateiformat).

---

## Projektstruktur

```
mmo_vault/
├── mmo_vault/
│   └── public_html/
│       └── mmo_vault.html   Die vollständige Anwendung (= Auslieferverzeichnis)
├── docker/
│   └── nginx.conf           Statischer Server, Index auf mmo_vault.html
├── docs/
│   └── requirements.md      Anforderungen, Dateiformat, Bedrohungsmodell, Abnahme
├── Dockerfile
├── compose.yaml
├── README.md
└── LICENSE
```

Kein Build, kein Paketmanager, kein Test-Runner. Wer etwas ändern will, öffnet die HTML-Datei in einem Editor.

---

## Lizenz und Herkunft

Siehe [LICENSE](LICENSE). Entwickelt von Michael Müller als Teil der MMO-Toolreihe für Eigenprojekte.
