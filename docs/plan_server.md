# MMO Vault 2.0 — Umsetzungsplan Server-Modus

**Stand:** 2026-08-02
**Zielversion:** 2.0.0
**Status:** Planung, noch nicht umgesetzt

Dieses Dokument beschreibt den geplanten Umbau. Verbindlich für die Abnahme ist
weiterhin [requirements.md](requirements.md); die dort nötigen Ergänzungen sind in
Kapitel 10 aufgeführt.

**Vorgelagert:** [plan_versioning.md](plan_versioning.md) (Dateiformat v3,
Datensatz-Versionierung, Version 1.9.0). Die dort genannten Wechselwirkungen —
Strukturprüfung auf `mmo-vault-v3`, Größenlimit, Konfliktfall — sind hier
einzuarbeiten.

---

## 1. Ziel und Leitplanken

MMO Vault bekommt einen optionalen Server: einen FastAPI-Dienst, der Anmeldung
per OIDC (Google und andere), die Verwaltung zugelassener Benutzer und die
Ablage von Vault-Dateien übernimmt. Der Server ist **Dateiablage plus
Zugriffskontrolle**, nicht Kryptografie.

| Was | Wie es bleibt |
|---|---|
| Offline-Betrieb | `mmo_vault.html` bleibt **eine** Datei, per Doppelklick über `file://` voll funktionsfähig, ohne Server, ohne Build-Schritt |
| Verschlüsselung | Unverändert im Browser. Der Server bekommt **nie** Master-Passwort, Schlüssel oder Klartext — nur die fertigen NDJSON-Blöcke |
| Statische Auslieferung | Das heutige Deployment (nur nginx, eine Datei) bleibt als eigenes Compose-Profil erhalten |

Der Server ersetzt das lokale Dateisystem als Speicherort. Mehr nicht.

---

## 2. Content Security Policy — die eine echte Aufweichung

Heute steht in der Datei `connect-src 'none'`: der Browser erzwingt, dass die
Seite überhaupt keine Verbindung aufbauen kann. Ein Server-Modus braucht
`fetch`. Das geht nur mit `connect-src 'self'`.

- **Offline (`file://`)**: keine Änderung. Der Origin ist opak, `'self'` erlaubt
  dort keine einzige Verbindung. Die Garantie bleibt technisch identisch.
- **Server-Modus**: die Seite darf mit ihrem eigenen Origin sprechen — und
  ausschließlich damit. Kein CDN, kein Drittserver, keine Telemetrie; das bleibt
  vom Browser erzwungen.

Die Zusage lautet künftig „keine Verbindung außer zum ausliefernden Server"
statt „keine Netzwerkverbindung". Das gehört so in README und Bedrohungsmodell.

Verworfene Alternative: zwei getrennte HTML-Dateien (offline/server). Das kostet
einen Build-Schritt oder doppelte Pflege und wiegt die kleine Aufweichung nicht
auf.

---

## 3. Client-Änderungen (`mmo_vault.html`)

### 3.1 Speicherquelle als Abstraktion

Heute hängt alles an `state.fileHandle`, verstreut über Laden, Speichern,
Fallback, Sperren und Passwortwechsel. Das wird vorher aufgeräumt, sonst wird der
Server-Modus ein Flickenteppich:

```js
state.quelle = {
  art: 'fsa' | 'download' | 'server',
  name,                  // Anzeigename
  beschreibbar,          // false beim Download-Fallback
  async lesen(),         // → NDJSON-Text
  async schreiben(text)  // → true nur bei bestätigtem Schreiben
}
```

Die drei bestehenden Pfade (FSA-Handle, klassischer Datei-Dialog, Download)
werden auf diese Form gebracht. `saveToFile()` ruft danach nur noch
`state.quelle.schreiben()` und behält Rollback-, Verify- und Dirty-Logik
unverändert.

Diese Phase ist für sich prüfbar: die Anwendung muss sich offline exakt wie
1.8.0 verhalten.

### 3.2 Server-Quelle

- Aktivierung nur, wenn `location.protocol` `http(s)` ist **und**
  `GET /api/config` antwortet. Auf `file://` wird nichts versucht — kein Timeout,
  kein Fehler, keine sichtbare Änderung.
- Der Sperrbildschirm bekommt oberhalb von „Datei laden" einen Block
  **Server-Dateien**: Anmeldestatus, Liste der freigegebenen Vaults mit
  Sperrzustand, „Neu anlegen".
- Lesen: `GET /api/vaults/{id}/content` → Text unverändert durch
  `parseVaultText()`. Ab da ist der Ablauf identisch zum Datei-Fall.
- Schreiben: `PUT` mit `If-Match: <etag>` und gültigem Sperr-Token. Der Server
  antwortet mit neuem ETag und SHA-256 des gespeicherten Inhalts; der Client
  vergleicht gegen den lokal berechneten Hash. Dieselbe Regel wie heute:
  `state.dirty` fällt erst, wenn das Schreiben **bestätigt** ist.
- Sperren der Anwendung räumt zusätzlich Server-Quelle, ETag und Sperr-Token ab
  und gibt die Dateisperre frei. Die Sitzung beim Server bleibt bestehen — das
  sind zwei verschiedene Dinge und muss in der Oberfläche unterscheidbar sein.

### 3.3 Was der Client nicht bekommt

Keine Benutzerverwaltung. Die läuft über eine eigene, vom FastAPI-Dienst
ausgelieferte Admin-Seite. Der Vault bleibt schlank und muss für Adminfunktionen
nicht entsperrt sein.

---

## 4. Geteilte Vaults und Sperrmodell

Ein Vault kann mehreren Benutzern freigegeben sein (`read` oder `readwrite`).
Alle Schreibberechtigten teilen sich dasselbe Master-Passwort — das ist ein
Betriebsmodell, das man bewusst wählen muss; der Server kann daran nichts ändern.

Damit sich zwei Bearbeiter nicht gegenseitig überschreiben, gibt es **zwei
Schichten**, und die Reihenfolge ist wichtig:

| Schicht | Zweck | Verbindlichkeit |
|---|---|---|
| **Dateisperre** | verhindert, dass zwei Leute überhaupt parallel bearbeiten | beratend — dient der Bedienbarkeit |
| **ETag / `If-Match`** | verhindert verlorene Änderungen | **maßgeblich** — greift auch, wenn die Sperre versagt |

Die Sperre wird nie allein vertraut. Ein abgestürzter Client, dessen Sperre
abgelaufen ist, wird trotzdem vom ETag abgefangen.

### 4.1 Ablauf

```
POST   /api/vaults/{id}/lock     erwerben  → { token, holder, expires_at }
PUT    /api/vaults/{id}/lock     verlängern (Heartbeat)
DELETE /api/vaults/{id}/lock     freigeben
```

- **Erwerb** beim Entsperren eines Server-Vaults, für den der Benutzer
  Schreibrecht hat. Scheitert der Erwerb, wird der Vault **lesend** geöffnet —
  nicht abgewiesen. Die Oberfläche zeigt „Wird von *X* bearbeitet, Sperre läuft
  um *HH:MM* ab" und schaltet Bearbeiten/Speichern ab.
- **Laufzeit** voreingestellt 10 Minuten, konfigurierbar
  (`VAULT_LOCK_TTL_SECONDS`). Bewusst länger als die Auto-Sperre des Clients
  (Vorgabe 5 Minuten), damit nicht die Sperre vor dem Bearbeiter abläuft.
- **Heartbeat** alle TTL/3, solange der Vault entsperrt ist. Kein Heartbeat bei
  gesperrter Anwendung — dann soll die Sperre auslaufen.
- **Freigabe** ausdrücklich bei: Anwendung sperren, Auto-Sperre, „Datei
  schließen", Abmelden. Zusätzlich `navigator.sendBeacon` beim
  `beforeunload` — unzuverlässig, deshalb ist die TTL die eigentliche Absicherung.
- **Ablauf** wird faul ausgewertet: bei jeder Anfrage gilt eine Sperre mit
  `expires_at < now` als nicht vorhanden. Kein Hintergrundjob nötig.
- **Übernehmen**: Besitzer und Admins können eine fremde Sperre brechen
  (`DELETE .../lock?force=1`). Das erscheint im Audit-Log, und der bisherige
  Halter erfährt es beim nächsten Heartbeat (`409`) — seine Oberfläche schaltet
  dann auf „nur lesen" mit dem Hinweis, die Änderungen über *Als neue Datei
  speichern* zu retten.
- Alle Zeitstempel kommen **vom Server**. Client-Uhren werden nicht verwendet.

### 4.2 Konfliktfall

`PUT` ohne gültige Sperre oder mit veraltetem ETag → `409 Conflict`. Kein
Überschreiben, sondern ein Dialog:

- *Neu laden und eigene Änderungen verwerfen*
- *Als neue Datei speichern* (neuer Vault, gleiche Verschlüsselung)
- *Abbrechen* — „ungespeichert" bleibt stehen

Das löst nebenbei das Sync-Konflikt-Problem, vor dem die README heute nur warnt.

### 4.3 Grenzen, die genannt werden müssen

Die Sperre ist beratend und keine Sicherheitsgrenze. Sie schützt vor
versehentlichem Parallelbearbeiten, nicht vor einem böswilligen Client und nicht
vor direktem Zugriff auf das Datenverzeichnis. Der Schutz vor verlorenen
Änderungen liegt beim ETag.

---

## 5. FastAPI-Dienst (`server/`)

```
server/
├── app/
│   ├── main.py           App, Router, Startup-Bootstrap
│   ├── config.py         Settings aus Umgebung (pydantic-settings)
│   ├── auth.py           OIDC via Authlib, Sitzungscookie
│   ├── models.py         SQLModel: User, Vault, VaultAccess, VaultLock, AuditLog
│   ├── storage.py        atomares Schreiben, ETag, Generationen
│   ├── deps.py           aktueller Nutzer, Rollen- und ACL-Prüfungen
│   ├── routers/          auth, users, vaults, content, locks, admin
│   └── templates/        Admin-Oberfläche (Jinja, serverseitig gerendert)
├── pyproject.toml
└── Dockerfile
```

**Stack:** FastAPI + Uvicorn, Authlib (OIDC), SQLModel auf SQLite, itsdangerous
für signierte Cookies. Kein Postgres, kein Redis — das passt weder zum Maßstab
noch zur Projektlinie.

### 5.1 Anmeldung

- Provider generisch über Discovery konfigurierbar, nicht fest auf Google
  verdrahtet:
  `VAULT_OIDC_<NAME>_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET`, `_SCOPES`.
  Google, Entra, Authentik und Keycloak funktionieren damit ohne Codeänderung.
- Identität ist `(issuer, sub)`, **nicht** die E-Mail. Die E-Mail dient nur der
  Zuordnung beim ersten Login und wird nur akzeptiert, wenn der Provider
  `email_verified` setzt — sonst könnte ein Provider mit freier Mailwahl fremde
  Freischaltungen übernehmen.
- Sitzung: HttpOnly, `Secure`, `SameSite=Lax`, kurze Lebensdauer, serverseitig
  widerrufbar.

### 5.2 Provisionierung des Super-Admins

Beim Start, idempotent:

```
VAULT_SUPERADMIN_ISSUER=https://accounts.google.com
VAULT_SUPERADMIN_EMAIL=…
```

Existiert kein Super-Admin, wird ein Platzhalter mit dieser E-Mail und der Rolle
`superadmin` angelegt; beim ersten erfolgreichen Login wird die `sub` daran
gebunden. Danach wird die Variable ignoriert — sie ist Erstinbetriebnahme, kein
Dauerzustand. Der letzte Super-Admin lässt sich weder herabstufen noch löschen.

### 5.3 Rollen und Zugriff

| Rolle | Darf |
|---|---|
| `superadmin` | alles, inklusive Adminrechte vergeben |
| `admin` | Benutzer freischalten und sperren, Vaults anlegen, Freigaben setzen, Sperren brechen |
| `user` | nur die ihm freigegebenen Vaults |

Pro Vault eine ACL mit `read` oder `readwrite`. **Keine Selbstregistrierung:**
wer nicht vorher freigeschaltet ist, bekommt nach erfolgreichem OIDC-Login ein
klares „Dieses Konto ist nicht freigeschaltet"; der Versuch landet im Audit-Log.

### 5.4 Endpunkte

```
GET    /api/config                    Provider-Liste, Server-Modus-Kennung  (anonym)
GET    /auth/login/{provider}         → Weiterleitung zum IdP
GET    /auth/callback/{provider}
POST   /auth/logout
GET    /api/me                        Identität, Rolle, sichtbare Vaults
GET/POST/PATCH/DELETE /api/users      Admin
GET/POST/DELETE       /api/vaults     Liste, anlegen, löschen
PUT    /api/vaults/{id}/access        Freigaben setzen
POST/PUT/DELETE       /api/vaults/{id}/lock    erwerben / verlängern / freigeben
GET    /api/vaults/{id}/content       → NDJSON + ETag + Sperrzustand
PUT    /api/vaults/{id}/content       If-Match + Sperr-Token nötig → neuer ETag + SHA-256
```

### 5.5 Ablage

- Dateien unter `/data/vaults/{uuid}.ndjson`, Schreiben atomar (temporäre Datei
  plus `os.replace`), konfigurierbar N Generationen daneben.
- Metadaten, Benutzer, ACL, Sperren und Audit-Log in SQLite unter `/data/app.db`.
- Der Server prüft nur die **Struktur**: gültiger `mmo-vault-v1/v2`-Header,
  parsbare NDJSON-Zeilen, Größenlimit (Vorgabe 25 MB, konfigurierbar). Nie den
  Inhalt.

### 5.6 Absicherung

- Schreibende Endpunkte verlangen zusätzlich einen eigenen Header
  (`X-Vault-Request: 1`). Zusammen mit `SameSite=Lax` reicht das gegen CSRF ohne
  Token-Zirkus.
- Rate-Limit auf Login und `PUT`.
- Audit-Log: Login, abgelehnter Login, Rollenwechsel, Freigabeänderung, Vault
  angelegt/geschrieben/gelöscht, Sperre erworben/gebrochen. Ohne Inhalte.

---

## 6. Ergänzung des Bedrohungsmodells

Neu und ausdrücklich zu nennen:

- Wer den Server kontrolliert, kann Vault-Dateien **löschen, zurückrollen oder
  durch ältere Stände ersetzen**. Lesen kann er sie nicht. Verfügbarkeit und
  Integrität hängen damit am Server, Vertraulichkeit weiterhin allein am
  Master-Passwort.
- Bei geteilten Vaults kennen alle Schreibberechtigten dasselbe Master-Passwort.
  Der Entzug einer Freigabe nimmt den Zugriff auf den Server, **nicht** die
  Kenntnis des Passworts. Nach einem Entzug gehört das Master-Passwort
  gewechselt.
- Die Dateisperre ist beratend (siehe 4.3).
- Backups bleiben Pflicht des Betreibers.

---

## 7. Docker-Compose und nginx

**Zwei Dienste, zwei Profile.** Das heutige Deployment bleibt unverändert
bestehen:

```bash
docker compose up -d                      # wie bisher: nur nginx, eine Datei
docker compose --profile server up -d     # zusätzlich FastAPI und Volume
```

```yaml
services:
  mmo-vault:            # nginx, unverändert gehärtet, veröffentlicht 4080
    ...
    networks: [vault-intern]

  mmo-vault-api:
    profiles: [server]
    build: ./server
    image: mmo-vault-api:2.0.0
    # KEINE ports: — nur über das interne Netz erreichbar
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    volumes:
      - vault-data:/data
    env_file: .env      # OIDC-Geheimnisse, nicht in der compose.yaml
    mem_limit: 256m
    networks: [vault-intern]

volumes:
  vault-data:
networks:
  vault-intern:
```

**nginx** wird vom reinen Dateiserver zum Eingang für beides — dadurch ein
Origin, kein CORS, und `connect-src 'self'` genügt:

- Neue `location /api/` und `/auth/` mit `proxy_pass http://mmo-vault-api:8000;`.
  Wichtig: die `add_header`-Zeilen in diesen Blöcken **wiederholen**, sonst
  verwirft nginx die geerbten Header — die Falle ist in
  [nginx.conf](../docker/nginx.conf) bereits kommentiert.
- Die Methodensperre (`GET|HEAD`) gilt künftig nur noch für `location /`; unter
  `/api/` müssen POST/PUT/DELETE durch.
- CSP-Header auf `connect-src 'self'`, sonst unverändert.
- `client_max_body_size` passend zum Vault-Limit.
- Der API-Container läuft ohne `ports:` — von außen strukturell unerreichbar,
  exakt die Argumentation, die heute schon für die Loopback-Bindung gilt.

Für den statischen Betrieb ohne Server gibt es eine zweite
nginx-Konfiguration ohne `/api/`-Block, die per Profil eingehängt wird. Sonst
liefe der Proxy-Pfad ins Leere und erzeugte 502er im Log.

---

## 8. Umsetzungsreihenfolge

| Phase | Inhalt | Prüfbar durch |
|---|---|---|
| 0 | Client: Speicherquelle abstrahieren, kein neues Verhalten | Offline-Verhalten identisch zu 1.8.0 |
| 1 | FastAPI-Gerüst, OIDC, Freischaltung, Super-Admin-Bootstrap, Admin-Seite | Login mit Google; unfreigeschaltetes Konto wird abgewiesen |
| 2 | Vault-Endpunkte, ACL, atomares Schreiben, ETag | Roundtrip per `curl`, Konflikt provoziert 409 |
| 3 | Sperrmodell: erwerben, Heartbeat, Ablauf, Brechen | zwei Browser parallel; Sperre läuft nach TTL ab |
| 4 | Client-Server-Modus samt Sperr- und Konfliktdialog | Anlegen, Speichern, paralleles Bearbeiten |
| 5 | Compose, nginx, Härtung, README, Bedrohungsmodell, requirements.md | Container-Start, Header-Prüfung, `file://` weiter lauffähig |

Versionssprung auf **2.0.0** — neue Betriebsart und geänderte CSP sind kein Minor.

---

## 9. Bewusst nicht enthalten

- Serverseitige Entschlüsselung, Suche oder Vorschau
- Wiederherstellung des Master-Passworts über den Server
- Zusammenführen paralleler Änderungen (Merge). Bei Konflikt gilt: neu laden oder
  als neue Datei speichern
- Mehrmandantenfähigkeit über die Rollen hinaus

---

## 10. Nötige Ergänzungen in requirements.md

Beim Umsetzen nachzuziehen (bisher nicht angefasst):

- Kapitel 2: Server-Modus als Teil des Geltungsbereichs, Abgrenzung zu Kapitel 9
- Kapitel 3.5 Bedrohungsmodell: die Punkte aus Kapitel 6 dieses Plans
- Neue SEC-Anforderungen: CSP `connect-src 'self'`, Sitzungscookie, CSRF-Header,
  Identität über `(issuer, sub)`, keine Selbstregistrierung
- Neue FUN-Anforderungen: OIDC-Login, Benutzerverwaltung, Vault-Freigaben,
  Sperrmodell mit TTL und Heartbeat, ETag-Konfliktbehandlung, Server-Quelle im
  Client
- Kapitel 9 Abnahmekriterien: Sperrablauf, Konfliktfall, Abweisung nicht
  freigeschalteter Konten, `file://` weiterhin ohne Netzwerkzugriff
