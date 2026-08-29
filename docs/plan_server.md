# MMO Vault 2.0 — Umsetzungsplan Server-Variante

**Stand:** 2026-08-29
**Zielversion:** 2.0.0
**Status:** Planung, noch nicht umgesetzt

Vorgelagert und **erledigt**: [plan_versioning.md](plan_versioning.md) — Dateiformat v3
und Datensatz-Versionierung sind mit 1.9.0 ausgeliefert.

Verbindlich für die Abnahme bleibt [requirements.md](requirements.md); die dort
nötigen Ergänzungen stehen in Kapitel 14.

---

## 1. Ziel und Leitplanken

Neben der lokalen Datei entsteht ein Server: Benutzer- und Gruppenverwaltung,
Anmeldung per Passkey oder OIDC, vom Administrator angelegte Vaults, und eine
unbegrenzte Dateihistorie. Der Server ist **Ablage und
Zugriffskontrolle**, nicht Kryptografie.

| Was | Wie es bleibt |
|---|---|
| Offline-Betrieb | `mmo_vault.html` bleibt **eine** Datei, per Doppelklick über `file://` voll funktionsfähig, ohne Server, ohne Build-Schritt |
| Verschlüsselung | Unverändert im Browser. Der Server bekommt **nie** Master-Passwort, Schlüssel oder Klartext — nur die fertigen NDJSON-Blöcke |
| Aufbewahrung | Wie bei den Datensatz-Versionen: nichts verfällt automatisch, gelöscht wird von Hand |

---

## 2. Die Injektion — der Kern des Entwurfs

Die ausgelieferte Datei bleibt **byte-identisch** zu der, die man auch offline
benutzt. Im Server-Betrieb liefert der Dienst sie nicht roh aus, sondern
verändert sie beim Ausliefern an genau zwei Stellen:

1. Die CSP im `<meta>`-Tag wird von `connect-src 'none'` auf `connect-src 'self'`
   gehoben — **nur in der ausgelieferten Kopie**.
2. Vor `</body>` wird ein `<script>`-Block eingefügt, der `window.mmoVaultServer`
   bereitstellt.

Das löst das Problem, an dem der frühere Entwurf hing. Dort sollte die CSP in der
Datei selbst aufgeweicht werden; damit hätte auch die lokale Datei ihre
technisch erzwungene Zusage „keine Netzwerkverbindung" verloren. Jetzt gilt:

- **Lokale Datei:** `connect-src 'none'`. Die Zusage bleibt wörtlich wahr und vom
  Browser durchgesetzt. Die Datei enthält keine einzige URL und keinen
  `fetch`-Aufruf.
- **Server-Kopie:** darf mit ihrem eigenen Origin sprechen — und ausschließlich
  damit. Kein CDN, kein Drittserver, keine Telemetrie.

Damit das prüfbar bleibt: Der Dienst MUSS die Injektion auf diese zwei
Veränderungen begrenzen, das Ergebnis zwischenspeichern und über einen eigenen
Endpunkt (`GET /api/injection`) im Klartext ausliefern, damit sich nachsehen
lässt, was eingefügt wurde.

---

## 3. Client-Änderungen (`mmo_vault.html`)

### 3.1 Speicherquelle als Abstraktion

Heute hängt alles an `state.fileHandle`, verstreut über Laden, Speichern,
Fallback, Sperren und Passwortwechsel. Das wird zuerst aufgeräumt:

```js
state.source = {
  kind: 'fsa' | 'download' | 'server',
  name,
  writable,
  async read(),
  async write(text)   // true nur bei bestaetigtem Schreiben
}
```

Die drei bestehenden Pfade werden auf diese Form gebracht, `saveToFile()` ruft
danach nur noch `state.source.write()` und behält Rollback-, Verify- und
Dirty-Logik unverändert. Diese Phase ist für sich prüfbar: das Offline-Verhalten
muss identisch zu 1.9.0 bleiben.

### 3.2 Der Erweiterungspunkt

Die ausgelieferte Datei enthält **keinen** Servercode, nur den Haken:

```js
// Im Server-Betrieb legt der injizierte Block dieses Objekt an. Fehlt es –
// und offline fehlt es immer –, bleibt alles wie bisher.
const server = window.mmoVaultServer || null;
```

Erwartete Schnittstelle, vom injizierten Block zu erfüllen:

```
me()                          -> { user, groups, isAdmin }
listVaults()                  -> [{ id, name, permission, etag, lockedBy }]
readVault(id)                 -> { text, etag }
writeVault(id, text, etag)    -> { etag, sha256 }   | 409 bei Konflikt
acquireLock(id) / renewLock(id) / releaseLock(id)
listGenerations(id)           -> [{ generation, ts, size, author }]
readGeneration(id, gen)       -> { text }
logout()
```

Alles Weitere — Anmeldung, Benutzerverwaltung, Freigaben — läuft über eigene
Seiten des Dienstes, nicht in der Vault-Datei.

### 3.3 Ablauf im Server-Betrieb

Anmeldung am Dienst → Liste der freigegebenen Vaults auf dem Sperrbildschirm →
Klick auf eine Datei → **nur noch das Vault-Passwort**. Ab dem Entsperren ist der
Ablauf identisch zum Datei-Betrieb: dieselbe Entschlüsselung, dieselben
Datensatz-Versionen, derselbe Anhangs-Lazy-Load.

Das Sperren der Anwendung räumt Schlüssel, Einträge und die Server-Quelle ab und
gibt die Dateisperre frei. Die Sitzung beim Dienst bleibt davon unberührt — zwei
verschiedene Dinge, und das muss die Oberfläche unterscheidbar zeigen.

---

## 4. Benutzer, Gruppen, Rechte

| Rolle | Darf |
|---|---|
| `admin` | Benutzer und Gruppen verwalten, Vaults anlegen und zuweisen, Provider konfigurieren, Generationen löschen |
| `user` | nur die ihm oder seinen Gruppen freigegebenen Vaults |

- Ein Benutzer gehört zu beliebig vielen Gruppen.
- Ein Vault wird an **Benutzer oder Gruppen** freigegeben, jeweils mit `read`
  oder `readwrite`. Gilt für einen Benutzer mehr als eine Regel, gewinnt das
  weiter gehende Recht.
- **Keine Selbstregistrierung.** Wer nicht angelegt ist, bekommt nach
  erfolgreicher Anmeldung ein klares „Dieses Konto ist nicht freigeschaltet";
  der Versuch landet im Audit-Log.
- Der erste Administrator entsteht beim `setup` (Kapitel 9). Der letzte
  Administrator lässt sich weder herabstufen noch löschen.

**Zu benennen, weil es keine technische Lösung dafür gibt:** Alle
Schreibberechtigten eines Vaults teilen sich dasselbe Master-Passwort. Der Entzug
einer Freigabe nimmt den Zugriff auf den Server, **nicht** die Kenntnis des
Passworts. Nach einem Entzug gehört das Master-Passwort gewechselt.

---

## 5. Anmeldung

### 5.1 Verfahren, je Benutzer und Gruppe einstellbar

Wie die Provider ist auch das Anmeldeverfahren eine Eigenschaft von Benutzer und
Gruppe. Es gibt zwei reguläre Wege:

| Verfahren | Wofür |
|---|---|
| `passkey` | **Vorgabe.** WebAuthn/FIDO2, passwortlos |
| `oidc` | Microsoft 365, Google und alles Weitere per Discovery |

Ein Passwort allein ist **kein** reguläres Verfahren. Es existiert nur in zwei
eng begrenzten Fällen: bei der Erstinbetriebnahme (5.3) und, falls ausdrücklich
eingeschaltet, über Loopback (5.4).

**TOTP entfällt.** Passkeys sind Phishing-resistent, weil sie an den Origin
gebunden sind — ein Einmalcode lässt sich auf einer nachgebauten Anmeldeseite
abfragen und binnen Sekunden weiterreichen. Dazu spart der Verzicht ein ganzes
Teilsystem: kein Secret in der Datenbank, kein QR-Code, keine Zeitdrift.

### 5.2 Passkeys

- Bibliothek `webauthn` (py_webauthn). Gespeichert werden nur Credential-ID,
  öffentlicher Schlüssel, Signaturzähler und ein Anzeigename je Gerät.
- **Resident Keys** mit Nutzerverifikation (Biometrie oder Geräte-PIN). Damit ist
  die Anmeldung für sich schon zweifaktoriell: Besitz plus Verifikation.
- Mehrere Passkeys je Benutzer. Nach dem ersten fordert die Oberfläche zu einem
  zweiten Gerät auf — nachdrücklich, aber nicht erzwungen.
- **Ersatzcodes**: acht Stück, einmalig verwendbar, als Argon2-Hash gespeichert.
  Sie entstehen bei der Passkey-Registrierung und werden dort einmalig angezeigt.
- **Die RP ID hängt am Domainnamen.** Zieht der Dienst auf eine andere Domain um,
  werden alle Passkeys ungültig. Die RP ID gehört deshalb ausdrücklich in die
  Konfiguration und wird von `setup` abgefragt, statt aus dem `Host`-Header
  geraten zu werden.
- Passkeys setzen wie `crypto.subtle` einen Secure Context voraus. Das ist keine
  zusätzliche Einschränkung: ohne HTTPS ist die Anwendung ohnehin unbenutzbar
  (SEC-27).

> **Ein Passkey entsperrt keinen Vault.** Der Server hat den Schlüssel nie; nach
> dem Anklicken einer Vault-Datei ist weiterhin das Master-Passwort einzugeben.
> Wer „Passkey heißt kein Passwort mehr" erwartet, wird sonst überrascht — das
> gehört sichtbar in die Oberfläche.
>
> Technisch ließe sich über die WebAuthn-`prf`-Erweiterung Schlüsselmaterial aus
> dem Passkey ableiten und der Vault damit ohne Passworteingabe öffnen. Davon
> wird abgesehen: die Entschlüsselung hinge dann an einem Credential, und eine
> Datei, die offline auf jedem Gerät funktionieren muss, wäre an ein Gerät
> gebunden.

### 5.3 Erstinbetriebnahme: Passwort, dann sofort Passkey

`setup` läuft im Terminal, ein Passkey lässt sich dort nicht registrieren — der
braucht einen Browser und den echten Origin. Deshalb:

1. `setup` vergibt für den Administrator **nur ein Passwort** (Argon2id,
   Mindestlänge 12, Stärkeprüfung). Kein TOTP, kein QR-Code.
2. Das Konto trägt das Flag `must_enroll_passkey`.
3. Bei der ersten Anmeldung wird unmittelbar die Passkey-Registrierung verlangt.
4. Danach wird das Flag gelöscht, die Ersatzcodes werden angezeigt, und die
   Passwort-Anmeldung für dieses Konto ist **abgeschaltet** — endgültig, nicht
   als abschaltbare Bequemlichkeit.

**Entschieden:** Sobald ein Konto einen Passkey hat, gibt es für dieses Konto
keinen Passwortweg mehr. Ein Passwort als dauerhafter Notausgang wäre bequemer,
hielte aber genau den Angriffspfad offen, den die Passkeys schließen sollen. Die
beiden verbleibenden Wege zurück sind die Ersatzcodes und `enroll` auf dem
Server (9.3). Das Passwortfeld verschwindet für solche Konten auch aus der
Anmeldeseite; ein `password_hash` wird beim Löschen des Flags verworfen, nicht
nur ignoriert.

**Entscheidend ist Punkt 2**, nicht Punkt 1: Solange `must_enroll_passkey`
gesetzt ist, darf die Sitzung **ausschließlich** den Registrierungs-Endpunkt
aufrufen. Keine Vaults, keine Benutzerverwaltung, keine API, keine ausgelieferte
Anwendung. Ohne diese Sperre wäre das Zeitfenster zwischen Einrichtung und
erster Anmeldung ein vollwertiger Admin-Zugang mit einem einzigen Faktor — und
dieses Fenster ist in der Praxis nicht immer kurz.

Zusätzlich: Rate-Limit und Sperre nach wiederholtem Fehlschlag, und die
Registrierung ist auf einen konfigurierbaren Zeitraum begrenzt (Vorgabe 72
Stunden). Läuft er ab, öffnet `python mmo_vault.py enroll <benutzer>` auf dem
Server ein neues Fenster. Dasselbe Kommando ist der Weg zurück, wenn alle
Passkeys und Ersatzcodes verloren sind — die lokale Shell ist damit die
Vertrauenswurzel, was ehrlich ist: wer den Server hat, hat ohnehin alles.

Für weitere Benutzer gilt dasselbe Muster: ein Administrator legt das Konto an
und erzeugt einen einmaligen Registrierungs-Link mit Ablaufdatum; ein
Anfangspasswort ist dafür nicht nötig.

### 5.4 Passwort über Loopback — und die Falle dabei

Gefordert war, dass die Anmeldung über localhost ohne zweiten Faktor möglich
bleibt. Mit Passkeys gibt es keinen „zweiten Faktor", den man weglassen könnte;
die Ausnahme betrifft nur noch die **Passwort-Anmeldung** und ist damit der
einzige Weg, auf dem ein Passwort allein eine vollwertige Sitzung ergibt. Sie hat
eine Falle, die im dokumentierten Betrieb **garantiert** zuschlägt:

> **Hinter einem Reverse Proxy auf demselben Host sieht jede Anfrage wie
> localhost aus.** Der Proxy verbindet sich von `127.0.0.1` auf den Dienst. Eine
> Ausnahme, die nur die Peer-Adresse prüft, öffnet die Passwort-Anmeldung damit
> für **alle** Benutzer aus dem Internet.

Deshalb drei Bedingungen gemeinsam, nicht einzeln:

1. Die Peer-Adresse (`request.client.host`, **nicht** `X-Forwarded-For`) ist
   `127.0.0.1` oder `::1`.
2. Die Anfrage trägt **keinen** `X-Forwarded-For`- und keinen
   `Forwarded`-Header — ihr Vorhandensein beweist einen Proxy davor.
3. Die Einstellung `auth.allow_local_password_login` steht auf `true`. **Vorgabe
   ist `false`**, und `setup` fragt ausdrücklich danach.

Zusätzlich empfohlen und in der Konfiguration vorgesehen: ein getrennter, nur an
Loopback gebundener Port für diesen Zugang, während der öffentliche Port ihn nie
gewährt. Wer das nutzt, ist gegen eine Fehlkonfiguration des Proxys strukturell
abgesichert statt nur durch Header-Prüfungen.

### 5.5 OIDC, je Benutzer oder Gruppe einstellbar

- Provider werden als Datensätze gepflegt: Name, Issuer, Client-ID,
  Client-Secret, Scopes, aktiv ja/nein. Konfiguriert wird generisch über
  Discovery — Microsoft 365 und Google im ersten Schritt, Keycloak und Authentik
  funktionieren damit ohne Codeänderung.
- Zuordnung: an einem Benutzer **und** an einer Gruppe kann ein Provider hängen.
  Die Anmeldeseite bietet einem Benutzer genau die Wege an, die für ihn oder
  eine seiner Gruppen erlaubt sind. Passkey und OIDC nebeneinander sind zulässig.
- Identität ist `(issuer, sub)`, **nicht** die E-Mail. Die E-Mail dient nur der
  Zuordnung beim ersten Login und nur, wenn der Provider `email_verified` setzt —
  sonst könnte ein Provider mit freier Mailwahl fremde Konten übernehmen.
- Der zweite Faktor liegt beim Provider; der Dienst verlangt keinen weiteren.
- Bibliothek: **Authlib**.

### 5.6 Sitzung

Serverseitige Sitzungen in der Datenbank, adressiert über ein signiertes
Cookie (`HttpOnly`, `Secure`, `SameSite=Lax`). Serverseitig, weil sie damit
widerrufbar sind — nötig, sobald ein Konto gesperrt oder ein Gerät verloren wird.
Zwei Lebensdauern: absolute Gültigkeit und Leerlauf-Verfall, beide konfigurierbar
(Vorschlag: 12 Stunden und 30 Minuten). Eine Sitzung mit gesetztem
`must_enroll_passkey` ist auf den Registrierungs-Endpunkt beschränkt (5.3).

---

## 6. Vaults

- Anlegen ausschließlich durch Administratoren, mit Namen und Freigaben. Der
  Dienst legt eine leere Hülle an; **erzeugt** wird der Vault im Browser des
  ersten Benutzers, der ein Master-Passwort vergibt — der Server kennt es nie.
- Ablage unter `var/vaults/<uuid>/current.ndjson`, geschrieben über temporäre
  Datei plus `os.replace`, also atomar.
- Der Dienst prüft nur die **Struktur**: gültiger Header `mmo-vault-v1|v2|v3`,
  parsbare NDJSON-Zeilen, Größenlimit. Nie den Inhalt.
- Löschen eines Vaults ist Administratorensache und entfernt Verzeichnis samt
  Historie — mit ausdrücklicher Rückfrage.

### 6.1 Schreibkonflikte: zwei Schichten

| Schicht | Zweck | Verbindlichkeit |
|---|---|---|
| **Dateisperre** | verhindert paralleles Bearbeiten | beratend — dient der Bedienbarkeit |
| **ETag / `If-Match`** | verhindert verlorene Änderungen | **maßgeblich** — greift auch, wenn die Sperre versagt |

Der Sperre wird nie allein vertraut: ein abgestürzter Client, dessen Sperre
abgelaufen ist, wird trotzdem vom ETag abgefangen.

- Erwerb beim Entsperren eines Vaults mit Schreibrecht. Scheitert er, öffnet der
  Vault **lesend** — nicht abgewiesen — mit Hinweis „Wird von *X* bearbeitet".
- Laufzeit 10 Minuten (`vault.lock_ttl_seconds`), bewusst länger als die
  Auto-Sperre des Clients, damit nicht die Sperre vor dem Bearbeiter abläuft.
  Heartbeat alle TTL/3, nur solange der Vault entsperrt ist.
- Freigabe bei Sperren, Auto-Sperre, Schließen und Abmelden, zusätzlich per
  `navigator.sendBeacon` beim `beforeunload` — unzuverlässig, deshalb ist die TTL
  die eigentliche Absicherung.
- Ablauf wird faul ausgewertet: bei jeder Anfrage gilt eine Sperre mit
  `expires_at < now` als nicht vorhanden. Kein Hintergrundjob.
- Brechen durch Besitzer und Administratoren, im Audit-Log vermerkt; der bisherige
  Halter erfährt es beim nächsten Heartbeat und kann seine Änderungen über
  *Als neue Datei speichern* retten.
- Alle Zeitstempel kommen vom Server, Client-Uhren werden nicht verwendet.

`PUT` ohne gültige Sperre oder mit veraltetem ETag → `409`, kein Überschreiben,
sondern der Dialog *neu laden* / *als neue Datei speichern* / *abbrechen*.

---

## 7. Dateihistorie

Jeder erfolgreiche Schreibvorgang legt eine **Generation** an:
`var/vaults/<uuid>/history/<lfd-nr>-<zeitstempel>.ndjson`, dazu ein Datensatz mit
Zeitpunkt, Urheber, Größe und SHA-256.

- **Unbegrenzt.** Es verfällt nichts automatisch — dieselbe Entscheidung wie bei
  den Datensatz-Versionen in 1.9.0.
- **Gelöscht wird nur von Hand:** einzelne Generationen, alles vor einem Datum,
  oder die gesamte Historie eines Vaults. Nur Administratoren.
- **Wiederherstellen erzeugt eine neue Generation**, statt zurückzuspulen. Der
  Verlauf bleibt damit lückenlos und die Wiederherstellung selbst umkehrbar.
- Die Oberfläche zeigt Anzahl und Gesamtgröße der Generationen je Vault und warnt
  ab einer konfigurierbaren Schwelle — Vorgabe 200 MB je Vault.
- Ein Administrator kann eine Generation herunterladen. Sie ist verschlüsselt und
  ohne Master-Passwort wertlos, aber es bleibt der bequemste Weg zu einem Backup.

**Wichtig zu verstehen und zu dokumentieren:** Das sind zwei Ebenen. Die
Datensatz-Versionen liegen **in** der Datei und wandern mit ihr, auch offline.
Die Generationen liegen **daneben** auf dem Server und gibt es nur im
Server-Betrieb.

---

## 8. Dienst und Datenmodell

```
mmo_vault.py                  CLI-Einstieg (setup, start)
mmo_vault/
├── public_html/
│   └── mmo_vault.html        unveraendert, die Anwendung
├── server/
│   ├── app.py                FastAPI-App, Router, Lifespan
│   ├── config.py             Einstellungen (pydantic-settings, var/config.toml)
│   ├── db.py                 Engine, Session, Basisklasse
│   ├── models.py             SQLAlchemy-Modelle
│   ├── security.py           Argon2, WebAuthn, Sitzungen, Abhaengigkeiten
│   ├── injection.py          CSP-Umschreiben und Script-Einbau
│   ├── storage.py            atomares Schreiben, ETag, Generationen
│   ├── cli.py                setup/start
│   ├── routers/              auth, passkeys, oidc, users, groups, vaults, content, locks, history, admin
│   ├── static/               server.js (der injizierte Block), Admin-Assets
│   └── templates/            Anmeldung und Admin-Oberflaeche (Jinja)
└── migrations/               Alembic
```

> **Namenskonflikt beachten:** `mmo_vault.py` und der Ordner `mmo_vault/` liegen
> nebeneinander. Python bevorzugt beim Import das Paket, das Skript läuft als
> `__main__` — es funktioniert, ist aber verwirrend. `mmo_vault.py` bleibt
> deshalb ein dünner Starter, der nichts tut außer
> `from mmo_vault.server.cli import main`. Aller Code liegt im Paket.

**Stack:** FastAPI, SQLAlchemy 2.0 (ORM, async), Alembic, Authlib, argon2-cffi,
pydantic-settings, Uvicorn. Kein Redis, kein Celery — passt weder zum Maßstab
noch zur Projektlinie.

**Datenbank abstrahiert:** ausschließlich über SQLAlchemy, keine
SQLite-Besonderheiten im Code, Verbindung über `database.url`. Vorgabe
`sqlite+aiosqlite:///var/mmo_vault.db`; PostgreSQL funktioniert durch Umstellen
der URL. Alembic von Anfang an — später nachzurüsten ist deutlich teurer.

### 8.1 Modelle

```
User        id, name, email, password_hash?, auth_method='passkey'|'oidc',
            must_enroll_passkey, enroll_expires_at?, is_admin, is_active,
            provider_id?, created_at, last_login_at
Credential  id, user_id, credential_id, public_key, sign_count, label,
            created_at, last_used_at        -- Passkeys, mehrere je Benutzer
Group       id, name, description, provider_id?
UserGroup   user_id, group_id
Provider    id, name, kind='oidc', issuer, client_id, client_secret, scopes, enabled
Vault       id, name, description, created_by, created_at, size_bytes, etag
VaultAccess vault_id, subject_type='user'|'group', subject_id, permission='read'|'readwrite'
VaultLock   vault_id, user_id, token, acquired_at, expires_at
Generation  id, vault_id, seq, ts, author_id, size_bytes, sha256, note?
Session     id, user_id, created_at, last_seen_at, expires_at, ip, user_agent
BackupCode  id, user_id, code_hash, used_at?   -- entsteht bei der Passkey-Registrierung
AuditLog    id, ts, actor_id?, action, target, detail
```

### 8.2 Endpunkte

```
GET    /                            ausgelieferte Anwendung, injiziert
GET    /api/injection               zeigt den eingefuegten Block im Klartext
GET    /api/config                  Provider-Liste, Server-Kennung        (anonym)
POST   /auth/login                  Passwort (nur Erstinbetriebnahme oder Loopback)
POST   /auth/passkey/options        WebAuthn-Challenge zur Anmeldung
POST   /auth/passkey/verify         Anmeldung abschliessen
POST   /auth/passkey/register/options   Registrierung, nur mit must_enroll_passkey
POST   /auth/passkey/register/verify
POST   /auth/backup-code
GET    /auth/oidc/{provider}        -> Weiterleitung zum IdP
GET    /auth/oidc/{provider}/callback
POST   /auth/logout
GET    /api/me
CRUD   /api/users  /api/groups  /api/providers                            (admin)
CRUD   /api/vaults                                                        (admin)
PUT    /api/vaults/{id}/access                                            (admin)
POST   /api/vaults/{id}/lock  PUT  ...  DELETE ...
GET    /api/vaults/{id}/content     -> NDJSON + ETag + Sperrzustand
PUT    /api/vaults/{id}/content     If-Match + Sperr-Token -> ETag + SHA-256
GET    /api/vaults/{id}/history
GET    /api/vaults/{id}/history/{seq}
POST   /api/vaults/{id}/history/{seq}/restore                             (admin)
DELETE /api/vaults/{id}/history/{seq}                                     (admin)
```

### 8.3 Absicherung

- Schreibende Endpunkte verlangen zusätzlich `X-Vault-Request: 1`; zusammen mit
  `SameSite=Lax` reicht das gegen CSRF ohne Token-Zirkus.
- Größenlimit je Vault, konfigurierbar; `client_max_body_size` am Proxy passend.
- Audit-Log: Anmeldung, abgelehnte Anmeldung, Rollen- und Freigabeänderung,
  Vault angelegt/geschrieben/gelöscht, Sperre erworben/gebrochen, Generation
  wiederhergestellt/gelöscht. Ohne Inhalte.
- Security-Header setzt der Dienst selbst, damit sie auch ohne Proxy stimmen.

---

## 9. `mmo_vault.py` — die Kommandozeile

```bash
python mmo_vault.py setup      # interaktive Erstinbetriebnahme
python mmo_vault.py start      # Dienst starten
```

### 9.1 `setup`

Interaktiv, mit sinnvollen Vorgaben in Klammern; jede Frage auch als Schalter für
den unbeaufsichtigten Lauf (`--admin-name`, `--port`, `--non-interactive`, …).

1. **Datenbank** — URL (Vorgabe `sqlite+aiosqlite:///var/mmo_vault.db`), danach
   Schema anlegen bzw. Alembic auf den aktuellen Stand bringen.
2. **Administrator** — Name, E-Mail, Passwort zweimal, mit Stärkeprüfung und
   Mindestlänge 12. Eingabe verdeckt. Mehr nicht: kein TOTP, kein QR-Code.
   Das Konto bekommt `must_enroll_passkey` und ein Ablaufdatum für die
   Registrierung.
3. **RP ID und Origin für Passkeys** — der Domainname, unter dem der Dienst
   erreichbar sein wird. Wird abgefragt statt geraten, weil ein späterer Wechsel
   alle Passkeys ungültig macht (5.2).
4. **Passwort-Anmeldung über Loopback** — ausdrückliche Frage, Vorgabe **nein**,
   mit dem Hinweis aus 5.4.
5. **Uvicorn** — Adresse (Vorgabe `127.0.0.1`), Port (Vorgabe `8000`), Anzahl
   Worker, Proxy-Headers ja/nein, optional der getrennte Loopback-Port.
6. Schreibt `var/config.toml` mit `0600`-Rechten, legt `var/vaults/` an und
   meldet, was als Nächstes zu tun ist.

Zum Schluss nennt `setup` die Adresse, unter der sich der Administrator anmelden
muss, und weist darauf hin, dass die erste Sitzung **nichts** kann außer einen
Passkey anzulegen.

Ein zweiter Lauf verweigert die Arbeit, solange eine Konfiguration existiert —
außer mit `--force`, das ausdrücklich nur Einstellungen ändert und **keine**
Benutzer löscht.

### 9.2 `start`

Liest die Konfiguration, prüft sie (fehlende Datenbank, ausstehende Migration,
falsche Dateirechte an `config.toml`) und startet Uvicorn. `--reload` für die
Entwicklung. Ohne vorheriges `setup` bricht der Start mit einem klaren Hinweis ab
statt mit einem Stacktrace.

### 9.3 `enroll`

```bash
python mmo_vault.py enroll <benutzer>
```

Öffnet ein neues Registrierungsfenster: setzt `must_enroll_passkey`, vergibt ein
Einmalpasswort und gibt es aus. Das ist der Weg zurück, wenn das erste Fenster
abgelaufen ist oder alle Passkeys und Ersatzcodes verloren sind. Nur lokal auf
dem Server ausführbar — die Shell ist damit die Vertrauenswurzel.

Später vorgesehen, jetzt nicht: `user add`, `backup`, `migrate`.

---

## 10. Docker

Der Dockerfile bekommt zwei Ziele, damit die heutige statische Auslieferung
erhalten bleibt:

```dockerfile
# ---- Ziel "static": wie bisher, nur nginx und eine Datei ----
FROM nginx:alpine AS static
COPY mmo_vault/public_html/ /srv/mmo-vault/
COPY docker/nginx.conf /etc/nginx/nginx.conf

# ---- Ziel "server": FastAPI ----
FROM python:3.13-slim AS builder
COPY requirements.txt .
RUN python -m venv /venv && /venv/bin/pip install --no-cache-dir -r requirements.txt

FROM python:3.13-slim AS server
COPY --from=builder /venv /venv
COPY mmo_vault.py /app/
COPY mmo_vault/ /app/mmo_vault/
USER 10001:10001
ENTRYPOINT ["/venv/bin/python", "/app/mmo_vault.py"]
CMD ["start"]
```

Compose bekommt zwei Profile:

```bash
docker compose up -d                      # wie bisher: nur nginx, eine Datei
docker compose --profile server up -d     # FastAPI mit Volume
```

Für den Server-Dienst:

- **kein `ports:`** nach außen, wenn ein Proxy-Container davor liegt; sonst
  Loopback-Bindung wie bisher.
- `read_only: true` plus `tmpfs: /tmp`, benanntes Volume auf `/data`. Datenbank
  und Vaults liegen dort, `var/` zeigt im Container darauf.
- `cap_drop: [ALL]`, `no-new-privileges`, unprivilegierter Benutzer, `mem_limit`
  eher 512 MB als 64 MB.
- `--proxy-headers` nur einschalten, wenn tatsächlich ein Proxy davorsteht —
  siehe die Falle in 5.2.
- Healthcheck auf einen schlanken `GET /api/health`.
- Das `setup` läuft einmalig als eigener Lauf:
  `docker compose run --rm mmo-vault-server setup`.

nginx bleibt im Server-Betrieb **außen** als TLS-Terminierung; die Anwendung
liefert der Dienst selbst aus, weil er sie ohnehin injizieren muss. Damit gibt es
einen Origin und kein CORS.

---

## 11. Sicherheitseigenschaften und Bedrohungsmodell

Neu zu benennen:

- Wer den Server kontrolliert, kann Vault-Dateien **löschen, zurückrollen oder
  durch ältere Generationen ersetzen**. Lesen kann er sie nicht. Verfügbarkeit
  und Integrität hängen am Server, Vertraulichkeit weiterhin allein am
  Master-Passwort.
- Wer den Server kontrolliert, kann **beliebigen Code injizieren**. Das ist keine
  neue Schwäche — wer die Anwendungsdatei ausliefert, konnte das immer schon —
  aber die Injektion macht es zu einem regulären Vorgang. Gegenmaßnahmen:
  Begrenzung auf zwei Stellen, Offenlegung über `/api/injection`, und der
  Hinweis, dass für den höchsten Anspruch die lokale Datei der richtige Weg
  bleibt.
- Bei geteilten Vaults kennen alle Schreibberechtigten dasselbe Master-Passwort;
  ein Freigabeentzug nimmt nicht die Kenntnis (Kapitel 4).
- Die Passwort-Anmeldung über Loopback ist eine bewusste Abwägung und im
  Standard aus. Sie ist der einzige Weg, auf dem ein Passwort allein eine
  vollwertige Sitzung ergibt.
- Zwischen `setup` und der ersten Anmeldung ist das Administratorkonto durch ein
  Passwort allein geschützt. Der Schaden ist dadurch begrenzt, dass diese Sitzung
  ausschließlich einen Passkey registrieren kann (5.3), das Fenster abläuft und
  die Anmeldung ratenbegrenzt ist.
- Wer Shell-Zugang zum Server hat, kann sich über `enroll` einen Zugang
  verschaffen. Das ist beabsichtigt und unvermeidbar: wer den Server
  kontrolliert, kontrolliert den Dienst.
- Die Dateisperre ist beratend und keine Sicherheitsgrenze.
- Backups bleiben Pflicht des Betreibers — die Generationen liegen auf demselben
  Datenträger.

---

## 12. Umsetzungsreihenfolge

| Phase | Inhalt | Prüfbar durch |
|---|---|---|
| 0 | Client: Speicherquelle abstrahieren, Erweiterungspunkt einbauen | Offline-Verhalten identisch zu 1.9.0 |
| 1 | `mmo_vault.py`, Konfiguration, Datenbank, Modelle, Alembic, `setup`, `start` und `enroll` | Setup legt den Administrator mit Passwort und Registrierungspflicht an, Start läuft |
| 2 | Anmeldung: Passkeys, Registrierungszwang, Ersatzcodes, Sitzungen, Loopback-Ausnahme | Erste Sitzung kann nur registrieren; danach Anmeldung per Passkey; Ausnahme greift nur lokal und ohne Proxy-Header |
| 3 | Benutzer, Gruppen, Provider, Admin-Oberfläche | OIDC-Anmeldung mit Google und M365, nicht freigeschaltetes Konto wird abgewiesen |
| 4 | Vaults, Freigaben, atomares Schreiben, ETag, Sperrmodell | Roundtrip per `curl`, Konflikt provoziert 409, Sperre läuft nach TTL ab |
| 5 | Dateihistorie: Generationen, Ansehen, Wiederherstellen, Löschen | Wiederherstellen erzeugt eine neue Generation, nichts verfällt von selbst |
| 6 | Injektion und Client-Server-Modus samt Sperr- und Konfliktdialog | `file://` weiterhin ohne Netzwerk, Server-Kopie mit `connect-src 'self'` |
| 7 | Docker, Compose, Härtung, README, Bedrohungsmodell, requirements.md | Container-Start, Header-Prüfung, Setup im Container |

Version **2.0.0**.

---

## 13. Offene Entscheidungen

1. **OIDC-Benutzer automatisch anlegen?** Ich plane mit *nein* — ein Konto
   entsteht nur durch einen Administrator, die OIDC-Identität wird beim ersten
   Login daran gebunden. Alternative: automatisches Anlegen, wenn die
   E-Mail-Domäne zu einer Gruppe passt. Sag Bescheid, falls du das willst.
2. **Getrennter Loopback-Port für die Passwort-Anmeldung** (5.4) — meine
   Empfehlung, weil er gegen Proxy-Fehlkonfiguration strukturell schützt statt
   nur durch Header-Prüfung. Kostet eine zweite Uvicorn-Bindung.
3. **Admin-Oberfläche serverseitig gerendert** (Jinja) statt als eigene
   JavaScript-Anwendung — passt zur Projektlinie und hält die Abhängigkeiten
   klein.

---

## 14. Nötige Ergänzungen in requirements.md

- Kapitel 1.1: Der Server ist nicht mehr außerhalb des Geltungsbereichs;
  Mehrbenutzer- und Freigabeverwaltung ebenso wenig. Beides umformulieren statt
  streichen, mit Verweis auf die neuen Kapitel.
- Kapitel 2: Begriffe Gruppe, Provider, Generation, Sitzung, Injektion.
- Kapitel 3.4: CSP-Aufweichung ausschließlich in der ausgelieferten Kopie, mit
  der Anforderung, dass die Datei selbst `connect-src 'none'` behält.
- Kapitel 3.5: die Punkte aus Kapitel 11 dieses Plans.
- Neue SEC-Anforderungen: Passkeys als reguläres Verfahren, Beschränkung der
  Sitzung mit `must_enroll_passkey`, Ablauf des Registrierungsfensters, Argon2id,
  Identität über `(issuer, sub)`, keine Selbstregistrierung, widerrufbare
  Sitzungen, CSRF-Header, Begrenzung und Offenlegung der Injektion.
- Neue FUN-Anforderungen: Benutzer- und Gruppenverwaltung, Provider je Benutzer
  und Gruppe, Vault-Anlage und Freigaben, Sperrmodell mit TTL und Heartbeat,
  ETag-Konfliktbehandlung, Dateihistorie mit manuellem Löschen, `setup` und
  `start`.
- Kapitel 9: Abnahmekriterien für Sperrablauf, Konfliktfall, Abweisung nicht
  freigeschalteter Konten, Passkey-Registrierungszwang samt gesperrter Sitzung,
  Loopback-Ausnahme mit und ohne Proxy-Header,
  Wiederherstellen einer Generation, und `file://` weiterhin ohne
  Netzwerkzugriff.
