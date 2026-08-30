# MMO Vault 2.1 — Umsetzungsplan: Identität kommt vom Provider

**Stand:** 2026-08-30
**Zielversion:** 2.1.0
**Status:** Planung, noch nicht umgesetzt
**Löst ab:** die Kapitel 4, 5 und 9 von [plan_server.md](plan_server.md). Alles zu
Vaults, Sperre, ETag, Historie und Injektion (Kapitel 2, 3, 6, 7, 10) bleibt gültig.

---

## 1. Was sich ändert, in einem Satz

Der Dienst führt **keine eigenen Anmeldedaten mehr**. Wer jemand ist, entscheidet
ein OIDC-Provider; wer hinein darf, entscheidet eine Whitelist; was jemand darf,
entscheiden Rollen, Gruppen und Freigaben im Dienst.

| Weg fällt | Warum |
|---|---|
| Passwort-Bootstrap, `enroll`, Einmalpasswörter | kein lokales Geheimnis mehr, das ein Konto öffnet |
| Passkeys, Ersatzcodes, `must_enroll_passkey`, SEC-46 | der zweite Faktor liegt beim Provider — zwei Anmeldesysteme nebeneinander wären Komplexität ohne Gewinn |
| Loopback-Ausnahme | es gibt keine Passwort-Anmeldung mehr, die man ausnehmen könnte |
| `config.toml` | **alle** Einstellungen liegen in der Datenbank |
| Konten von Hand anlegen | Konten entstehen beim ersten Login — für Adressen auf der Whitelist |

**Bleibt unverändert:** Vaults, Freigaben, Sperre und ETag, Generationen,
Injektion, der Client, das Dateiformat. Die lokale Datei ohnehin.

---

## 2. Konfiguration: zwei Umgebungsvariablen, sonst nichts

```
MMO_VAULT_DIR           Arbeitsverzeichnis (Vorgabe: var/ im Projekt)
MMO_VAULT_DATABASE_URL  SQLAlchemy-URL   (Vorgabe: sqlite:///$MMO_VAULT_DIR/mmo_vault.db)
```

Alles Weitere steht in der Tabelle `setting` (Schlüssel/Wert, typisierter
Zugriff mit Vorgabewerten — fehlender Schlüssel heißt Vorgabe, genau wie bisher
beim TOML):

| Schlüssel | Vorgabe | Wer setzt |
|---|---|---|
| `origin` | — (Pflicht) | `setup`, danach Admin-UI |
| `secret_key` | beim ersten Start erzeugt | Dienst selbst |
| `session_hours` / `session_idle_minutes` | 12 / 30 | Admin-UI |
| `vault.max_size_bytes` / `lock_ttl_seconds` / `history_warn_bytes` | wie bisher | Admin-UI |
| `server.proxy_headers` / `forwarded_allow_ips` | false / 127.0.0.1 | Admin-UI, wirkt nach Neustart |

`origin` ist Pflicht und wird beim `setup` abgefragt, weil die Redirect-URI der
Provider daraus gebaut wird — vor dem ersten Login muss sie feststehen.

> **Folge, die man kennen muss:** Auch die Client-Secrets der Provider liegen
> in der Datenbank. Wer die Datenbank hat, hat sie. Eine Verschlüsselung at rest
> bräuchte einen Schlüssel von außerhalb — und genau den soll es per Vorgabe
> nicht geben. Das gehört ins Bedrohungsmodell, nicht in eine halbe Lösung.

---

## 3. Provider

Tabelle `provider`, erweitert:

```
id, name, kind ('microsoft' | 'google' | 'generic'), issuer, client_id,
client_secret, scopes, tenant (nur microsoft), is_primary, enabled,
sync_groups (bool), created_at
```

`kind` bestimmt drei Dinge, die sich zwischen den Anbietern unterscheiden:

| | Microsoft 365 | Google |
|---|---|---|
| Issuer | `https://login.microsoftonline.com/{tenant}/v2.0` | `https://accounts.google.com` |
| Adresse aus | `email`, sonst `preferred_username` | `email` |
| Adresse bestätigt? | Microsoft liefert **kein** `email_verified`; die Adresse gilt als vom Tenant bestätigt, sofern `tid` zum konfigurierten Tenant passt | `email_verified` muss `true` sein |
| Gruppen | Microsoft Graph `GET /me/memberOf` | Cloud Identity API, siehe Kapitel 6 |

`generic` deckt Keycloak, Authentik und andere ab — ohne Gruppen-Sync, mit
strenger `email_verified`-Prüfung.

**Der primäre Provider** (`is_primary`) ist der, den `setup` anlegt. Er hat keine
Sonderrechte im Betrieb; die Markierung dient nur der Erstinbetriebnahme und
der Anmeldeseite (steht oben). Der Admin kann weitere anlegen und den primären
wechseln. Ein Provider mit Whitelist-Einträgen oder gebundenen Konten lässt sich
nicht löschen, nur abschalten.

---

## 4. Whitelist und Konten

### 4.1 Whitelist

Tabelle `allowlist`:

```
id, provider_id, email (normalisiert, klein), is_admin, note, created_at, created_by
```

Ein Login wird angenommen, wenn eine dieser Bedingungen gilt:

1. Das Konto ist bereits an `(provider, sub)` gebunden **und** seine Adresse
   steht noch auf der Whitelist dieses Providers.
2. Kein gebundenes Konto, aber die bestätigte Adresse steht auf der Whitelist
   → Konto wird angelegt und gebunden.

Alles andere: 403, Audit-Eintrag, keine Kontoanlage.

Das Admin-Flag kommt **bei jedem Login** aus der Whitelist. Wer dort vom Admin
zum Nutzer wird, ist es ab der nächsten Anmeldung — und weil Sitzungen
serverseitig liegen, kann der Admin die laufende Sitzung sofort widerrufen.
Streichen von der Whitelist deaktiviert das Konto beim nächsten Versuch; das
Konto selbst (und damit seine Historie in Audit und Generationen) bleibt, bis ein
Admin es löscht. Löschen räumt wie bisher alle Referenzen ab.

**Der letzte Administrator** ist weiterhin geschützt — jetzt auf Whitelist-Ebene:
der letzte `is_admin`-Eintrag lässt sich weder entfernen noch herabstufen.

Optional, für später: Domain-Einträge (`*@firma.de`). Nicht im ersten Schritt —
die Semantik gegenüber Einzeleinträgen (welcher gewinnt beim Admin-Flag?) will
erst geklärt sein.

### 4.2 Konten

Tabelle `user`, verschlankt:

```
id (AUTOINCREMENT), name, email, provider_id, provider_subject, is_admin,
is_active, created_at, last_login_at
```

Weg sind `password_hash`, `must_enroll_passkey`, `enroll_expires_at`,
`failed_attempts`, `locked_until`. Der Anzeigename kommt aus `name`/`preferred_username`
des Providers und wird bei jedem Login aktualisiert.

Die Identität bleibt `(provider, sub)`. Die Adresse dient der Whitelist-Prüfung
und der ersten Bindung — ändert jemand seine Adresse beim Provider, muss der Admin
den Whitelist-Eintrag anpassen, das Konto bleibt über `sub` dasselbe.

### 4.3 Sitzungen

Unverändert serverseitig und widerrufbar. `strong_auth` entfällt — jede Sitzung
entsteht durch den Provider. `enrollment_only` entfällt.

---

## 5. Erstinbetriebnahme

```bash
export MMO_VAULT_DIR=/srv/mmo-vault        # optional
python mmo_vault.py setup
```

Fragt, mit Schaltern für den unbeaufsichtigten Lauf:

1. **Origin** — `https://vault.example`
2. **Primärer Provider** — Art (`microsoft` / `google`), Client-ID, Client-Secret,
   bei Microsoft der Tenant. Der Dienst nennt die einzutragende Redirect-URI:
   `{origin}/auth/oidc/{name}/callback`
3. **Initiale Administratoren** — E-Mail-Adressen, kommagetrennt. Werden als
   `allowlist`-Einträge mit `is_admin=true` für den primären Provider angelegt.
4. Erzeugt `secret_key`, schreibt alles in die Datenbank, legt `$MMO_VAULT_DIR/vaults/` an.

Ein zweiter Lauf verweigert, solange ein primärer Provider existiert. `--force`
ersetzt Provider-Zugangsdaten und ergänzt die Admin-Whitelist, löscht aber nichts.

`start` prüft: Datenbank erreichbar, Schema aktuell, Origin gesetzt, mindestens
ein aktivierter Provider, mindestens ein Admin auf der Whitelist. Fehlt etwas,
sagt es, was — statt eine Anmeldeseite ohne Knöpfe zu liefern.

Neu: **`python mmo_vault.py export-vault <id> [--generation N]`** schreibt den
Chiffretext eines Vaults auf stdout. Der Notfallweg, wenn der Provider nicht
erreichbar ist: Wer die Shell hat, bekommt die verschlüsselte Datei und öffnet
sie lokal mit dem Master-Passwort — der Dienst selbst kann sie nicht lesen.

---

## 6. Gruppen: lokal gepflegt oder vom Provider gespiegelt

Beides nebeneinander. Tabelle `group`, erweitert:

```
id (AUTOINCREMENT), name, description, source ('local' | 'provider'),
provider_id, external_id, last_synced_at
```

- **Lokale Gruppen** wie bisher: Admin legt an, weist Mitglieder zu, gibt Vaults frei.
- **Provider-Gruppen** entstehen durch Sync. Mitgliedschaft ist dort **nicht**
  editierbar — sie ist eine Kopie. Freigaben auf sie funktionieren wie auf lokale.

### 6.1 Sync beim Login, nicht im Hintergrund

Der Sync läuft **beim Login des Nutzers** mit dessen eigenem Access-Token. Das
hat einen Preis und einen Grund:

- **Grund:** Kein Service-Account, keine Directory-weiten Rechte, keine
  Hintergrund-Jobs. Der Dienst erfährt genau die Gruppen des Menschen, der sich
  gerade anmeldet, mit dessen Erlaubnis — nichts über andere.
- **Preis:** Eine Gruppenänderung beim Provider wirkt erst beim **nächsten
  Login**. Wer aus einer Gruppe fliegt, behält den Zugriff bis zum Sitzungsende
  (höchstens `session_hours`, Vorgabe 12 h). Ein Admin kann Sitzungen jederzeit
  widerrufen. Das gehört in die Doku, nicht unter den Teppich.

Ablauf: Nach dem Token-Austausch ruft der Dienst die Gruppen ab, legt fehlende
Provider-Gruppen an (Name vom Provider, `external_id` als stabile Kennung), und
**ersetzt** die Provider-Gruppenmitgliedschaften dieses Nutzers durch das
Ergebnis. Lokale Mitgliedschaften bleiben unberührt. Schlägt der Abruf fehl,
bleibt die letzte bekannte Mitgliedschaft stehen und es gibt einen
Audit-Eintrag — ein fehlgeschlagener Sync darf niemanden aussperren, aber auch
niemanden befördern.

Provider-Gruppen erscheinen in der Verwaltung erst, wenn sich ein Mitglied
angemeldet hat. Ein Admin, der vorher eine Freigabe setzen will, kann die Gruppe
nicht sehen — das ist die Kehrseite des Login-Zeit-Syncs und wird so benannt.

### 6.2 Microsoft 365

- Scope zusätzlich: `GroupMember.Read.All` (delegiert) — muss in der
  App-Registrierung freigegeben sein.
- Abruf: `GET https://graph.microsoft.com/v1.0/me/memberOf` mit Paging
  (`@odata.nextLink`). Nur Objekte vom Typ `#microsoft.graph.group`;
  Verzeichnisrollen werden ignoriert.
- Kennung: die Objekt-ID der Gruppe. Name: `displayName`.

### 6.3 Google

Nur **Google Workspace** hat Gruppen; ein privates Gmail-Konto hat keine — der
Sync ist dort schlicht leer.

- Scope: `https://www.googleapis.com/auth/cloud-identity.groups.readonly`
- Abruf: Cloud Identity API `groups/-/memberships:searchDirectGroups?query=member_key_id=='{email}'`
  — liefert die direkten Gruppen des angemeldeten Nutzers mit dessen eigenem Token.
- Kennung: der Gruppen-Ressourcenname. Name: `displayName`.

> **Zu verifizieren mit echtem Tenant:** ob `searchDirectGroups` für einen
> normalen Workspace-Nutzer ohne Admin-Rolle Ergebnisse liefert oder die
> Organisation das per Richtlinie sperrt. Falls Letzteres, bleibt für Google der
> Weg über einen Service-Account mit Domain-wide Delegation — der bräuchte dann
> doch einen Hintergrund-Sync. Das ist der eine Punkt dieses Plans, den ich
> nicht aus der Dokumentation heraus sicher zusagen kann.

### 6.4 Aus- und Abschalten

`sync_groups` ist pro Provider ein Schalter. Aus → keine Abfrage beim Login,
bestehende Provider-Gruppen bleiben eingefroren (Mitgliedschaften wie zuletzt
gesehen) und sind als „nicht mehr synchronisiert" markiert. Ein Admin kann sie
löschen; ihre Freigaben gehen wie bisher mit.

---

## 7. Anmeldeseite und Verwaltung

**Anmeldeseite:** nur noch Provider-Knöpfe, primärer oben. Kein Formular, kein
Passwortfeld. Ein abgewiesenes Konto sieht „Dieses Konto ist nicht
freigeschaltet" — ohne zu verraten, ob die Adresse irgendwo bekannt ist.

**Verwaltung** (`/admin`), Abschnitte:

1. **Provider** — anlegen (Art, Zugangsdaten, Tenant), Redirect-URI zum
   Kopieren, aktivieren/abschalten, `sync_groups`, primär setzen. Secret nur
   schreibbar.
2. **Whitelist** — je Provider: Adresse, Admin-Flag, Notiz. Anzeige, ob ein
   Konto dazu bereits existiert und wann es sich zuletzt angemeldet hat.
3. **Konten** — die gebundenen Konten: Name, Provider, Gruppen, letzte
   Anmeldung; Sitzungen widerrufen, Konto löschen. Anlegen gibt es hier nicht
   mehr — das macht die Whitelist.
4. **Gruppen** — lokale wie bisher; Provider-Gruppen mit Herkunft, letztem Sync
   und schreibgeschützter Mitgliederliste.
5. **Vaults** — unverändert.
6. **Einstellungen** — die Werte aus Kapitel 2, mit Hinweis, welche einen
   Neustart brauchen.

---

## 8. Sicherheitsaspekte, neu oder verschoben

- **Vertrauensanker ist der Provider.** Wer beim Provider die Adresse eines
  Whitelist-Eintrags kontrolliert, ist drin. Für einen eigenen Microsoft-Tenant
  oder eine Workspace-Domain ist das die gewollte Aussage. Für private
  Gmail-Adressen heißt es: die Sicherheit des Gmail-Kontos ist die Sicherheit des
  Vault-Zugangs.
- **Adressbestätigung ist providerspezifisch** (Kapitel 3). Ein `generic`-Provider,
  der `email_verified` nicht setzt, kann niemanden binden — das ist Absicht.
- **Ausfall des Providers = Ausfall der Anmeldung.** Es gibt keinen Ausweichweg,
  und es soll keinen geben. Der Notfall ist `export-vault` auf dem Server plus die
  lokale Datei.
- **Client-Secrets in der Datenbank** (Kapitel 2).
- **Gruppen-Sync ist nachlaufend** (Kapitel 6.1): Entzug einer Provider-Gruppe
  wirkt frühestens beim nächsten Login. Wer es sofort braucht, widerruft die
  Sitzung.
- **Rate-Limit** auf `/auth/oidc/*` gehört an den Proxy; der Dienst selbst hat
  nichts mehr, was man brute-forcen könnte.
- Unverändert: Injektion begrenzt und offengelegt, CSRF-Header, ETag vor
  Sperre, atomares Schreiben, IDs zählen nur aufwärts.

---

## 9. Datenbankmigration

Es gibt noch keinen produktiven Bestand — 2.0.0 ist getaggt, aber die manuellen
Abnahmen stehen aus. Trotzdem eine ordentliche Migration, keine neue Datenbank:

1. Tabelle `setting` anlegen; `config.toml` wird **einmalig eingelesen**, falls
   vorhanden, und ihre Werte übernommen. Danach wird die Datei nicht mehr
   beachtet; `setup --force` sagt das.
2. `provider`: Spalten `kind`, `tenant`, `is_primary`, `sync_groups` ergänzen.
   Bestehende Provider werden `generic`.
3. `allowlist` anlegen. Für jedes bestehende Konto mit `provider_id` und E-Mail
   entsteht ein Eintrag mit dessen Admin-Flag — niemand wird durch die Migration
   ausgesperrt.
4. `group`: `source`, `external_id`, `last_synced_at` ergänzen; Bestand wird `local`.
5. Löschen: `credential`, `backup_code`, `webauthn_challenge`; auf `user` die
   Passwort- und Enrollment-Spalten; auf `session` `enrollment_only` und
   `strong_auth`.
6. Konten **ohne** Provider-Bindung (reine Passwort/Passkey-Konten) bleiben als
   `is_active=false` stehen und werden im Admin-UI als „ohne Anmeldeweg"
   markiert — der Admin entscheidet, ob er sie per Whitelist wieder anbindet
   oder löscht.

---

## 10. Umsetzungsreihenfolge

| Phase | Inhalt | Prüfbar durch |
|---|---|---|
| 1 | `setting`-Tabelle, zwei Env-Variablen, `config.toml` raus, `setup` schreibt Datenbank | Setup ohne Datei; `start` verweigert ohne Origin/Provider/Admin |
| 2 | Provider-Arten, Whitelist, Login mit Kontoanlage, Admin-Flag aus Whitelist; Rückbau Passkeys/Passwort/enroll | gelistete Adresse kommt rein, ungelistete nicht; Admin-Entzug wirkt beim nächsten Login; Microsoft ohne `email_verified` bindet, `generic` ohne nicht |
| 3 | Admin-UI: Provider, Whitelist, Konten, Einstellungen | letzter Admin geschützt; Secret nie ausgegeben |
| 4 | Gruppen-Sync Microsoft (Graph), dann Google (Cloud Identity); Provider-Gruppen in UI | Login legt Gruppen an und ersetzt Mitgliedschaften; Fehlschlag sperrt nicht aus; Abschalten friert ein |
| 5 | `export-vault`, Migration mit Bestandsübernahme, README, requirements.md, Bedrohungsmodell | Migration gegen eine 2.0.0-Datenbank; Export liefert die Datei, die der Browser öffnet |

Version **2.1.0**. Das Betriebsmodell der Anmeldung ändert sich; Dateiformat, Client und Vault-API bleiben kompatibel.

---

## 11. Entscheidungen, die du treffen musst

1. **Passkeys komplett raus?** Der Plan sagt ja: mit OIDC als einzigem Weg wäre
   ein zweites Anmeldesystem Pflegeaufwand ohne Sicherheitsgewinn — den zweiten
   Faktor liefern Google und Microsoft. Wenn du sie als Ausweichweg bei
   Provider-Ausfall behalten willst, bleibt der ganze Bootstrap-Apparat
   (Einmalpasswort, Registrierungspflicht, SEC-46) bestehen — dann ist es kein
   Rückbau mehr, sondern ein Nebeneinander.
2. **Whitelist-Entzug: sofort oder beim nächsten Login?** Geplant ist „beim
   nächsten Login, plus Sitzungen widerrufbar". Sofortige Wirkung hieße, bei jeder
   Anfrage die Whitelist zu prüfen — machbar, ein Query pro Request.
3. **Google-Gruppen ohne Service-Account** — steht und fällt mit dem Punkt in
   6.3. Wenn der Tenant-Test negativ ausgeht, wird Google-Sync eine spätere
   Phase mit eigenem Hintergrundmechanismus.
4. **Domain-Whitelist** (`*@firma.de`) jetzt oder später? Geplant: später.
