# MMO Vault — Anforderungsspezifikation

**Version:** 2.1.0
**Stand:** 2026-08-30
**Status:** Im Eigenbetrieb freigegeben. Alle automatisiert prüfbaren Kriterien aus Kapitel 9 sind verifiziert; die verbleibenden erfordern manuelle Durchführung und stehen dort als unmarkierte Kästchen. Diese Zahl wird hier bewusst nicht wiederholt, damit sie nicht veraltet.
**Autor:** Michael Müller

---

## 1. Zweck und Geltungsbereich

MMO Vault ist ein Passwortmanager, der vollständig als **eine einzelne HTML-Datei** ausgeliefert wird und ausschließlich im Browser des Anwenders läuft. Er verwaltet Zugangsdaten, Freitext-Notizen, 2FA-Secrets und Dateianhänge in einer verschlüsselten Datei, die der Anwender selbst besitzt und ablegt.

Seit 2.0.0 gibt es **zwei Betriebsarten**:

| Betriebsart | Was |
|---|---|
| **Lokal** | Die Datei per Doppelklick im Browser. Ohne Server, ohne Installation, ohne Netzwerkzugriff. Ein Auslieferungs-Webserver ist keine eigene Betriebsart: wer die Datei über das Netz bereitstellt, liefert dieselbe Datei aus, die auch lokal läuft. |
| **Server** | Ein FastAPI-Dienst mit Anmeldung über einen Identity Provider (OIDC), Allowlist, Gruppen, geteilten Vaults und Dateihistorie. Er liefert dieselbe HTML-Datei aus und legt die Vault-Dateien ab. Seit 2.1.0 ohne eigene Benutzerverwaltung: Identität kommt vom Provider, Konfiguration liegt in der Datenbank. |

Der Server ist **Ablage und Zugriffskontrolle**, nicht Kryptografie. Verschlüsselt und entschlüsselt wird ausschließlich im Browser; Master-Passwort und Schlüssel erreichen ihn nie.

Das Dokument beschreibt den Funktions- und Qualitätsumfang der Version 2.1.0. Es richtet sich an Entwicklung, Review und Abnahme.

### 1.1 Nicht im Geltungsbereich

Ausdrücklich **nicht** Bestandteil dieser Version:

- Cloud-Anbindung an fremde Dienste, automatische Synchronisation zwischen Geräten
- Serverseitige Entschlüsselung, Suche oder Vorschau — der Dienst sieht ausschließlich Chiffretext
- Wiederherstellung des Master-Passworts über den Server
- Zusammenführen paralleler Änderungen an einer Vault-Datei
- Browser-Erweiterung, Autofill in fremden Seiten, Zwischenablage-Überwachung
- Direkter Import der proprietären Exportformate anderer Passwortmanager (KeePass-XML, 1Password-1PUX). Ein CSV-Import mit festen Spaltennamen ist seit 1.7.0 enthalten (FUN-65 ff.); Exporte anderer Werkzeuge müssen vorher auf diese Spaltennamen gebracht werden.
- Export in irgendein Format
- Ablaufdatum je Eintrag, Breach-Abgleich
- HOTP (zählerbasierte Einmalpasswörter)
- Automatische Backup-Rotation oder Versionierung der Vault-**Datei** als Ganzes. Versionen einzelner **Datensätze** sind seit 2.0.0 enthalten (FUN-73 ff.).
- Automatisches Aufräumen alter Versionen. Nichts verfällt von selbst; gelöscht wird ausschließlich von Hand (FUN-82).

---

## 2. Begriffe

| Begriff | Bedeutung |
|---|---|
| **Vault** | Die Gesamtheit der verschlüsselten Nutzdaten, gespeichert in einer Vault-Datei |
| **Vault-Datei** | Datei im Format `mmo-vault-v3` (NDJSON), Endung `.json` |
| **Master-Passwort** | Das einzige Geheimnis, aus dem der Verschlüsselungsschlüssel abgeleitet wird |
| **Eintrag** | Ein Datensatz vom Typ *Zugang* oder *Freitext* |
| **Block** | Eine Zeile der Vault-Datei; `header`, `text`, `vers` oder `file` |
| **Version** | Ein aufgehobener Stand eines Eintrags von **vor** einer Änderung |
| **Grabstein** | Der Vermerk im `versionIndex`, der einen gelöschten Eintrag im Papierkorb auffindbar macht |
| **FSA** | File System Access API (`showOpenFilePicker`, `showSaveFilePicker`) |
| **Dienst** | Der Serverbetrieb: FastAPI, Datenbank, Vault-Ablage |
| **Gruppe** | Zusammenfassung von Konten, an die ein Vault freigegeben werden kann |
| **Provider** | Ein externer Identitätsanbieter nach OIDC |
| **Generation** | Ein aufbewahrter Stand einer ganzen Vault-Datei auf dem Server |
| **Sitzung** | Anmeldung am Dienst; unabhängig davon, ob ein Vault entsperrt ist |
| **Injektion** | Die zwei Änderungen, die der Dienst beim Ausliefern an der HTML-Datei vornimmt |
| **Sperren** | Verwerfen aller Klartextdaten aus dem Speicher und Rückkehr zum Sperrbildschirm |

Schlüsselwörter nach RFC 2119: **MUSS**, **SOLL**, **KANN**.

---

## 3. Sicherheitsanforderungen

Diese Kapitel hat Vorrang vor allen funktionalen Anforderungen. Ein Konflikt wird zugunsten der Sicherheitsanforderung aufgelöst.

### 3.1 Kryptografie

| ID | Anforderung |
|---|---|
| SEC-01 | Nutzdaten MÜSSEN mit **AES-256-GCM** verschlüsselt werden. Implementierung ausschließlich über die native `crypto.subtle`-API des Browsers; eigene Krypto-Primitive sind unzulässig. |
| SEC-02 | Der Schlüssel MUSS per **PBKDF2-HMAC-SHA256** mit **600.000 Iterationen** aus dem Master-Passwort abgeleitet werden (OWASP-Empfehlung 2023 ff.). |
| SEC-03 | Das Salt MUSS 16 kryptografisch zufällige Bytes umfassen und bei jedem Passwortwechsel neu erzeugt werden. |
| SEC-04 | Jeder verschlüsselte Block MUSS einen eigenen, zufälligen 96-Bit-IV erhalten. Eine IV-Wiederverwendung unter demselben Schlüssel ist unzulässig. |
| SEC-05 | Der abgeleitete Schlüssel MUSS als `extractable: false` importiert werden und darf den Speicher nie als Rohmaterial verlassen. |
| SEC-06 | Alle Zufallswerte MÜSSEN aus `crypto.getRandomValues()` stammen. `Math.random()` ist für sicherheitsrelevante Zwecke unzulässig. |
| SEC-07 | Der Passwortgenerator MUSS gleichverteilt über das gewählte Alphabet ziehen. Modulo-Bias MUSS durch Rejection Sampling ausgeschlossen sein. |
| SEC-08 | Beim Laden einer Datei MÜSSEN Salt (8–64 Byte) und Iterationszahl (ganzzahlig, 1.000–5.000.000) plausibilisiert werden, bevor sie in die Schlüsselableitung eingehen. |
| SEC-09 | Wird eine Datei mit weniger als 600.000 Iterationen geöffnet, MUSS der Vault unmittelbar nach dem Entsperren auf den aktuellen Standard gehoben und als ungespeichert markiert werden. |
| SEC-10 | Der verschlüsselte Klartext eines Dateianhangs MUSS dessen ID enthalten, damit das Vertauschen zweier Blöcke beim Laden auffällt. |

**Bekannte Grenze:** Der Header-Block (Format, Salt, Iterationen) ist nicht authentifiziert und geht nicht als *Additional Authenticated Data* in AES-GCM ein. Eine Manipulation führt zum Fehlschlag der Entschlüsselung, nicht zur Preisgabe von Klartext. Eine echte AAD-Bindung würde das Dateiformat brechen und ist für v2.0 vorgesehen.

### 3.2 Umgang mit Klartext im Speicher

| ID | Anforderung |
|---|---|
| SEC-11 | Beim Sperren MÜSSEN Schlüssel, Salt, Iterationszahl, Einträge, Verlauf, Anhangsblöcke, Datei-Handle und TOTP-Cache verworfen werden. |
| SEC-12 | Beim Sperren MÜSSEN **alle** modalen Dialoge geschlossen und ihre Eingabefelder geleert werden. Ein offener Eintrags-Dialog darf nicht über dem Sperrbildschirm stehen bleiben. |
| SEC-13 | Beim Sperren MÜSSEN aufgedeckte Passwörter und entschlüsselte Werte aus dem DOM entfernt werden (Kartenraster, Verlaufsliste, Tag-Leiste, Suchfeld). |
| SEC-14 | Kopierte **Geheimnisse** (Passwort, 2FA-Code) MÜSSEN nach 30 Sekunden aus der Zwischenablage entfernt werden. Nicht-geheime Werte (URL, Benutzername) DÜRFEN NICHT automatisch gelöscht werden, um fremde Kopier-Inhalte nicht zu überschreiben. |
| SEC-15 | Das Master-Passwort DARF NICHT über den Ableitungsvorgang hinaus gehalten werden. |
| SEC-31 | Versionen sind Geheimnisse: sie MÜSSEN in denselben AES-256-GCM-Blöcken liegen wie die Einträge, beim Sperren aus Speicher und DOM verschwinden und beim Master-Passwort-Wechsel vollständig neu verschlüsselt werden. Die Abgrenzung zu SEC-26 ist wesentlich: der Änderungsverlauf bleibt geheimnisfrei, Versionen sind es ausdrücklich nicht. |
| SEC-32 | Das Löschen von Versionen MUSS sofort wirken: alle Blöcke laden, die betroffenen Stände entfernen, den Rest beim nächsten Speichern neu schreiben. Ein Löschen, das erst später greift, wäre bei alten Passwörtern die falsche Zusage. |

**Bekannte Grenze:** JavaScript erlaubt kein deterministisches Nullsetzen von Strings. Klartext kann bis zur nächsten Garbage Collection im Heap verbleiben. Gegen einen Angreifer mit Speicherzugriff auf dem laufenden Gerät schützt die Anwendung nicht (siehe Bedrohungsmodell).

### 3.3 Auto-Sperre

| ID | Anforderung |
|---|---|
| SEC-16 | Der Vault MUSS nach einer einstellbaren Zeit ohne Nutzeraktivität automatisch gesperrt werden. Vorgabe: 5 Minuten. |
| SEC-17 | Wählbar MÜSSEN sein: 1, 5, 10, 15, 30 Minuten sowie „Nie". Die Einstellung wird mitverschlüsselt in der Vault-Datei abgelegt. |
| SEC-18 | Die verbleibende Zeit MUSS in der Kopfleiste sekundengenau angezeigt und in den letzten 30 Sekunden visuell hervorgehoben werden. |
| SEC-19 | Tastatur-, Maus- und Touch-Aktivität MUSS den Timer zurücksetzen. |

### 3.4 Ausführungsumgebung

| ID | Anforderung |
|---|---|
| SEC-20 | Die ausgelieferte Datei DARF KEINE Netzwerkverbindung aufbauen. Dies MUSS per Content-Security-Policy erzwungen werden, nicht nur zugesichert: `default-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'`. Die Datei DARF weder eine URL noch einen `fetch`-Aufruf enthalten. |
| SEC-20a | Im Serverbetrieb DARF die Aufweichung auf `connect-src 'self'` **ausschließlich in der ausgelieferten Kopie** erfolgen. Die Datei auf dem Datenträger MUSS unverändert bleiben, damit sie heruntergeladen und offline mit unveränderter Zusage weiterverwendet werden kann. |
| SEC-20b | Die Injektion MUSS auf genau zwei Stellen begrenzt sein — die CSP-Direktive und ein Skriptblock — und MUSS im Klartext abrufbar sein (`GET /api/injection`). Schlägt die Erkennung dieser Stellen fehl, MUSS die Auslieferung mit einem Fehler abbrechen, statt eine Anwendung ohne Adapter zu liefern. |
| SEC-21 | Es DÜRFEN KEINE externen Ressourcen eingebunden werden — keine CDN-Skripte, Stylesheets, Web Fonts oder Bilder. |
| SEC-22 | Es DARF KEINE Telemetrie, Fehlerübermittlung oder Nutzungsstatistik stattfinden. |
| SEC-23 | Nutzergesteuerte Inhalte (Titel, Benutzername, Notizen, Tags, Anhangsnamen, Verlaufsdetails) MÜSSEN per `textContent` in das DOM geschrieben werden, nie per `innerHTML`. |
| SEC-24 | Gespeicherte URLs DÜRFEN nur mit den Schemata `http` und `https` geöffnet werden. Alle anderen — insbesondere `javascript:` — MÜSSEN abgewiesen werden. |
| SEC-25 | Externe Links MÜSSEN mit `noopener,noreferrer` geöffnet werden. |
| SEC-26 | Der Änderungsverlauf DARF nur Zeitstempel, Aktionstyp und Eintragstitel enthalten — nie Passwörter, Benutzernamen, URLs oder 2FA-Secrets. |
| SEC-27 | Wird die Anwendung über einen Webserver ausgeliefert, MUSS die Übertragung per TLS erfolgen. Browser stellen `crypto.subtle` nur in einem *Secure Context* bereit; über `http://` auf einer anderen Adresse als `localhost` fehlt die Web-Crypto-API vollständig. |
| SEC-28 | Fehlt der Secure Context, MUSS die Anwendung dies beim Laden erkennen, verständlich melden und die Bedienelemente zum Anlegen und Entsperren sperren — statt später mit einem Laufzeitfehler abzubrechen. |
| SEC-29 | Ein ausliefernder Server MUSS `frame-ancestors 'none'` als HTTP-Header setzen. Im `<meta>`-Tag wird die Direktive vom Browser ignoriert und ist dort nicht durchsetzbar. |
| SEC-30 | Ein Container-Abbild DARF keine Dokumentation, keine Tests, keine Konfiguration mit Geheimnissen, keine Datenbank und unter keinen Umständen eine Vault-Datei enthalten. Der Dienstcode gehört hinein, das Datenverzeichnis kommt als Volume dazu. |

### 3.4a Serverbetrieb: Anmeldung und Zugriff

| ID | Anforderung |
|---|---|
| SEC-33 | Das **einzige** Anmeldeverfahren ist OIDC gegen einen konfigurierten Provider. Der Dienst DARF KEINE eigenen Anmeldegeheimnisse führen — keine Passwörter, keine Passkeys, keine Ersatzcodes, kein zweiter Faktor. MFA, Gerätebindung und Offboarding sind Sache des Providers. |
| SEC-34 | Die Identität eines Kontos ist `(provider, sub)`. Sie wird bei der **ersten** Anmeldung gebunden und danach nie über die Mailadresse geändert; eine geänderte Adresse beim Provider aktualisiert das Konto, erzeugt aber kein zweites. |
| SEC-35 | Wer hinein darf, bestimmt eine **Allowlist pro Provider**: Mailadresse plus Administrator-Flag. Es DARF KEINE Selbstregistrierung geben. Ein Konto entsteht ausschließlich durch die erste erfolgreiche Anmeldung einer gelisteten Adresse. |
| SEC-36 | Die Mailadresse DARF nur verifiziert gegen die Allowlist geprüft werden: bei generischen Providern und Google über `email_verified`, bei Microsoft über die Übereinstimmung von `tid` mit dem konfigurierten Tenant (Microsoft setzt `email_verified` nicht). Eine unverifizierte Adresse bindet nichts. |
| SEC-37 | Das Administrator-Flag MUSS bei **jeder** Anmeldung aus der Allowlist übernommen werden. Das Entfernen von der Liste oder das Entziehen des Flags MUSS die Sitzungen des Kontos sofort beenden und das Konto deaktivieren bzw. herabstufen — nicht erst beim nächsten Login. |
| SEC-38 | Ein Microsoft-Provider MUSS einen konkreten Tenant tragen. Die offenen Aliasse `common`, `organizations` und `consumers` MÜSSEN abgewiesen werden: eine Adresse ist nur vertrauenswürdig, wenn der eigene Tenant sie verwaltet. |
| SEC-39 | Der Dienst liest genau **zwei** Umgebungsvariablen: `MMO_VAULT_DIR` und `MMO_VAULT_DATABASE_URL`. Alles Weitere — Origin, Provider samt Client-Secret, Allowlist, Sitzungsdauern, Grenzen, der Signaturschlüssel für den OIDC-State — MUSS in der Datenbank liegen. Es gibt keine Konfigurationsdatei. |
| SEC-40 | Ohne Origin, ohne aktivierten Provider oder ohne gelisteten Administrator DARF der Dienst nicht starten; er MUSS benennen, was fehlt. Der Origin MUSS `https` sein (Ausnahme: `localhost`). |
| SEC-41 | Sitzungen MÜSSEN serverseitig gehalten und damit widerrufbar sein. Das Deaktivieren eines Kontos MUSS seine Sitzungen sofort beenden. |
| SEC-42 | Zustandsändernde Endpunkte MÜSSEN zusätzlich zu `SameSite=Lax` den Header `X-Vault-Request` verlangen. |
| SEC-43 | Der Dienst DARF Vault-Inhalte nur strukturell prüfen — Header, parsbare Zeilen, Größe. Niemals den Inhalt. |
| SEC-44 | Das Client-Secret eines Providers DARF nach dem Anlegen nicht mehr ausgegeben werden, auch nicht an Administratoren. Der primäre Provider DARF weder deaktiviert noch gelöscht werden; ein Provider mit Konten oder Allowlist-Einträgen DARF NICHT gelöscht werden. |
| SEC-45 | Der letzte Administrator-Eintrag der Allowlist DARF weder herabgestuft noch entfernt werden. |
| SEC-46 | Der Gruppen-Sync läuft mit dem **eigenen Access-Token des Nutzers** beim Login — kein Service-Account, keine verzeichnisweiten Rechte, kein Hintergrundjob. Ein fehlgeschlagener Abruf DARF NICHTS ändern: weder aussperren noch befördern; die letzte bekannte Mitgliedschaft bleibt und der Fehlschlag wird protokolliert. |
| SEC-47 | Gespiegelte Gruppen werden über ihre externe Kennung identifiziert, nicht über den Namen. Kollidiert ein Provider-Gruppenname mit einer lokalen Gruppe, MUSS der Spiegel einen eindeutigen Namen erhalten — Freigaben adressieren Gruppen über den Namen, ein Doppel wäre mehrdeutig. Die Mitgliedschaft eines Spiegels DARF NICHT von Hand editierbar sein. |
| SEC-48 | Die Migration von 2.0.0 MUSS gebundene OIDC-Konten mit ihrem Administrator-Flag in die Allowlist übernehmen, Konten ohne Provider deaktivieren, alle Sitzungen beenden und die Credential-Tabellen (Passkeys, Ersatzcodes, Challenges) entfernen. Eine vorhandene `config.toml` wird einmalig in die Datenbank importiert. |

Entfallen seit 2.1.0: die früheren SEC-33 bis SEC-39 und SEC-46 (Passkeys, Passwort-Bootstrap, Argon2, Loopback-Ausnahme, Fehlversuchszähler, Frische der Sitzung für weitere Passkeys). Sie haben kein Gegenstück mehr, weil der Dienst keine Anmeldegeheimnisse mehr führt.

### 3.5 Bedrohungsmodell

**Wogegen die Anwendung schützt:**

- Verlust oder Diebstahl der Vault-Datei (Cloud-Speicher, USB-Stick, Backup-Band, E-Mail-Anhang). Ohne Master-Passwort sind die Daten nicht verwertbar.
- Neugierige Mitleser am unbeaufsichtigten Bildschirm (Auto-Sperre, maskierte Passwörter, Zwischenablage-Löschung).
- Manipulation der Vault-Datei: jede Änderung am Chiffrat führt zum Fehlschlag der GCM-Authentifizierung.

**Wogegen die Anwendung ausdrücklich nicht schützt:**

- Kompromittiertes Endgerät: Keylogger, Screen Scraper, Malware mit Prozessspeicherzugriff, manipulierter Browser oder manipulierte Browser-Erweiterungen.
- Schwaches oder wiederverwendetes Master-Passwort. Die Iterationszahl erhöht die Kosten eines Offline-Angriffs, sie ersetzt keine Passwortstärke.
- Manipulation der HTML-Datei selbst. Wer die Anwendungsdatei austauschen kann, kann beliebigen Code ausführen. Die Datei SOLL aus vertrauenswürdiger Quelle stammen und schreibgeschützt abgelegt werden.
- Verlust des Master-Passworts. Es gibt **keine** Wiederherstellung, keine Hintertür, kein Reset.
- **Serverbetrieb:** Wer den Dienst kontrolliert, kann Vault-Dateien löschen, zurückrollen oder durch ältere Generationen ersetzen — und beliebigen Code in die ausgelieferte Anwendung injizieren. Lesen kann er die Vault-Dateien nicht. Verfügbarkeit und Integrität hängen damit am Server, Vertraulichkeit weiterhin allein am Master-Passwort. Wer den höchsten Anspruch hat, nutzt die lokale Datei.
- **Identity Provider:** Wer den Provider kontrolliert, kann sich als jede gelistete Adresse anmelden — der Dienst vertraut dem Wort des Providers. Das ist der bewusste Tausch: eine Stelle für Identität, MFA und Offboarding statt eines zweiten Satzes Zugangsdaten, der verloren gehen kann. Fällt der Provider aus, ist der *Dienst* nicht erreichbar, die Daten schon: `export-vault` liefert jede Datei als NDJSON, die sich mit der lokalen Anwendung öffnen lässt.
- **Gruppen-Sync ist nachlaufend:** Eine Gruppenänderung beim Provider wirkt beim nächsten Login. Wer aus einer Gruppe entfernt wird, behält den Zugriff bis zum Sitzungsende (höchstens `session_hours`, Vorgabe 12 h) — oder bis ein Administrator die Sitzung widerruft.
- **Geteilte Vaults:** Alle Schreibberechtigten kennen dasselbe Master-Passwort. Der Entzug einer Freigabe nimmt den Zugriff auf den Dienst, **nicht** die Kenntnis des Passworts. Nach einem Entzug gehört das Master-Passwort gewechselt.
- **Zugang über den Server:** Wer Shell-Zugang zum Server hat, kann sich über `setup --force` selbst auf die Allowlist setzen oder mit `export-vault` jede Datei ziehen. Das ist beabsichtigt und unvermeidbar — wer den Server kontrolliert, kontrolliert den Dienst. Lesen kann er die Dateien trotzdem nicht.
- Die Dateisperre ist beratend und keine Sicherheitsgrenze. Sie schützt vor versehentlichem Parallelbearbeiten, nicht vor einem böswilligen Client.
- Die verlängerte Lebensdauer abgelöster Geheimnisse. Ein gewechseltes Passwort bleibt im Verlauf lesbar — das ist der Zweck der Versionierung, erhöht aber den Schaden einer preisgegebenen Vault-Datei. Wer das nicht will, verwirft die betroffenen Versionen (FUN-82) oder schaltet die Historie über das Löschen ab.

---

## 4. Funktionale Anforderungen

### 4.1 Vault-Verwaltung

| ID | Anforderung |
|---|---|
| FUN-01 | Der Anwender MUSS einen neuen Vault mit Master-Passwort anlegen können. Mindestlänge: 8 Zeichen, Bestätigungseingabe erforderlich. |
| FUN-02 | Eine visuelle Stärkeanzeige SOLL das Passwort bewerten. Sie ist Hinweis, keine Sperre. |
| FUN-03 | Eine vorhandene Vault-Datei MUSS über Dateiauswahl geladen und mit dem Master-Passwort entsperrt werden können. |
| FUN-04 | Bei verfügbarer FSA MUSS die zuletzt genutzte Datei per Verknüpfung wieder öffenbar sein, ohne sie erneut auszuwählen. Es wird das Handle gespeichert, nie der Inhalt. |
| FUN-05 | Die Verknüpfung MUSS manuell entfernbar sein und MUSS automatisch entfernt werden, wenn die Datei nicht mehr lesbar ist (typisch bei Cloud-Sync-Ordnern). |
| FUN-06 | Der Vault MUSS jederzeit manuell sperrbar sein. |
| FUN-07 | Das Master-Passwort MUSS änderbar sein. Das alte Passwort ist zu verifizieren; der Vault wird vollständig mit neuem Salt neu verschlüsselt. |
| FUN-08 | Vor einem Schlüsselwechsel MÜSSEN alle noch nicht geladenen Anhänge mit dem alten Schlüssel entschlüsselt werden, damit beim Neuverschlüsseln nichts verloren geht. |

### 4.2 Einträge

| ID | Anforderung |
|---|---|
| FUN-09 | Es MUSS die Typen **Zugang** (Titel, URL, Benutzername, Passwort, 2FA, Notizen) und **Freitext** (Titel, Inhalt) geben. |
| FUN-10 | Einträge MÜSSEN anlegbar, bearbeitbar und löschbar sein. Löschen MUSS bestätigt werden. |
| FUN-11 | Ein Titel MUSS Pflichtfeld sein. |
| FUN-12 | Einträge MÜSSEN frei mit Tags versehbar sein. Tags MÜSSEN als Filterleiste erscheinen, sobald mindestens einer vergeben ist. |
| FUN-13 | Eine Volltextsuche MUSS über Titel, Benutzername, Notizen und Tags laufen. |
| FUN-14 | Ein Typfilter MUSS die Liste auf einen Eintragstyp einschränken. |
| FUN-15 | Passwörter MÜSSEN in der Übersicht maskiert und einzeln aufdeckbar sein. |
| FUN-16 | URL, Benutzername, Passwort und 2FA-Code MÜSSEN einzeln in die Zwischenablage kopierbar sein. |
| FUN-17 | Bei leerem Ergebnis MUSS unterschieden werden zwischen „noch keine Einträge angelegt" und „Suche/Filter ohne Treffer". |
| FUN-17a | Jeder Eintrag MUSS eine kurze, fortlaufende Nummer tragen, die bei der Anlage vergeben wird und **nie wiederverwendet** wird. Der Zähler wird mitverschlüsselt gespeichert; das Maximum der vorhandenen Nummern zu nehmen wäre unzulässig, weil nach dem Löschen des höchsten Eintrags ein gespeicherter Verweis auf einen anderen Eintrag zeigen würde. |
| FUN-17b | Einträge aus Dateien ohne Nummern MÜSSEN beim Entsperren welche erhalten, in Anlagereihenfolge, und der Vault MUSS dabei als ungespeichert markiert werden. |
| FUN-17c | Die Nummer MUSS auf der Karte sichtbar sein und beim Antippen den zugehörigen Suchausdruck in die Zwischenablage legen. |
| FUN-17d | Die Suche MUSS Feldfilter der Form `schlüssel=wert` unterstützen, mindestens `id`, `tag`, `typ`, `benutzer`, `titel`. Mehrere Filter und freie Begriffe verknüpfen mit UND, ebenso mit den Filter-Chips. Ein unbekannter Schlüssel MUSS als Volltext behandelt werden, damit nichts stillschweigend wegfällt. |
| FUN-17e | `id=` MUSS sowohl die fortlaufende Nummer (mit und ohne `#`) als auch die interne ID akzeptieren. |
| FUN-17j | Feldwerte MÜSSEN in Anführungszeichen (einfach oder doppelt) stehen dürfen, damit Werte mit Leerzeichen möglich sind. Ein Zitat ohne Schlüssel ergibt eine Phrasensuche. |
| FUN-17k | Ein nicht geschlossenes Anführungszeichen DARF die Suche nicht stören. Die Suche läuft bei jedem Tastendruck; während des Tippens ist das Zitat zwangsläufig eine Zeit lang offen. |
| FUN-17f | Ein Suchausdruck KANN über das Adress-Fragment `#search=…` vorbelegt werden. Er MUSS ausschließlich das Suchfeld füllen — kein Entsperren, kein Öffnen eines Eintrags, nichts Zustandsänderndes. Nach dem Anwenden MUSS er aus der Adresse entfernt werden. |
| FUN-17g | Für diesen Zweck DARF KEIN Query-String verwendet werden. Query-Strings werden an den Server übertragen und landen im Zugriffsprotokoll; ein Suchbegriff ist hier typischerweise ein Kontoname. Fragmente werden nie gesendet. |
| FUN-17h | Ein Eintrag MUSS duplizierbar sein. Das Duplikat MUSS eine neue ID und Nummer erhalten und **eigene Anhangs-IDs mit eigenen Kopien der Rohdaten**. Gemeinsam genutzte Anhangs-IDs sind unzulässig, weil beide Einträge dann auf denselben verschlüsselten Block zeigen und das Löschen des einen den anderen beeinflusst. |
| FUN-17i | Scheitert das Entschlüsseln eines Anhangs beim Duplizieren, DARF kein Teil-Duplikat entstehen. |

### 4.3 Zwei-Faktor-Authentifizierung

| ID | Anforderung |
|---|---|
| FUN-18 | Zeitbasierte Einmalpasswörter MÜSSEN nach **RFC 6238** erzeugt werden, mit dynamischer Truncation nach RFC 4226. |
| FUN-19 | Die Parameter **Stellenzahl** (6–10), **Periode** (5–300 s) und **Algorithmus** (SHA-1, SHA-256, SHA-512) MÜSSEN je Eintrag gespeichert und verwendet werden. Vorgabe: 6 / 30 s / SHA-1. |
| FUN-19a | Wird das 2FA-Secret von Hand geändert, MÜSSEN die Parameter aus FUN-19 auf die Standardwerte zurückfallen. Ein anderes Secret gehört zu einem anderen Konto; die Parameter eines früheren QR-Imports würden sonst still falsche Codes erzeugen. |
| FUN-20 | Der aktuelle Code MUSS mit einem Fortschrittsring bis zum Ablauf der Periode angezeigt werden. |
| FUN-21 | Ein Secret MUSS als Base32 manuell eingebbar sein. |
| FUN-22 | Ein `otpauth://totp/…`-QR-Code MUSS als Bilddatei importierbar sein (Klick oder Drag & Drop) — über die native `BarcodeDetector`-API, ohne externe Bibliothek. |
| FUN-23 | Beim QR-Import MÜSSEN Secret, Aussteller, Konto **und** die Parameter aus FUN-19 übernommen werden. Abweichende Parameter MÜSSEN im Dialog sichtbar sein. |
| FUN-24 | `otpauth://hotp/…` MUSS mit verständlicher Meldung abgewiesen werden. |

### 4.4 Dateianhänge

| ID | Anforderung |
|---|---|
| FUN-25 | An jeden Eintrag MÜSSEN beliebig viele Dateien anhängbar sein. |
| FUN-26 | Anhänge MÜSSEN in eigenen, separat verschlüsselten Blöcken abgelegt werden, getrennt vom Textblock. |
| FUN-27 | Anhänge DÜRFEN beim Entsperren **nicht** entschlüsselt werden, sondern erst beim tatsächlichen Herunterladen. |
| FUN-28 | Unveränderte Anhänge MÜSSEN beim Speichern unverändert übernommen werden, ohne Neuverschlüsselung. |
| FUN-29 | Nicht mehr referenzierte Blöcke MÜSSEN beim Speichern entfernt werden. |
| FUN-30 | Ab 8 MB SOLL vor der Größenwirkung auf die Vault-Datei gewarnt werden. Eine harte Grenze gibt es nicht. |

### 4.5 Speichern

| ID | Anforderung |
|---|---|
| FUN-31 | Bei verfügbarer FSA MUSS direkt in die geöffnete Datei geschrieben werden. Andernfalls MUSS ein Download erfolgen. |
| FUN-32 | Ungespeicherte Änderungen MÜSSEN am Speichern-Symbol markiert werden. |
| FUN-33 | Beim Sperren mit ungespeicherten Änderungen MUSS zwischen *Speichern & Sperren*, *ohne Speichern sperren* und *Abbrechen* gewählt werden können. |
| FUN-34 | Beim Verlassen der Seite mit ungespeicherten Änderungen MUSS der Browser-Warnhinweis ausgelöst werden. |
| FUN-35 | **Ein abgebrochener Speichern-Dialog DARF KEINEN Download auslösen** und MUSS den Zustand „ungespeichert" erhalten. |
| FUN-36 | Nach dem Schreiben MUSS die Datei zurückgelesen, byteweise verglichen und erneut geparst werden. |
| FUN-37 | Schlägt Schreiben oder Verifikation fehl, MUSS der vorherige Dateiinhalt wiederhergestellt und der Zustand „ungespeichert" beibehalten werden. |
| FUN-38 | „Ungespeichert" DARF erst zurückgesetzt werden, wenn das Schreiben bestätigt ist. Folgeaktionen (Sperren, Melden eines Passwortwechsels) MÜSSEN sich auf dieses Ergebnis stützen. |
| FUN-39 | Scheitert das Speichern nach einem Passwortwechsel, MUSS ausdrücklich darauf hingewiesen werden, dass die Datei noch das alte Passwort trägt. |
| FUN-39a | Scheitert das Schreiben in die verknüpfte Datei, MUSS die Anwendung einen Ausweg anbieten: die Daten als Download sichern oder einen anderen Speicherort wählen. Ohne das lägen die Änderungen nur noch im Speicher. |
| FUN-39b | Dieser Ausweg MUSS als Rückfrage erscheinen und DARF NICHT ungefragt herunterladen. Der Grund des Fehlschlags MUSS im Dialog stehen. |
| FUN-39c | Wird „anderen Speicherort" gewählt, MUSS das bisherige Datei-Handle verworfen werden. Ein durch einen Sync-Client ersetztes Handle bleibt sonst dauerhaft unbrauchbar. Das Verwerfen gilt nur vorläufig: bricht der Anwender die Ortsauswahl ab, MUSS die bestehende Verknüpfung erhalten bleiben. |
| FUN-39d | Jeder Weg, der den Rückfalldialog schließt — Schaltfläche, Escape, Sperren — MUSS die wartende Speicheroperation auflösen. Ein offenes Versprechen ließe den Aufrufer endlos warten. |

### 4.6 Änderungsverlauf

| ID | Anforderung |
|---|---|
| FUN-40 | Protokolliert werden MÜSSEN: Vault angelegt, Eintrag erstellt/bearbeitet/gelöscht, Master-Passwort geändert, Auto-Sperre geändert, Schlüsselableitung aktualisiert. |
| FUN-41 | Der Verlauf MUSS auf die letzten 300 Einträge begrenzt und mitverschlüsselt gespeichert werden. |
| FUN-42 | Die Anzeige MUSS absteigend nach Zeit sortiert und lokalisiert formatiert sein. |

### 4.7 Oberfläche

| ID | Anforderung |
|---|---|
| FUN-43 | Die Oberfläche MUSS vollständig in Deutsch und Englisch verfügbar sein, jederzeit umschaltbar. Dies gilt **einschließlich aller Fehler-, Status- und Hinweismeldungen**. |
| FUN-44 | Das Layout MUSS von 320 px bis Desktop nutzbar sein. Unter 900 px MÜSSEN die Werkzeuge der Kopfleiste in ein Menü wandern, das als Bottom Sheet erscheint. |
| FUN-45 | Ein Passwortgenerator MUSS Länge (8–48) und Sonderzeichen einstellbar anbieten. Optisch verwechselbare Zeichen (`l`, `I`, `O`, `0`, `1`) MÜSSEN ausgeschlossen sein. |
| FUN-46 | Modale Dialoge MÜSSEN per **Escape** schließbar sein. Dialoge ohne Eingabefelder MÜSSEN zusätzlich per Klick auf den Hintergrund schließbar sein. |
| FUN-47 | Jedes Eingabefeld MUSS ein zugeordnetes Label oder ein `aria-label` besitzen; Dialoge MÜSSEN `role="dialog"` und `aria-modal` tragen. |
| FUN-48 | `prefers-reduced-motion` MUSS respektiert werden. |
| FUN-49 | Auf Touch-Geräten (unter 560 px) MÜSSEN alle Bedienelemente mindestens 36 px in der kleineren Kante messen, Kopfleisten- und Dialogschaltflächen mindestens 44 px. Ein natives Kontrollelement DARF kleiner sein, wenn eine umgebende Beschriftung die Trefferfläche auf dieses Maß bringt. |
| FUN-50 | Unter 560 px MUSS die Suche eine eigene Zeile über die volle Breite erhalten. Nebeneinander mit Dateiname und Menü bleibt zu wenig Platz für eine brauchbare Eingabe. |
| FUN-51 | Eingabefelder MÜSSEN auf Touch-Geräten mindestens 16 px Schriftgröße haben, damit iOS beim Fokussieren nicht in die Seite zoomt. |
| FUN-52 | Die Kopfleiste MUSS links eine Bildmarke tragen, die auch dann sichtbar bleibt, wenn der Schriftzug auf schmalen Bildschirmen entfällt. |

### 4.9 Entsperren und CSV-Import

| ID | Anforderung |
|---|---|
| FUN-62 | Das Entsperr-Feld MUSS in einem echten `<form>` mit Absende-Ereignis und einem Kennungsfeld liegen, damit Passwortmanager das Master-Passwort anbieten können. Die Anwendung selbst speichert dabei nichts; ob und wo gespeichert wird, entscheidet allein der Browser bzw. der Anwender. |
| FUN-63 | Das Absenden MUSS unterbunden werden (`preventDefault`), sonst lädt die Seite neu und ein entsperrter Zustand geht verloren. |
| FUN-64 | Das Kennungsfeld SOLL den Dateinamen tragen, damit ein gespeicherter Eintrag zuordenbar ist. |
| FUN-64a | Dasselbe gilt für „Vault erstellen" und „Master-Passwort ändern". Ohne Formular kann ein Passwortmanager ein neu vergebenes Passwort nicht anbieten und einen bereits gespeicherten Eintrag nach einem Wechsel nicht aktualisieren — dort stünde sonst dauerhaft das alte Passwort. |
| FUN-64b | Abbrechen- und Zurück-Schaltflächen in diesen Formularen MÜSSEN `type="button"` tragen, sonst lösen sie ein Absenden aus. |
| FUN-65 | Einträge MÜSSEN aus einer CSV-Datei importierbar sein, für beide Eintragstypen. |
| FUN-66 | Die Spaltennamen sind **fest und ausschließlich englisch** und MÜSSEN im Import-Dialog selbst dokumentiert sein: `title` (Pflicht), `type`, `url`, `username`, `password`, `totp`, `notes`, `tags`. Deutsche Bezeichnungen DÜRFEN NICHT erkannt werden — eine Schreibweise je Feld, damit Vorlage, Dialog und README übereinstimmen. Reihenfolge beliebig, unbekannte Spalten werden ignoriert, fehlende bleiben leer. |
| FUN-67 | Eine Vorlagendatei MUSS herunterladbar sein, mit Semikolon und BOM, damit deutsches Excel sie samt Umlauten direkt korrekt öffnet. |
| FUN-68 | Der Parser MUSS RFC 4180 beherrschen: Anführungszeichen, eingebettete Trennzeichen und Zeilenumbrüche, verdoppelte Quotes, CRLF. Das Trennzeichen (Komma, Semikolon, Tabulator) MUSS automatisch erkannt werden. |
| FUN-69 | Zeilen mit bereits vorhandenem Titel MÜSSEN übersprungen werden können; die Voreinstellung ist „überspringen". Der Vergleich erfolgt ohne Berücksichtigung von Groß- und Kleinschreibung. |
| FUN-70 | Ungültige 2FA-Secrets MÜSSEN verworfen und gemeldet werden. Die Prüfung MUSS strenger sein als `base32Decode`, das Fremdzeichen kommentarlos entfernt und aus Unsinn einen plausibel aussehenden, aber falschen Code machen würde. |
| FUN-71 | Der Import DARF nur den Speicher verändern und den Vault als ungespeichert markieren. So lässt sich ein misslungener Import durch Sperren ohne Speichern verwerfen. |
| FUN-72 | Das Ergebnis MUSS die Zahl importierter, übersprungener und beanstandeter Zeilen nennen und darauf hinweisen, dass die CSV-Datei alle Passwörter im Klartext enthält und zu löschen ist. |

### 4.9 Datensatz-Versionen

| ID | Anforderung |
|---|---|
| FUN-73 | Bei jeder Änderung an einem Eintrag MUSS der **vorherige** Stand aufgehoben werden. Der aktuelle Stand steht im Textblock; eine Dopplung wäre überflüssig. |
| FUN-74 | Eine Version DARF nur entstehen, wenn sich mindestens ein Feld tatsächlich geändert hat. Öffnen und Schließen des Dialogs ohne Änderung erzeugt weder Version noch „ungespeichert". |
| FUN-75 | Auslöser sind: Bearbeiten (`edited`), Löschen (`deleted`) und Wiederherstellen (`restored`). Duplizieren und CSV-Import erzeugen **keine** Versionen. |
| FUN-76 | Beim Entsperren DÜRFEN Versionsblöcke NICHT entschlüsselt werden. Der `versionIndex` im Textblock MUSS die Anzeige eines Zählers je Eintrag ohne Entschlüsselung ermöglichen. |
| FUN-77 | Der Verlauf eines Eintrags MUSS je Stand Zeitstempel, Grund und die **Namen** der geänderten Felder zeigen. Werte erscheinen erst nach dem Aufklappen; Passwörter und 2FA-Secrets bleiben dabei verdeckt und unterliegen den Regeln aus SEC-13 und SEC-14. |
| FUN-78 | Ein Stand MUSS vollständig oder feldweise wiederherstellbar sein. Das Wiederherstellen MUSS selbst eine Version anlegen und damit umkehrbar sein. |
| FUN-79 | Der Zeitstempel einer Version ist zugleich die Sortierordnung und MUSS streng monoton vergeben werden. Zwei Änderungen in derselben Millisekunde lägen sonst gleichauf und die Reihenfolge wäre zufällig. |
| FUN-80 | Gelöschte Einträge MÜSSEN in einem Papierkorb auffindbar und wiederherstellbar sein. Die Liste MUSS ohne Entschlüsselung auskommen. Ein wiederhergestellter Eintrag MUSS seine ursprüngliche laufende Nummer behalten, damit ein gespeicherter Deep-Link weiter auf denselben Eintrag zeigt. |
| FUN-81 | Anhänge, die nur noch von einer aufbewahrten Version referenziert werden, DÜRFEN beim Speichern NICHT als verwaist bereinigt werden. Fehlt der Block dennoch, MUSS der Anhang beim Wiederherstellen übersprungen und die Zahl gemeldet werden — ein toter Verweis ist unzulässig. |
| FUN-82 | Versionen und Grabsteine DÜRFEN NICHT automatisch verfallen. Löschen erfolgt ausschließlich von Hand: je Eintrag, als Auswahl mehrerer Einträge, nach Alter oder vollständig. Ein Schalter „jüngste Version je Eintrag behalten" MUSS vorhanden und voreingestellt sein. |
| FUN-83 | Nach dem Speichern MUSS die Anwendung auf eine große Datei hinweisen (Vorgabe: ab 5 MB) und dabei den Anteil des Verlaufs nennen. Der Hinweis erscheint höchstens einmal je Sitzung. |
| FUN-84 | Wird die letzte Version eines gelöschten Eintrags entfernt, MUSS auch sein Grabstein verschwinden — der Eintrag ist dann endgültig fort. |

### 4.10 Serverbetrieb

Alle Anforderungen dieses Kapitels gelten **nur** im Serverbetrieb. Die lokale
Datei bleibt davon unberührt und funktioniert unverändert ohne Netzwerk.

| ID | Anforderung |
|---|---|
| FUN-85 | Die Anwendungsdatei MUSS einen Erweiterungspunkt besitzen, über den ein injizierter Adapter den Serverbetrieb bereitstellt. Fehlt er, MUSS sich die Anwendung exakt wie zuvor verhalten. Die Datei DARF keinen Servercode enthalten. |
| FUN-86 | Der Adapter MUSS **vor** dem Anwendungsskript eingefügt werden. Er meldet sich sonst zu spät, und die Vault-Liste bliebe leer, ohne dass etwas den Grund nennt. |
| FUN-87 | Im Serverbetrieb MUSS der Sperrbildschirm die freigegebenen Vaults anzeigen. Nach dem Anklicken MUSS nur noch das Master-Passwort nötig sein. |
| FUN-88 | Ein Vault wird von Administratoren angelegt und an **Benutzer oder Gruppen** freigegeben, mit `read` oder `readwrite`. Gilt mehr als eine Regel, gewinnt das weiter gehende Recht. |
| FUN-89 | Ein neu angelegter Vault ist eine leere Hülle. Der Vault selbst entsteht im Browser des ersten Benutzers, der ein Master-Passwort vergibt. |
| FUN-90 | Administratoren MÜSSEN alle Vaults sehen, um sie verwalten zu können, für den Inhalt aber einen eigenen Freigabeeintrag brauchen wie alle anderen. |
| FUN-91 | Ein Schreibvorgang MUSS eine gültige Dateisperre **und** ein zutreffendes `If-Match` verlangen. Die Sperre ist beratend, der ETag maßgeblich: eine unbemerkt abgelaufene Sperre DARF NICHT zu einer verlorenen Änderung führen. |
| FUN-92 | Die Sperre MUSS eine Laufzeit haben, per Heartbeat verlängert werden und beim Sperren der Anwendung freigegeben werden. Abgelaufene Sperren MÜSSEN faul ausgewertet werden. Erneutes Holen durch denselben Halter verlängert, statt zu scheitern. |
| FUN-93 | Wer die Sperre nicht bekommt, MUSS den Vault **lesend** öffnen können, mit Angabe, wer ihn bearbeitet. Administratoren MÜSSEN eine Sperre brechen können; der bisherige Halter MUSS es beim nächsten Heartbeat erfahren. |
| FUN-94 | Bei einem Schreibkonflikt MUSS die Anwendung drei Auswege anbieten: neu laden, als lokale Datei speichern, oder abbrechen. Ein stilles Überschreiben ist unzulässig, „ungespeichert" bleibt stehen. |
| FUN-95 | Jeder erfolgreiche Schreibvorgang MUSS eine Generation aufheben. Generationen DÜRFEN NICHT automatisch verfallen. |
| FUN-96 | Wiederherstellen MUSS eine **neue** Generation erzeugen, statt zurückzuspulen. Der Verlauf bleibt damit lückenlos und der Schritt umkehrbar. Generationsnummern DÜRFEN NICHT wiederverwendet werden. |
| FUN-97 | Generationen MÜSSEN einzeln, unterhalb einer Nummer oder vollständig löschbar sein — ausschließlich durch Administratoren und ausschließlich von Hand. Die aktuelle Datei bleibt dabei unberührt. |
| FUN-98 | Anzahl und Gesamtgröße der Generationen MÜSSEN angezeigt werden, mit einem Hinweis ab einer konfigurierbaren Marke. Die Marke ist eine Aussage, keine Grenze. |
| FUN-99 | `mmo_vault.py` MUSS die Befehle `setup`, `start` und `export-vault` bereitstellen. `setup` läuft interaktiv oder über Schalter, fragt Origin, Art und Zugangsdaten des primären Providers (Microsoft mit Tenant, Google, generisch mit Issuer) sowie die ersten Administrator-Adressen ab und schreibt alles in die Datenbank. Ein zweiter Lauf verweigert ohne `--force`; mit `--force` ersetzt er Zugangsdaten und ergänzt Administratoren, löscht aber nichts. |
| FUN-100 | `start` MUSS Konfiguration und Schemastand prüfen und mit einer verständlichen Meldung abbrechen, statt mit einem Stacktrace. |
| FUN-101 | `export-vault <id|name> [--generation N]` MUSS den aktuellen Stand oder eine Generation eines Vaults unverändert auf die Standardausgabe schreiben. Es ist der Weg zu den Daten, wenn der Provider nicht erreichbar ist. |
| FUN-102 | Die Datenbank MUSS über SQLAlchemy abstrahiert sein, ohne Bindung an ein bestimmtes System. Vorgabe ist SQLite; Migrationen laufen über Alembic. |
| FUN-103 | Administratoren MÜSSEN weitere Provider anlegen, ändern, aktivieren, deaktivieren und zum primären machen können. Die Redirect-URI MUSS angezeigt werden; Issuer und Scopes werden aus der Art abgeleitet (Microsoft: Tenant, Google: fest, generisch: Issuer von Hand). |
| FUN-104 | Administratoren MÜSSEN die Allowlist je Provider pflegen können: Adresse, Administrator-Flag, Notiz. Adressen werden normalisiert (Kleinschreibung, getrimmt); Doppel und ungültige Adressen werden abgewiesen. Der Eintrag zeigt, ob bereits ein Konto dahintersteht. |
| FUN-105 | Konten entstehen nicht von Hand. Administratoren KÖNNEN sie deaktivieren, ihre Sitzungen widerrufen, lokale Gruppen zuweisen und sie löschen; das Löschen MUSS Freigaben, Sperren und Gruppenmitgliedschaften des Kontos mitnehmen. |
| FUN-106 | Gruppen sind **lokal** (Mitglieder von Hand) oder **gespiegelt** (Mitglieder vom Provider, Schalter `sync_groups` je Provider für Microsoft und Google). Ein Spiegel, dessen Provider nicht mehr synchronisiert, MUSS als eingefroren gekennzeichnet sein und behält seinen letzten Stand. Freigaben funktionieren auf beide gleich. |
| FUN-107 | Einstellungen — Origin, Sitzungsdauer, Leerlaufzeit, Größenlimit, Sperrlaufzeit, Warnmarke der Historie — MÜSSEN in der Verwaltung änderbar sein und ohne Neustart wirken. |

### 4.8 Markdown in Freitext-Einträgen

| ID | Anforderung |
|---|---|
| FUN-53 | Der Inhalt von Freitext-Einträgen MUSS als Markdown dargestellt werden. Notizen an Zugangsdaten bleiben reiner Text. Gesucht und bearbeitet wird immer der Rohtext. |
| FUN-54 | Der Renderer MUSS ausschließlich DOM-Knoten über `createElement` und `textContent` erzeugen und DARF `innerHTML` nicht verwenden. Damit ist HTML-Injection konstruktionsbedingt ausgeschlossen und SEC-23 bleibt gewahrt — ein Sanitizer wäre eine schwächere Zusicherung. |
| FUN-55 | Unterstützt werden MÜSSEN: Überschriften, fett, kursiv, durchgestrichen, Inline-Code, Code-Blöcke, Listen (geordnet und ungeordnet, **mehrstufig über die Einzugstiefe**), Zitat, Trennlinie, Links und **Tabellen**. |
| FUN-55a | Eine Tabelle MUSS an einer Trennzeile (`\|---\|`) erkannt werden. Ohne Trennzeile bleibt der Text ein Absatz — sonst würde jede Zeile mit einem senkrechten Strich zur Tabelle. |
| FUN-55b | Die Spaltenausrichtung aus `:---`, `:---:`, `---:` MUSS umgesetzt werden. |
| FUN-55c | Zeilen MÜSSEN auf die Spaltenzahl der Kopfzeile normiert werden: fehlende Zellen bleiben leer, überzählige entfallen. Ein mit Backslash geschütztes `\|` trennt nicht. |
| FUN-55d | Eine Tabelle MUSS in einem eigenen horizontal scrollbaren Container liegen. Bei rund 330 px Kartenbreite passt eine mehrspaltige Tabelle nicht und würde die Kachel sonst aufweiten. |
| FUN-56 | Bilder DÜRFEN NICHT gerendert werden. Ein `<img>` mit externer Quelle wäre ein Netzwerk-Beacon und würde die Zusage aus SEC-20 bis SEC-22 brechen. Der Tag DARF nicht entstehen, unabhängig davon, dass die CSP ihn zusätzlich blockt. |
| FUN-57 | Eingebettetes HTML im Markdown MUSS als Text ausgegeben werden. |
| FUN-58 | Links MÜSSEN dieselbe Allowlist wie Eintrags-URLs durchlaufen (nur `http`/`https`) und mit `noopener noreferrer` öffnen. Abgewiesene Ziele MÜSSEN als Text erhalten bleiben. |
| FUN-59 | Ein einzelner Zeilenumbruch MUSS ein Umbruch bleiben und DARF NICHT zum Absatz zusammengezogen werden. Abweichung von CommonMark, weil in Notizen Dinge wie Backup-Codes zeilenweise stehen. |
| FUN-60 | Lange Notizen MÜSSEN auf der Karte in der Höhe begrenzt und aufklappbar sein. Die Begrenzung ist rein visuell. |
| FUN-61 | Der Eintrags-Dialog MUSS für Freitext eine Vorschau-Umschaltung anbieten. |

---

## 5. Dateiformat

### 5.1 Format v3 — `mmo-vault-v3`

Erweitert v2 um **einen** neuen Blocktyp und **zwei** Felder im Textblock. Alles Übrige ist unverändert.

```
{"type":"header","format":"mmo-vault-v3","salt":"<base64>","iterations":600000}
{"type":"text","iv":"<base64>","data":"<base64>"}
{"type":"vers","iv":"<base64>","data":"<base64>"}
{"type":"file","id":"<att-id>","iv":"<base64>","data":"<base64>"}
```

**Versionsblock (`vers`)** — AES-256-GCM über eine Liste abgelöster Eintragsstände:

```jsonc
{ "v": [{
  "id": "e…",                 // Eintrags-ID
  "num": 42,                  // laufende Nummer zum Zeitpunkt der Ablösung
  "ts": 1754132400000,        // Zeitstempel, zugleich Sortierordnung
  "reason": "edited" | "deleted" | "restored",
  "snapshot": { … }           // vollständiger Eintrag VOR der Änderung
}] }
```

**Zusätzliche Felder im Textblock:**

```jsonc
{
  "versionIndex": { "e…": { "n": 7, "last": 1754132400000, "deleted": true, "title": "…", "num": 42 } },
  "versionAtt": ["<att-id>", "…"]
}
```

`versionIndex` trägt nur Zähler, Zeitstempel und — bei gelöschten Einträgen — Grabsteindaten; keine Werte. `versionAtt` listet die Anhangs-IDs, die nur noch von einer Version gebraucht werden, damit deren Blöcke nicht als verwaist bereinigt werden.

Beim Speichern wird **höchstens ein neuer** `vers`-Block angefügt; bestehende werden unverändert als Chiffrat übernommen. Aufgeräumt wird nur beim Löschen von Versionen und beim Master-Passwort-Wechsel, dann als ein einziger Block.

### 5.2 Format v2 — `mmo-vault-v2`

NDJSON: eine Zeile je Block, jede Zeile unabhängig parsbar.

```
{"type":"header","format":"mmo-vault-v2","salt":"<base64>","iterations":600000}
{"type":"text","iv":"<base64>","data":"<base64>"}
{"type":"file","id":"<att-id>","iv":"<base64>","data":"<base64>"}
```

**Header** — unverschlüsselt. Enthält ausschließlich die zur Schlüsselableitung nötigen Parameter, keine Nutzdaten.

**Textblock** — AES-256-GCM über das JSON-Objekt:

```jsonc
{
  "entries": [{
    "id": "e…", "type": "zugang" | "freitext",
    "title": "…", "url": "…", "username": "…", "password": "…",
    "totp": "<base32>", "totpDigits": 6, "totpPeriod": 30, "totpAlgorithm": "SHA-1",
    "notes": "…", "tags": ["…"],
    "attachments": [{ "id": "e…", "name": "…", "type": "…", "size": 1234 }]
  }],
  "history": [{ "ts": 1750000000000, "action": "hist_entry_created", "detail": "Titel" }],
  "autoLockMinutes": 5
}
```

Anhänge erscheinen hier **nur mit Metadaten**. Die Rohdaten liegen in eigenen `file`-Blöcken.

**Dateiblock** — je Anhang ein eigener AES-256-GCM-Block über `{"id":"<att-id>","b":"<base64-rohdaten>"}`. Die mitverschlüsselte ID bindet den Klartext an seinen Anhang.

### 5.3 Format v1 (Legacy, nur lesend)

Ein einzelnes JSON-Objekt `{salt, iterations, iv, data}` mit allen Daten inklusive Anhängen in einem Block. Wird beim Laden erkannt und beim nächsten Speichern automatisch ins Blockformat überführt.

### 5.3a Ablage im Serverbetrieb

Der Dienst speichert die Datei unverändert, wie sie der Browser schickt:

```
var/vaults/<uuid>/current.ndjson       der aktuelle Stand
var/vaults/<uuid>/history/000001.ndjson  je eine Generation, aufsteigend
```

Geschrieben wird über eine temporäre Datei plus `os.replace`, mit `fsync` davor.
Der ETag ist der SHA-256 des Inhalts — zwei Schreibvorgänge mit gleichem Inhalt
ergeben denselben Wert, und eine wiederhergestellte Generation ist als solche
erkennbar.

### 5.4 Kompatibilitätsregeln

- Unbekannte Blocktypen MÜSSEN beim Lesen ignoriert werden.
- Fehlende Eintragsfelder MÜSSEN auf dokumentierte Vorgabewerte fallen.
- Ein `file`-Block ohne `id` im Klartext stammt aus einer Version vor 1.0 und wird ohne Bindungsprüfung akzeptiert.
- v3 wird erst geschrieben, wenn der Vault mindestens eine Version enthält. Ein Vault ohne Historie bleibt v2 und damit mit älteren Anwendungsversionen verlustfrei bearbeitbar.
- **Bekannte Grenze:** Weil unbekannte Blocktypen ignoriert werden, öffnet Version 1.8.0 eine v3-Datei anstandslos, verwirft beim Speichern aber sämtliche `vers`-Blöcke — kommentarlos. Das ist nicht nachträglich reparierbar, weil 1.8.0 bereits ausgeliefert ist; der Umstand MUSS in der README stehen.

---

## 6. Nicht-funktionale Anforderungen

| ID | Anforderung |
|---|---|
| NFR-01 | Die Anwendung MUSS aus genau einer HTML-Datei ohne Build-Schritt, Paketmanager oder Laufzeitabhängigkeit bestehen. |
| NFR-02 | Sie MUSS per Doppelklick über `file://` lauffähig sein — ohne Webserver und ohne Installation. |
| NFR-03 | Unterstützt werden MÜSSEN aktuelle Versionen von Chrome, Edge, Firefox und Safari. FSA und `BarcodeDetector` sind optionale Fähigkeiten mit dokumentiertem Ersatzverhalten. |
| NFR-04 | Das Entsperren eines Vaults mit 200 Einträgen SOLL auf zeitgemäßer Hardware unter 2 Sekunden bleiben (dominiert durch PBKDF2). |
| NFR-05 | Die TOTP-Anzeige DARF ein HMAC je Eintrag und Periode nicht überschreiten; die Sekundenanzeige darf keine Kryptooperation auslösen. |
| NFR-06 | Der Quelltext MUSS deutschsprachig kommentiert sein, mit Schwerpunkt auf der Begründung nicht offensichtlicher Entscheidungen. |
| NFR-07 | Neue Eintragstypen MÜSSEN durch Ergänzen von `RECORD_TYPES` und der zugehörigen Übersetzungsschlüssel hinzufügbar sein, ohne Filter-, Dialog- oder Badge-Logik anzufassen. |
| NFR-08 | Die Anwendungsdatei MUSS ohne Build-Schritt auskommen: `mmo_vault/public_html/mmo_vault.html` ist zugleich Quelle und Auslieferung. Im Serverbetrieb liefert der Dienst genau diese Datei aus; einen separaten Webserver gibt es nicht. |
| NFR-09 | Der Container MUSS als unprivilegierter Benutzer auf einem Port oberhalb 1024 laufen und mit read-only Wurzeldateisystem sowie ohne Capabilities startfähig sein. |
| NFR-10 | Die ausgelieferte Anwendung MUSS `Cache-Control: no-store` tragen. Sie enthält den Adapter der laufenden Sitzung; eine zwischengespeicherte Kopie zeigt auf eine Sitzung, die es nicht mehr gibt. |

---

## 7. Fehlerverhalten

| Situation | Verhalten |
|---|---|
| Falsches Master-Passwort | Sammelmeldung „Falsches Master-Passwort oder beschädigte Daten." — keine Unterscheidung zwischen falschem Passwort und defekter Datei |
| Ungültige oder fremde Datei | Ablehnung mit Hinweis, kein Absturz, Sperrbildschirm bleibt bedienbar |
| Unplausible Header-Werte | Ablehnung vor der Schlüsselableitung |
| Verknüpfte Datei nicht lesbar | Verknüpfung automatisch entfernen, Ursache benennen (Cloud-Sync), Neuauswahl anbieten |
| FSA im Cross-Origin-iframe gesperrt | Einmalig erkennen, für die Sitzung auf klassischen Dialog und Download umschalten, Grund erklären |
| Speichern abgebrochen | Kein Download, „ungespeichert" bleibt bestehen, Hinweis |
| Schreiben oder Verifikation fehlgeschlagen | Vorherigen Inhalt wiederherstellen, „ungespeichert" bleibt bestehen, Fehler benennen |
| Anhang nicht auffindbar oder ID passt nicht | Fehlermeldung, übrige Anwendung bleibt nutzbar |
| Kein `BarcodeDetector` im Browser | Hinweis auf manuelle Eingabe des Secrets |
| Zwischenablage nicht verfügbar | Hinweis „Kopieren fehlgeschlagen" |

---

## 8. Betriebshinweise

- **Backups sind Pflicht.** Die Anwendung führt keine Versionierung. Ein Verlust der Vault-Datei ist ein Totalverlust. Die Rückrollsicherung beim Schreiben schützt gegen abgebrochene Schreibvorgänge, nicht gegen Löschen, Defekte des Datenträgers oder Sync-Konflikte.
- **Master-Passwort:** keine Wiederherstellung. Getrennt vom Vault hinterlegen.
- **Cloud-Sync-Ordner:** Nextcloud, OneDrive und Dropbox tauschen Dateien intern aus; gespeicherte Datei-Handles können dadurch ins Leere zeigen. Die Anwendung erkennt das und räumt die Verknüpfung auf. Gleichzeitiges Bearbeiten auf mehreren Geräten wird nicht unterstützt und führt zu Sync-Konflikten.
- **Ablage der Anwendungsdatei:** aus vertrauenswürdiger Quelle beziehen und schreibgeschützt ablegen.
- **Serverbetrieb:** Das Datenverzeichnis (`MMO_VAULT_DIR`) enthält Datenbank und Vault-Dateien und ist die einzige Sicherungseinheit. Die Datenbank enthält die Client-Secrets der Provider — sie gehört in kein Repository und in keinen unverschlüsselten Cloud-Ordner. Bei der Registrierung der Anwendung beim Provider die von `setup` ausgegebene Redirect-URI eintragen; für den Gruppen-Sync `GroupMember.Read.All` (Microsoft, delegiert) bzw. `cloud-identity.groups.readonly` (Google Workspace) freigeben.

---

## 9. Abnahmekriterien

Abgehakte Punkte sind nachweisbar geprüft — die Krypto-, Datenintegritäts-, Sperr- und Container-Kriterien automatisiert gegen die laufende Anwendung bzw. den gebauten Container. Offene Punkte erfordern manuelle Prüfung und sind als solche gekennzeichnet.

### 9.1 Kryptografie

- [x] TOTP stimmt mit den RFC-6238-Testvektoren für SHA-1, SHA-256 und SHA-512 überein (T=59 → `94287082` / `46119246` / `90693936`)
- [x] Passwortgenerator zeigt über ≥ 50.000 Ziehungen keine systematische Abweichung von der Gleichverteilung
- [x] Vault-Datei enthält kein Passwort, kein 2FA-Secret und keinen Benutzernamen im Klartext
- [x] Falsches Master-Passwort wird abgewiesen
- [x] Header mit unplausibler Iterationszahl (`1e9`, `"600000"`) wird abgewiesen, gültiger Wert akzeptiert
- [x] Vertauschter Anhangsblock wird über die ID-Bindung erkannt
- [x] Datei mit 100.000 Iterationen wird beim Entsperren auf 600.000 gehoben, mit neuem Salt gespeichert und bleibt lesbar

### 9.2 Datenintegrität

- [x] Abgebrochener Speichern-Dialog löst keinen Download aus und lässt „ungespeichert" stehen
- [x] Fehlgeschlagenes Schreiben stellt den vorherigen Dateiinhalt wieder her
- [x] Abgeschnittener Schreibvorgang wird durch Rückverifikation erkannt und zurückgerollt
- [x] Erfolgreiches Speichern erzeugt eine wieder ladbare Datei und setzt „ungespeichert" zurück
- [x] Nach einem fehlgeschlagenen Schreibvorgang erscheint der Rückfalldialog mit dem Fehlergrund; „als Download sichern" persistiert die Daten, „anderen Speicherort" schreibt an den neu gewählten Ort und lässt die alte Datei unangetastet, „Abbrechen" behält „ungespeichert"
- [x] Escape und Sperren lösen den wartenden Speichervorgang auf, statt ihn hängen zu lassen
- [x] Im Ablauf „Speichern & Sperren" wird nach dem Rettungs-Download gesperrt, nach „Abbrechen" nicht
- [x] Wird die Ortsauswahl nach „anderen Speicherort" abgebrochen, bleibt die bisherige Datei-Verknüpfung erhalten; bei erfolgreicher Auswahl gilt das neue Handle
- [x] Roundtrip Anlegen → Speichern → Laden → Entschlüsseln erhält alle Feldwerte inklusive TOTP-Parameter
- [x] Anhänge werden lazy nachgeladen und liegen nicht im Textblock

### 9.3 Sperrverhalten

- [x] Sperren schließt alle Dialoge und leert deren Felder
- [x] Nach dem Sperren enthält das DOM kein Passwort mehr
- [x] Nach dem Sperren sind Schlüssel, Einträge, Datei-Handle und Suchzustand zurückgesetzt
- [x] Auto-Sperre greift auch bei geöffnetem Eintrags-Dialog
- [ ] Auto-Sperre löst nach der eingestellten Zeit ohne Aktivität aus (manueller Test über 1-Minuten-Einstellung)

### 9.4 Funktion und Oberfläche

- [x] QR-Import übernimmt Secret, Aussteller, Konto sowie Stellenzahl, Periode und Algorithmus
- [x] HOTP-QR wird mit verständlicher Meldung abgewiesen
- [x] Ein von Hand ersetztes 2FA-Secret fällt auf 6 Stellen / 30 s / SHA-1 zurück und erzeugt den Code, den ein Standard-Authenticator erwartet; ein QR-Import behält seine abweichenden Parameter

### 9.7 Nummern, Suche, Duplikate und Markdown

- [x] Einträge ohne Nummer erhalten beim Entsperren welche in Anlagereihenfolge; der Zähler wird gespeichert und nach dem Löschen des höchsten Eintrags nicht erneut vergeben
- [x] Suchsyntax geprüft: `id=1`, `id=#2`, `id=<interne-id>`, `tag=`, `typ=`, `benutzer=`, `titel=`, Kombination `id=1 nextcloud` (Treffer) und `id=1 bank` (kein Treffer), unbekannter Schlüssel bleibt Volltext
- [x] Zitierte Werte geprüft: `tag="mein tag"`, `tag='mein tag'`, `titel="deutsche bank"`, `benutzer="kunde 42"`, Phrasensuche `"zwei wörter"`, Kombination mit weiteren Filtern, sowie ein nicht geschlossenes Zitat (bricht nicht)
- [x] `#search=id%3D2` belegt das Suchfeld vor, filtert auf den passenden Eintrag und wird aus der Adresszeile entfernt
- [x] Duplikat erhält neue ID, neue Nummer, Titelzusatz und eigene Anhangs-IDs; die Datei enthält danach zwei getrennte Blöcke, und das Löschen des Originals lässt den Anhang des Duplikats lesbar
- [x] Markdown-Renderer erzeugt Überschriften, fett, kursiv, Code, Code-Block, beide Listenarten, Zitat, Trennlinie und Links
- [x] Injection-Prüfung: kein `<img>`, kein `<script>`, keine `on*`-Attribute; rohes HTML und Code-Block-Inhalt bleiben Text; `javascript:`-Link wird nicht verlinkt, sein Text bleibt erhalten; alle Links `http`/`https` mit `noopener noreferrer`
- [x] Einzelne Zeilenumbrüche bleiben als `<br>` erhalten (Backup-Code-Fall)
- [x] Notizen an Zugangsdaten bleiben reiner Text — `**text**` wird nicht formatiert
- [x] Vorschau nur bei Freitext, rendert den Rohtext und wird beim Zurückschalten und beim Sperren geleert

### 9.8 Entsperr-Formular und CSV-Import

- [x] Entsperr-Feld liegt in einem `<form>`, Knopf ist `type="submit"`, Kennungs- und Passwortfeld tragen die passenden `autocomplete`-Werte
- [x] Das Absende-Ereignis ruft den Entsperr-Vorgang und lädt die Seite nicht neu
- [x] Alle sechs Passwortfelder liegen in einem Formular; Konsole beim Laden vollständig leer
- [x] Anlegen und Passwortwechsel laufen über das Absende-Ereignis; nach dem Wechsel ist die Datei mit dem neuen Passwort lesbar
- [x] CSV-Parser geprüft: Komma, Semikolon, zitierte Trennzeichen, verdoppelte Quotes, eingebettete Zeilenumbrüche, CRLF, Leerzeilen
- [x] Trennzeichen-Erkennung für Komma, Semikolon und Tabulator
- [x] Import geprüft: beide Typen, Standardtyp bei fehlender Spalte, Tags, englische Spaltennamen, Zeile ohne Titel, Dublette mit und ohne Überspringen, Verlaufseintrag, leere Zugangsfelder bei Freitext
- [x] Fehlerfälle: nur Kopfzeile, fehlende Titelspalte
- [x] Base32-Prüfung über acht Fälle; formatierte Secrets mit Leerzeichen und Bindestrichen bleiben gültig, Unsinn wird verworfen und gezählt
- [x] Vorlage trägt BOM und Semikolon und ist selbst wieder importierbar
- [x] Eintragskarten tragen keine gestrichelte Linie mehr
- [ ] Speichern-Angebot des Passwortmanagers auf einem echten Android-Gerät (nur über die Server-Variante prüfbar, nicht über `file://`)
- [x] Tabelle: Kopfzeile, Ausrichtung links/zentriert/rechts wirksam (per `getComputedStyle` geprüft), fehlende Zelle leer, überzählige verworfen, geschütztes `\|` bleibt Inhalt, Absatz danach wird wieder als Absatz erkannt
- [x] Ohne Trennzeile entsteht keine Tabelle, der Text bleibt Absatz
- [x] Tabelle liegt im Scroll-Container; die Karte bleibt bei 360 px im Viewport, kein horizontaler Seiten-Überlauf
- [x] Verschachtelte Listen bis drei Ebenen, gemischt geordnet und ungeordnet
- [x] Injection in Tabellenzellen: kein `<img>`, keine `on*`-Attribute, rohes HTML bleibt Text, `javascript:`-Link wird nicht verlinkt
- [x] `javascript:`-URLs werden abgewiesen, schemalose Eingaben zu `https://` ergänzt
- [x] Suche ohne Treffer zeigt „Keine Treffer" statt einer leeren Seite
- [x] Escape schließt den obersten Dialog; Hintergrundklick schließt nur Dialoge ohne Eingabefelder
- [x] Beide Sprachtabellen deckungsgleich; kein verwendeter Schlüssel ohne Übersetzung
- [x] Sprachwechsel erfasst auch dynamisch erzeugte Inhalte (Typ-Chips, Leerzustände, Fehlermeldungen, `aria-label`) und erhält den aktiven Filter
- [x] Jedes sichtbare Eingabefeld besitzt ein zugeordnetes Label oder `aria-label`
- [x] Layout bei 320, 360, 411, 500, 900 und 1280 px: kein horizontaler Überlauf, keine mehrzeilig umbrechenden Schaltflächen, Dialoge schmaler als der Viewport
- [x] Layoutprüfung MUSS mit realistisch langen Werten erfolgen — vollständige URL, lange E-Mail-Adresse, langer Anhangsname, umbruchlose Zeichenkette im Freitext. Kurze Platzhalter verdecken Überlauf-Fehler, weil sie ohnehin passen.
- [x] Überbreite Inhalte werden gekürzt, nicht kaschiert: `document.scrollWidth` entspricht der Viewport-Breite, kein Element ragt über den rechten Rand, Wertzeilen kürzen mit Auslassungspunkten
- [x] Der Aktionsknopf zum Anlegen bleibt bei jeder Breite im Bild und anklickbar
- [x] Die Kopfleiste bleibt beim Scrollen oben stehen (`position:sticky` wirksam)
- [x] Bei 360 px messen alle Bedienelemente mindestens 36 px, Kopfleisten- und Dialogschaltflächen 44 px; das Kästchen „Sonderzeichen" ist über seine 44 px hohe Beschriftungszeile schaltbar
- [x] Unter 560 px liegt die Suche in eigener Zeile über die volle Breite (336 px bei 360 px Viewport, 44 px hoch, 16 px Schrift)
- [x] Die Bildmarke ist bei jeder Breite sichtbar; der Schriftzug entfällt nur unter 560 px
- [x] Unter 900 px erscheint das Werkzeugmenü als Bottom-Sheet am unteren Rand, vollständig im Bild, mit bildschirmfüllendem Backdrop; alle sieben Einträge sind per `elementFromPoint` nachweisbar erreichbar und lösen ihre Aktion aus
- [x] Ab 901 px entfällt das Sheet und die Werkzeuge liegen direkt in der Kopfleiste
- [ ] Sichtprüfung der übersetzten Texte auf Umbrüche und Überläufe in allen Ansichten
- [ ] Bedienung mit Tastatur allein von Sperrbildschirm bis Eintrag anlegen (manuelle Prüfung)

### 9.9 Datensatz-Versionen

- [x] Roundtrip v2 → v3: Datei mit Version schreiben, zurücklesen, Stand entschlüsseln
- [x] Ohne Versionen bleibt das Format v2; erst die erste Version macht die Datei zu v3
- [x] Bestehende `vers`-Blöcke werden beim erneuten Speichern als Chiffrat übernommen, nicht neu verschlüsselt
- [x] Entsperren entschlüsselt keinen Versionsblock; der Zähler kommt aus dem Index
- [x] Bearbeiten mit Änderung erzeugt genau eine Version, Öffnen ohne Änderung keine
- [x] Feldvergleich erfasst Werte, Tags und Anhänge; `undefined` und `""` gelten als gleich
- [x] Wiederherstellen ganz und feldweise; beides erzeugt selbst eine Version
- [x] Papierkorb: Grabstein mit Titel und Nummer, Wiederherstellen mit erhaltener Nummer, Zähler wird nicht weitergedreht
- [x] Anhang eines gelöschten Eintrags überlebt das Speichern; fehlender Block erzeugt keinen toten Verweis
- [x] Verlauf nach Master-Passwort-Wechsel weiterhin lesbar, Wechsel kompaktiert auf einen Block
- [x] Sammellöschen: je Eintrag, nach Alter, „jüngste behalten", Index danach vollständig neu aufgebaut
- [x] Grabstein verschwindet mit seiner letzten Version, bleibt solange der Löschstand da ist
- [x] Größenschätzung rechnet auf dem Chiffrat, ohne zu entschlüsseln
- [ ] Größenwarnung an einer echten Datei jenseits 5 MB (bisher nur mit gesetztem Schwellwert geprüft)

### 9.10 Serverbetrieb

- [x] `setup` schreibt Origin, primären Provider, Signaturschlüssel und Administrator-Allowlist in die Datenbank; keine Datei entsteht; ein zweiter Lauf verweigert ohne `--force`; `--force` ersetzt Zugangsdaten und ergänzt Administratoren ohne zu löschen
- [x] `setup` weist unsicheren Origin, Microsoft ohne konkreten Tenant und leere Administratorliste ab
- [x] `start` bricht ohne Konfiguration und bei veraltetem Schema verständlich ab; `create_app` nennt, was fehlt
- [x] Nur `MMO_VAULT_DIR` und `MMO_VAULT_DATABASE_URL` werden gelesen; fehlende Einstellungen fallen auf Vorgaben zurück
- [x] Gelistete Adresse erzeugt beim ersten Login ein Konto; ungelistete bekommt nichts und wird protokolliert; kein Token ohne `sub`
- [x] Identität ist `(provider, sub)`: geänderte Adresse erzeugt kein zweites Konto; unverifizierte Adresse bindet nichts; Adressen werden ohne Rücksicht auf Groß-/Kleinschreibung verglichen
- [x] Administrator-Flag folgt der Allowlist bei jedem Login; Entfernen deaktiviert das Konto und beendet die Sitzung sofort; Herabstufen beendet die Sitzung sofort
- [x] Microsoft: `tid` muss dem Tenant entsprechen, fremder Tenant wird abgewiesen, `common`/`organizations`/`consumers` sind schon bei der Konfiguration unzulässig
- [x] Provider: primärer zuerst gelistet, Secret nie ausgegeben, primärer weder deaktivier- noch löschbar, belegter nicht löschbar, Wechsel des primären
- [x] Allowlist: letzter Administrator geschützt; Doppel und ungültige Adressen 409/400; Normalisierung
- [x] Konten werden nicht von Hand angelegt (405); Deaktivieren widerruft Sitzungen; Löschen lässt keine Freigaben zurück
- [x] Gruppen, Freigaben an Benutzer und Gruppen, weiter gehendes Recht gewinnt; unbekanntes Mitglied ist ein Fehler; Löschen einer Gruppe nimmt ihre Freigaben mit
- [x] Gruppen-Sync: Spiegel entstehen, Mitgliedschaften werden ersetzt, lokale und fremde Provider-Gruppen bleiben unberührt, Umbenennungen folgen, Namenskollision wird aufgelöst, Doppel in der Antwort sind harmlos
- [x] Gruppen-Sync: Microsoft folgt `@odata.nextLink` und überspringt Verzeichnisrollen; Google fragt die eigene Adresse ab und folgt `nextPageToken`; Fehlerstatus und Netzwerkfehler sind ein `SyncFailed`
- [x] Fehlgeschlagener Sync lässt den letzten Stand stehen, sperrt nicht aus und landet im Audit; nur Microsoft und Google mit gesetztem Schalter synchronisieren
- [x] Einstellungen: Round-Trip, Wirkung ohne Neustart, Origin muss `https` sein, Redirect-URI folgt dem Origin
- [x] Migration von 2.0.0 gegen eine befüllte Datenbank: Allowlist mit Administrator-Flags übernommen, Konto ohne Provider deaktiviert, Sitzungen geleert, `config.toml` importiert, Credential-Tabellen entfernt
- [x] Schreiben mit gültiger Sperre und ETag; veralteter ETag ergibt 412, fehlende Sperre 409, fehlendes If-Match 428, zu groß 413 vor dem Lesen des Körpers
- [x] Sperre: Zweiter bekommt sie nicht, erneutes Holen verlängert, Ablauf wird faul erkannt, Administrator kann brechen, Beacon gibt mit Token frei
- [x] Atomares Schreiben: abgebrochener Schreibvorgang lässt die vorige Datei unversehrt, kein Rest im Verzeichnis
- [x] Generationen bei jedem Schreibvorgang; Wiederherstellen erzeugt eine neue; Nummern werden nicht wiederverwendet; Löschen einzeln, unterhalb einer Nummer und vollständig; aktuelle Datei bleibt
- [x] `export-vault` nach ID und Name, aktuelle Datei und Generation; unbekannt ergibt Fehlercode 1
- [x] Injektion: genau zwei Änderungen, Datei auf dem Datenträger unverändert, Adapter vor dem Anwendungsskript, `/api/injection` zeigt den Block
- [x] Anmeldeseite zeigt nur Provider-Schaltflächen, kein Passwortfeld
- [ ] OIDC-Anmeldung gegen Microsoft 365 und Google mit echten Zugangsdaten, einschließlich Gruppen-Sync (Google: ob `searchDirectGroups` für Nutzer ohne Admin-Rolle Ergebnisse liefert)
- [ ] Verhalten hinter dem Reverse Proxy der Zielumgebung

### 9.5 Auslieferung

- [x] Konsole beim Laden frei von Fehlern und Warnungen der Anwendung
- [x] Keine Netzwerkanfrage; CSP ohne Verstoß
- [x] Fehlender Secure Context wird erkannt: Hinweis in beiden Sprachen, Bedienelemente gesperrt, kein Laufzeitfehler
- [ ] Funktionsprüfung in Chrome, Edge, Firefox und Safari
- [ ] Prüfung des Ersatzverhaltens ohne FSA (Download-Pfad) und ohne `BarcodeDetector`

### 9.6 Container-Auslieferung

- [x] Antwort trägt `Content-Security-Policy` mit `frame-ancestors 'none'`, dazu `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy` und `Permissions-Policy`; `clipboard-write` bleibt erlaubt
- [x] Die ausgelieferte Anwendung trägt `Cache-Control: no-store`
- [ ] `docker build` läuft fehlerfrei durch; das Abbild enthält keine Dokumentation, keine Tests und keine Vault-Datei
- [ ] Container startet mit `read_only: true`, `cap_drop: ALL` und `no-new-privileges`; Healthcheck wird `healthy`; Prozess läuft als uid 10001
- [ ] `setup` als Einmal-Lauf schreibt in das Volume; ein anschließender Start findet die Konfiguration vor
- [ ] Anlegen, Eintrag mit generiertem Passwort und QR-2FA, Speichern-Roundtrip und Sperren funktionieren über den Container
- [ ] Aufruf über einen Nicht-localhost-Hostnamen ohne TLS zeigt den Secure-Context-Hinweis statt einer scheinbar funktionierenden Oberfläche
- [ ] Security-Header gehen unverändert durch einen TLS-terminierenden Reverse Proxy
- [ ] Prüfung mit dem tatsächlich eingesetzten Reverse Proxy der Zielumgebung (HSTS und `X-Forwarded-For` liegen dort)

---

## 10. Zurückgestellt

| Thema | Begründung |
|---|---|
| AAD-Bindung von Header und Blöcken | Bricht das Dateiformat; erfordert Migrationspfad v2 → v3 |
| Argon2id statt PBKDF2 | Nicht in `crypto.subtle` verfügbar; würde WASM und damit die Ein-Datei-Zusage brechen |
| Automatische Backup-Rotation | Erfordert Verzeichniszugriff statt eines einzelnen Datei-Handles |
| Import aus KeePass/CSV | Eigenständiger Umfang mit eigenem Sicherheitsbedarf |
| Passwort-Historie je Eintrag | Vergrößert die Angriffsfläche; Nutzen zuerst klären |
| Fokusfalle in Dialogen | Escape und ARIA-Rollen decken den Hauptbedarf in 1.0 ab |
