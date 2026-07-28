# MMO Vault — Anforderungsspezifikation

**Version:** 1.6.0
**Stand:** 2026-07-28
**Status:** Im Eigenbetrieb freigegeben. Alle automatisiert prüfbaren Kriterien aus Kapitel 9 sind verifiziert; die verbleibenden erfordern manuelle Durchführung und stehen dort als unmarkierte Kästchen. Diese Zahl wird hier bewusst nicht wiederholt, damit sie nicht veraltet.
**Autor:** Michael Müller

---

## 1. Zweck und Geltungsbereich

MMO Vault ist ein lokaler Passwortmanager, der vollständig als **eine einzelne HTML-Datei** ausgeliefert wird und ausschließlich im Browser des Anwenders läuft. Er verwaltet Zugangsdaten, Freitext-Notizen, 2FA-Secrets und Dateianhänge in einer verschlüsselten Datei, die der Anwender selbst besitzt und ablegt.

Das Dokument beschreibt den Funktions- und Qualitätsumfang der Version 1.6.0. Es richtet sich an Entwicklung, Review und Abnahme.

### 1.1 Nicht im Geltungsbereich

Ausdrücklich **nicht** Bestandteil dieser Version:

- Server-, Cloud- oder Synchronisationskomponente jeder Art
- Mehrbenutzer-, Freigabe- oder Rechteverwaltung
- Browser-Erweiterung, Autofill in fremden Seiten, Zwischenablage-Überwachung
- Import aus anderen Passwortmanagern (KeePass, 1Password, Bitwarden, CSV)
- Passwort-Historie pro Eintrag, Ablaufdatum, Breach-Abgleich
- HOTP (zählerbasierte Einmalpasswörter)
- Automatische Backup-Rotation oder Versionierung der Vault-Datei

---

## 2. Begriffe

| Begriff | Bedeutung |
|---|---|
| **Vault** | Die Gesamtheit der verschlüsselten Nutzdaten, gespeichert in einer Vault-Datei |
| **Vault-Datei** | Datei im Format `mmo-vault-v2` (NDJSON), Endung `.json` |
| **Master-Passwort** | Das einzige Geheimnis, aus dem der Verschlüsselungsschlüssel abgeleitet wird |
| **Eintrag** | Ein Datensatz vom Typ *Zugang* oder *Freitext* |
| **Block** | Eine Zeile der Vault-Datei; entweder `header`, `text` oder `file` |
| **FSA** | File System Access API (`showOpenFilePicker`, `showSaveFilePicker`) |
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
| SEC-20 | Die Anwendung DARF KEINE Netzwerkverbindung aufbauen. Dies MUSS per Content-Security-Policy erzwungen werden, nicht nur zugesichert: `default-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'`. |
| SEC-21 | Es DÜRFEN KEINE externen Ressourcen eingebunden werden — keine CDN-Skripte, Stylesheets, Web Fonts oder Bilder. |
| SEC-22 | Es DARF KEINE Telemetrie, Fehlerübermittlung oder Nutzungsstatistik stattfinden. |
| SEC-23 | Nutzergesteuerte Inhalte (Titel, Benutzername, Notizen, Tags, Anhangsnamen, Verlaufsdetails) MÜSSEN per `textContent` in das DOM geschrieben werden, nie per `innerHTML`. |
| SEC-24 | Gespeicherte URLs DÜRFEN nur mit den Schemata `http` und `https` geöffnet werden. Alle anderen — insbesondere `javascript:` — MÜSSEN abgewiesen werden. |
| SEC-25 | Externe Links MÜSSEN mit `noopener,noreferrer` geöffnet werden. |
| SEC-26 | Der Änderungsverlauf DARF nur Zeitstempel, Aktionstyp und Eintragstitel enthalten — nie Passwörter, Benutzernamen, URLs oder 2FA-Secrets. |
| SEC-27 | Wird die Anwendung über einen Webserver ausgeliefert, MUSS die Übertragung per TLS erfolgen. Browser stellen `crypto.subtle` nur in einem *Secure Context* bereit; über `http://` auf einer anderen Adresse als `localhost` fehlt die Web-Crypto-API vollständig. |
| SEC-28 | Fehlt der Secure Context, MUSS die Anwendung dies beim Laden erkennen, verständlich melden und die Bedienelemente zum Anlegen und Entsperren sperren — statt später mit einem Laufzeitfehler abzubrechen. |
| SEC-29 | Ein ausliefernder Server MUSS `frame-ancestors 'none'` als HTTP-Header setzen. Im `<meta>`-Tag wird die Direktive vom Browser ignoriert und ist dort nicht durchsetzbar. |
| SEC-30 | Ein Container-Abbild DARF nur das Auslieferverzeichnis und die Serverkonfiguration enthalten — keinen Quellcode, keine Dokumentation und unter keinen Umständen eine Vault-Datei. |

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

### 5.1 Format v2 — `mmo-vault-v2`

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

### 5.2 Format v1 (Legacy, nur lesend)

Ein einzelnes JSON-Objekt `{salt, iterations, iv, data}` mit allen Daten inklusive Anhängen in einem Block. Wird beim Laden erkannt und beim nächsten Speichern automatisch nach v2 überführt.

### 5.3 Kompatibilitätsregeln

- Unbekannte Blocktypen MÜSSEN beim Lesen ignoriert werden.
- Fehlende Eintragsfelder MÜSSEN auf dokumentierte Vorgabewerte fallen.
- Ein `file`-Block ohne `id` im Klartext stammt aus einer Version vor 1.0 und wird ohne Bindungsprüfung akzeptiert.

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
| NFR-08 | Die Auslieferung als Container MUSS ohne Build-Schritt auskommen und ausschließlich aus statischem Dateiversand bestehen. Das Auslieferverzeichnis ist `mmo_vault/public_html/`, der Index `mmo_vault.html`. |
| NFR-09 | Der Container MUSS als unprivilegierter Benutzer auf einem Port oberhalb 1024 laufen und mit read-only Wurzeldateisystem sowie ohne Capabilities startfähig sein. |
| NFR-10 | Die Anwendungsdatei SOLL mit `Cache-Control: no-cache` ausgeliefert werden, damit Anwender eine neue Version unmittelbar erhalten. Revalidierung per ETag ist erwünscht, dauerhaftes Caching nicht. |

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

### 9.5 Auslieferung

- [x] Konsole beim Laden frei von Fehlern und Warnungen der Anwendung
- [x] Keine Netzwerkanfrage; CSP ohne Verstoß
- [x] Fehlender Secure Context wird erkannt: Hinweis in beiden Sprachen, Bedienelemente gesperrt, kein Laufzeitfehler
- [ ] Funktionsprüfung in Chrome, Edge, Firefox und Safari
- [ ] Prüfung des Ersatzverhaltens ohne FSA (Download-Pfad) und ohne `BarcodeDetector`

### 9.6 Container-Auslieferung

- [x] `docker build` läuft fehlerfrei durch
- [x] `nginx -t` bestätigt die Konfiguration ohne Warnungen
- [x] Aufruf von `http://localhost:8080/` liefert `mmo_vault.html` ohne Pfadangabe, byteidentisch zur Quelldatei
- [x] Auslieferverzeichnis enthält ausschließlich `mmo_vault.html`, Verzeichnis 755 / Datei 644
- [x] Kein Quellcode, keine Dokumentation, keine Vault-Datei und keine nginx-Willkommensseite im Abbild
- [x] Container startet mit `read_only: true`, `cap_drop: ALL` und `no-new-privileges`; Healthcheck wird `healthy`; Prozess läuft als uid 101
- [x] Antwort trägt `Content-Security-Policy` mit `frame-ancestors 'none'`, dazu `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy` und `Permissions-Policy`
- [x] `Cache-Control: no-cache` mit funktionierender ETag-Revalidierung (zweiter Aufruf → 304)
- [x] Nur GET und HEAD werden bedient; POST und PUT → 405
- [x] `/index.html`, `/50x.html` und Pfad-Traversal → 404; `/favicon.ico` → 204 ohne Logeintrag
- [x] Anlegen, Eintrag mit generiertem Passwort und QR-2FA, Speichern-Roundtrip und Sperren funktionieren über den Container
- [x] Aufruf über einen Nicht-localhost-Hostnamen ohne TLS zeigt den Secure-Context-Hinweis statt einer scheinbar funktionierenden Oberfläche
- [x] Security-Header gehen unverändert durch einen TLS-terminierenden Reverse Proxy; Inhalt bleibt byteidentisch
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
