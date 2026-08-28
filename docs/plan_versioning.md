# MMO Vault — Umsetzungsplan Datensatz-Versionierung

**Stand:** 2026-08-02
**Zielversion:** 1.9.0 (vor dem Server-Umbau)
**Status:** Planung, noch nicht umgesetzt

Vorgelagert zu [plan_server.md](plan_server.md). Die Versionierung gehört in die
Datei, nicht in den Server — sonst hätte der Offline-Betrieb sie nicht.

---

## 1. Ziel

Jede Änderung an einem Eintrag hebt den **vorherigen** Stand auf. Ein
versehentlich überschriebenes Passwort, eine gelöschte Notiz oder ein komplett
gelöschter Eintrag lassen sich zurückholen — im Server-Modus **und** offline per
Doppelklick, ohne jeden Unterschied.

Der Leitsatz für den gesamten Entwurf: **Der Verlauf liegt in derselben
verschlüsselten Datei wie die Einträge.** Damit gilt automatisch alles, was heute
schon gilt — eine Datei zum Sichern, ein Master-Passwort, keine
Serverabhängigkeit, kein zweiter Speicherort.

---

## 2. Zwei Ebenen, klar getrennt

| Ebene | Was | Wo |
|---|---|---|
| **Datensatz-Versionen** | vorherige Stände einzelner Einträge, inklusive Geheimnisse | in der Vault-Datei (dieser Plan) |
| **Datei-Generationen** | vollständige frühere Vault-Dateien | Betreiber-Backup, im Server-Modus zusätzlich serverseitig ([plan_server.md](plan_server.md), 5.5) |

Dieser Plan behandelt die erste Ebene. Zur zweiten siehe Kapitel 11 — dort steht
ausdrücklich, warum ich sie **nicht** in die Datei legen würde.

Bereits vorhanden und davon unberührt: der **Änderungsverlauf**
(`state.history`), der bewusst nur Zeitstempel, Aktion und Titel führt und
niemals Geheimnisse. Der bleibt, wie er ist. Die neuen Versionen sind etwas
anderes: sie enthalten die alten Werte selbst.

---

## 3. Dateiformat v3

### 3.1 Neuer Blocktyp

```
{"type":"header","format":"mmo-vault-v3","salt":"…","iterations":600000}
{"type":"text","iv":"…","data":"…"}
{"type":"vers","iv":"…","data":"…"}      ← neu, beliebig viele
{"type":"file","id":"…","iv":"…","data":"…"}
```

Entschlüsselter Inhalt eines `vers`-Blocks:

```
{ "v": [
  { "id":   "e…",             Eintrags-ID
    "num":  42,               laufende Nummer zum Zeitpunkt der Änderung
    "ts":   1754132400000,    Zeitstempel der Ablösung
    "grund": "bearbeitet" | "geloescht" | "wiederhergestellt",
    "stand": { … }            vollständiger Eintrag VOR der Änderung
  }
] }
```

Gespeichert wird immer der **vorherige** Stand, nicht der neue. Der aktuelle
Stand steht ohnehin im Textblock; damit gibt es keine Dopplung und der jüngste
Stand ist ohne Rekonstruktion sofort da.

### 3.2 Anfügen statt neu schreiben

Beim Speichern entsteht **höchstens ein neuer** `vers`-Block mit den Versionen,
die seit dem letzten Speichern angefallen sind. Alle bestehenden Blöcke werden
unverändert als Chiffrat übernommen — exakt das Verfahren, das
`buildVaultLines()` heute schon für Anhänge über `state.fileBlockLines` nutzt.
Kein Neu-Verschlüsseln, keine mit der Historie wachsende Speicherdauer.

Daraus folgt der wichtigste Punkt für die Geschwindigkeit: **Beim Entsperren
wird kein einziger `vers`-Block entschlüsselt.** Sie bleiben als Chiffrat in
`state.versionBlockLines` liegen, genau wie Anhänge heute. Entsperren bleibt
schnell, auch bei jahrelanger Historie.

### 3.3 Index im Textblock

Damit die Oberfläche „Verlauf (7)" auf einer Karte anzeigen kann, ohne etwas zu
entschlüsseln, kommt ein schlanker Index in den Textblock:

```
"versionIndex": { "e…": { "n": 7, "last": 1754132400000 } }
```

Nur Zähler und Zeitstempel, keine Werte. Für gelöschte Einträge steht der Eintrag
mit `"weg": true` und dem letzten Titel darin — nur so ist ein gelöschter Eintrag
im Papierkorb überhaupt auffindbar.

### 3.4 Kompaktierung

`vers`-Blöcke werden nie einzeln geändert. Aufgeräumt wird gesammelt, sobald eine
Schwelle überschritten ist (Vorgabe: mehr als 32 Blöcke oder mehr als ein Viertel
überflüssige Versionen). Dann werden alle entschlüsselt, die
Aufbewahrungsregeln angewandt und ein einziger neuer Block geschrieben. Das ist
derselbe Vorgang, der beim Master-Passwort-Wechsel ohnehin nötig ist.

### 3.5 Rückwärts- und Vorwärtskompatibilität

- **v1/v2 lesen** wie bisher; `versionIndex` fehlt dann einfach, der Verlauf
  beginnt ab der ersten Änderung unter 1.9.0.
- **Wichtige Warnung:** `parseVaultText()` in 1.8.0 ignoriert unbekannte
  Blocktypen. Eine v3-Datei lässt sich mit einer **alten** Anwendung also
  problemlos öffnen — beim nächsten Speichern dort sind aber **alle Versionen
  weg**, kommentarlos. Nachträglich reparieren lässt sich das nicht, weil 1.8.0
  bereits ausgeliefert ist. Konsequenzen:
  - der Umstand gehört in README und Freigabehinweise,
  - v3 wird erst beim ersten Speichern nach einer echten Änderung geschrieben,
    nicht schon beim bloßen Öffnen,
  - der About-Dialog zeigt das Format der geladenen Datei, damit man weiß, womit
    man es zu tun hat.

---

## 4. Wann eine Version entsteht

| Auslöser | Version vom vorherigen Stand | Grund |
|---|---|---|
| Eintrag im Dialog gespeichert, Werte tatsächlich verändert | ja | `bearbeitet` |
| Eintrag gelöscht | ja, Grabstein mit letztem Stand | `geloescht` |
| Version wiederhergestellt | ja, vom aktuellen Stand | `wiederhergestellt` |
| Eintrag dupliziert | nein — die Kopie startet ohne Verlauf | — |
| CSV-Import, neue Einträge | nein | — |
| Nur Anhang hinzugefügt oder entfernt | ja, aber nur Metadaten (siehe 5) | `bearbeitet` |
| Schlüsselableitung angehoben, Master-Passwort gewechselt | nein — inhaltlich ändert sich nichts | — |

Vor dem Anlegen wird feldweise verglichen: ein Öffnen und Schließen des Dialogs
ohne Änderung erzeugt **keine** Version. Sonst wäre die Liste nach kurzer Zeit
unbrauchbar.

Alles passiert nur im Speicher; erst das Speichern schreibt in die Datei. Ein
misslungener Bearbeitungslauf lässt sich weiterhin durch Sperren ohne Speichern
verwerfen — dieselbe Regel wie beim CSV-Import.

---

## 5. Anhänge

Hier liegt das Größenproblem, deshalb ausdrücklich:

- Eine Version speichert Anhänge **nur als Verweis** (id, Name, Typ, Größe), nie
  die Rohdaten erneut.
- Ein Anhang, der aus dem aktuellen Eintrag entfernt wird, dessen Block aber noch
  von einer aufbewahrten Version referenziert wird, **bleibt in der Datei**. Die
  Bereinigung verwaister Blöcke in `buildVaultLines()` muss dafür zusätzlich die
  Versionen berücksichtigen — sonst zeigt eine wiederhergestellte Version auf
  einen gelöschten Block.
- Fällt die letzte referenzierende Version durch die Aufbewahrungsregel weg,
  verschwindet der Anhangsblock bei der nächsten Kompaktierung.
- Die Oberfläche muss das benennen: „Ein gelöschter Anhang belegt weiter Platz,
  solange eine Version ihn braucht."

---

## 6. Aufbewahrung

Pro Vault einstellbar, mit Vorgaben:

| Einstellung | Vorgabe |
|---|---|
| Versionen je Eintrag | 20 |
| Höchstalter | unbegrenzt |
| Papierkorb für gelöschte Einträge | 90 Tage |
| Gesamtobergrenze | keine, aber Warnung ab 5 MB Versionsanteil |

Angewandt wird beim Kompaktieren, nicht bei jedem Speichern — sonst müsste jedes
Mal alles entschlüsselt werden. Das Wegfallen von Versionen kommt als Zeile in
den bestehenden Änderungsverlauf.

Zusätzlich manuell: **„Verlauf dieses Eintrags löschen"** und **„Papierkorb
leeren"**. Beides erzwingt sofortiges Kompaktieren — ein Löschen, das erst
irgendwann wirkt, wäre bei Geheimnissen die falsche Zusage.

---

## 7. Bedienung

- Auf der Karte ein unaufdringlicher Zähler „Verlauf (7)", nur wenn es Versionen
  gibt; Klick öffnet den Verlauf. Kommt ohne Entschlüsselung aus (Index, 3.3).
- **Verlaufsdialog** je Eintrag: Liste absteigend nach Zeit, jede Zeile mit
  Zeitstempel, Grund und den **Namen** der geänderten Felder („Passwort,
  Notizen") — nicht deren Werten.
- Aufklappen einer Version zeigt die alten Werte. Passwörter und 2FA-Secrets
  bleiben verdeckt, mit denselben Regeln wie sonst: einzeln aufdecken, Kopieren
  leert die Zwischenablage nach 30 Sekunden, beim Sperren wird alles aus dem DOM
  entfernt — auch aus diesem Dialog.
- Aktionen: **ganzen Eintrag wiederherstellen** oder **einzelnes Feld
  übernehmen**. Beides erzeugt selbst eine Version, ist also umkehrbar.
- **Papierkorb** als eigener Filter-Chip neben „Alle": gelöschte Einträge mit
  Restzeit, wiederherstellbar. Ein wiederhergestellter Eintrag behält seine
  ursprüngliche laufende Nummer — die wird nie neu vergeben, ein alter Deep-Link
  `#search=id%3D42` zeigt also wieder auf denselben Eintrag.
- Der Verlauf ist von der Volltextsuche **ausgenommen**. Sonst tauchten alte
  Passwörter unerwartet in Trefferlisten auf.

---

## 8. Sicherheit

- Versionen sind **Geheimnisse** und liegen in denselben AES-256-GCM-Blöcken wie
  alles andere. Der bestehende, absichtlich geheimnisfreie Änderungsverlauf
  (SEC-26) bleibt davon unberührt — beides darf nicht verwechselt werden, weder
  im Code noch in der Oberfläche.
- **Ein gewechseltes Passwort bleibt im Verlauf lesbar.** Das ist der Zweck der
  Sache, verlängert aber die Lebensdauer eines kompromittierten Passworts in der
  Datei. Deshalb bietet der Eintragsdialog nach einem Passwortwechsel an, die
  betroffenen Versionen dieses Eintrags zu verwerfen.
- Beim Master-Passwort-Wechsel müssen alle `vers`-Blöcke mit dem alten Schlüssel
  geladen und mit dem neuen geschrieben werden — analog zu den Anhängen heute.
  Wird das vergessen, ist der Verlauf nach dem Wechsel unlesbarer Müll.
- Beim Sperren wandern entschlüsselte Versionen genauso weg wie Einträge.
- Größe: der Verlauf wächst mit jeder Änderung. Der Warnhinweis aus Kapitel 6 und
  die Anzeige des Versionsanteils im About-Dialog gehören dazu.

---

## 9. Offline und Server sind identisch

Weil alles in der Datei liegt, gibt es **keinen** Unterschied zwischen den
Betriebsarten. Kein zusätzlicher Endpunkt, kein Abgleich, kein Sonderfall im
Client.

Wechselwirkungen mit [plan_server.md](plan_server.md), die dort nachzuziehen
sind:

- Die Strukturprüfung des Servers (5.5) muss `mmo-vault-v3` und den Blocktyp
  `vers` kennen.
- Das Größenlimit (Vorgabe 25 MB) greift wegen der Versionen früher — Vorgabe
  überdenken und die Warnschwelle im Client anzeigen.
- Bei einem Schreibkonflikt (409) gilt weiterhin „neu laden oder als neue Datei
  speichern". Ein Zusammenführen der Versionslisten wäre möglich, ist aber
  ausdrücklich nicht geplant (Kapitel 12).

---

## 10. Umsetzungsreihenfolge

| Phase | Inhalt | Prüfbar durch |
|---|---|---|
| A | Format v3: Lesen, Schreiben, Chiffrat-Wiederverwendung, Migration v1/v2 | Roundtrip; v2-Datei öffnen, speichern, wieder öffnen |
| B | Versionen anlegen (bearbeiten, löschen), Index, Grabsteine | Änderung erzeugt genau eine Version, Öffnen ohne Änderung keine |
| C | Verlaufsdialog, Wiederherstellen ganz und feldweise | Wiederherstellen ist selbst umkehrbar |
| D | Papierkorb inklusive Erhalt der laufenden Nummer | gelöschter Eintrag kehrt mit alter Nummer zurück |
| E | Aufbewahrung, Kompaktierung, Anhangs-Bereinigung mit Versionsbezug | keine verwaisten Verweise nach dem Kompaktieren |
| F | Master-Passwort-Wechsel über alle Blöcke, Sperrverhalten, README, requirements.md | Verlauf nach Passwortwechsel weiter lesbar, Sperren räumt auf |

Version **1.9.0**. Das Format ändert sich, die Betriebsart nicht — deshalb kein
Major. Der Server-Umbau (2.0.0) setzt darauf auf.

---

## 11. Datei-Generationen: bewusste Empfehlung dagegen

Naheliegend wäre, zusätzlich N vollständige frühere Vault-Stände als
`{"type":"snapshot"}`-Blöcke in dieselbe Datei zu legen. Ich rate davon ab:

- Die Dateigröße vervielfacht sich bei jedem Speichern.
- Gegen das, was tatsächlich passiert — gelöschte Datei, defekter Datenträger,
  Sync-Konflikt — hilft es nicht: die Generationen lägen in derselben Datei.
- Gegen abgebrochene Schreibvorgänge schützt bereits der Rollback in
  `writeVaultToHandle()`.
- Der eigentliche Bedarf („ich habe etwas kaputtgemacht") wird von den
  Datensatz-Versionen genauer und billiger abgedeckt.

Stattdessen: **„Sicherungskopie herunterladen"** als ausdrückliche Aktion mit
Datum im Dateinamen — offline wie im Server-Modus, ein Klick, keine
Formatänderung. Im Server-Modus zusätzlich die serverseitigen Generationen.

Falls du Datei-Generationen dennoch in der Datei willst, ist das ein kleiner
Zusatz zu Phase A — sag Bescheid, dann plane ich es ein.

---

## 12. Bewusst nicht enthalten

- Zusammenführen von Versionen aus zwei parallel bearbeiteten Dateien
- Verlauf für Einstellungen, Tags oder den Zähler der laufenden Nummer
- Zeilenweiser Textvergleich bei Freitext-Einträgen; gezeigt werden geänderte
  **Felder**, nicht Wortunterschiede
- Signierte oder manipulationssichere Verlaufsketten
- Suche innerhalb des Verlaufs

---

## 13. Nötige Ergänzungen in requirements.md

- Kapitel 5 Dateiformat: v3, Blocktyp `vers`, Anfügeverfahren, Kompaktierung,
  Migration und der Hinweis auf Datenverlust bei Bearbeitung mit 1.8.0
- Neue FUN-Anforderungen: Versionsanlage und Auslöser, Verlaufsdialog,
  Wiederherstellen ganz und feldweise, Papierkorb mit Nummernerhalt,
  Aufbewahrungsregeln, manuelles Löschen des Verlaufs
- Neue SEC-Anforderungen: Versionen als Geheimnisse behandeln, Abgrenzung zu
  SEC-26, Aufräumen beim Sperren, vollständige Neuverschlüsselung beim
  Master-Passwort-Wechsel, Anhangs-Bereinigung ohne verwaiste Verweise
- Kapitel 3.5 Bedrohungsmodell: verlängerte Lebensdauer alter Passwörter in der
  Datei
- Kapitel 9 Abnahmekriterien: Roundtrip v2→v3, Wiederherstellen,
  Papierkorbablauf, Verlauf nach Passwortwechsel lesbar, keine verwaisten
  Anhangsblöcke
