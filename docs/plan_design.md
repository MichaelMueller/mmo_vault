# Design der Website übernehmen, Verwaltung auf dem Handy brauchbar machen

**Stand:** 2026-09-03 · **Version:** 2.2.0

Zwei Vorhaben, die sich berühren: das Aussehen wird das von
`michaelmuelleronline.de`, und die Verwaltungsseite wird auf einem Telefon
bedienbar. Das zweite ist der größere Eingriff — es geht dabei nicht um
Abstände, sondern um vier Stellen, an denen `prompt()` Eingaben abfragt, die
niemand blind richtig tippen kann.

---

## 1. Was das Design ausmacht

Aus `app/static/css/base.css` und `layout.css` der Website:

| | |
|---|---|
| Flächen | `--bg-0 #0b0f14`, `--bg-1 #10161e`, `--surface-solid #121923`, Rahmen `rgba(255,255,255,.09)` |
| Text | `--text-hi #e6edf3`, `--text-mid #9aa7b4`, `--text-dim #8494a3` |
| Akzent | Amber `--accent #f59e0b`, weich `#fbbf24`, Schein `rgba(245,158,11,.15)` |
| Schrift | **Space Grotesk** (500/700) für Überschriften und Knöpfe, **Inter** (400/600) für Fließtext |
| Form | `--radius 16px`, `--radius-sm 10px`, Knöpfe rund (`999px`) |
| Typo-Skala | `--step--1` bis `--step-4` als `clamp()`, also von sich aus responsiv |
| Fokus | `2px solid var(--accent)`, `outline-offset: 3px` |

Die Schriften sind selbst gehostet (vier `woff2`, zusammen 74 KB) — kein CDN,
das bleibt so.

### 1.1 Serverseiten (Anmeldung, Verwaltung)

Vollständige Übernahme. Bisher steht das gesamte CSS inline in `base.html`;
das wird eine Datei `mmo_vault/server/static/vault.css`, und die Schriften
kommen daneben. Dafür nötig:

- ein `StaticFiles`-Mount auf `/static` (bisher gibt es keinen; `server.js`
  liegt dort schon und ist über `/api/injection` ohnehin öffentlich)
- die CSP der Serverseiten von `style-src 'unsafe-inline'` auf
  `style-src 'self'` **verschärfen** und `font-src 'self'` ergänzen

Das ist eine Verbesserung, kein Zugeständnis: die Seiten kommen damit ohne
inline-Styles aus.

### 1.2 Die Vault-Anwendung selbst

Hier gilt die Ein-Datei-Zusage: keine externen Ressourcen, offline lauffähig
(SEC-20/21). Deshalb:

- **Farben, Radien, Typo-Skala, Knopfformen** werden übernommen — das ist der
  überwiegende Teil des Wiedererkennungswerts.
- **Space Grotesk** (500 und 700, zusammen 26 KB) wird als `data:`-URI
  eingebettet, für Überschriften und Knöpfe. Die Datei wächst um ~35 KB auf
  ~310 KB.
- **Inter** wird *nicht* eingebettet. Fließtext bleibt beim System-Stack; das
  spart 48 KB und fällt am wenigsten auf.
- Die CSP der Anwendung bekommt `font-src data:` — eine `data:`-URI kann keine
  Verbindung aufbauen, die Zusage aus SEC-20 bleibt also wörtlich gültig. Der
  Policy-Text in den Anforderungen wird entsprechend nachgezogen.

---

## 2. Warum die Verwaltung auf dem Handy nicht geht

Vier Befunde, vom schwersten zum leichtesten:

**2.1 `prompt()` mit erfundener Syntax.** Freigaben werden über ein
Systemfenster abgefragt, in das man `mueller, #team!` tippen soll — `#` für
Gruppe, `!` für nur lesen. Das ist auf keinem Gerät zu erraten und auf einem
Telefon in einem einzeiligen Systemdialog nicht zu korrigieren. Erschwerend:
der Name muss der **Kontoname** sein (`Admin`, `Kollege`), nicht die
Mailadresse — und den zeigt der Dialog nirgends an. Dieselbe Mechanik trifft
Gruppenmitglieder (Zeile 283) und lokale Gruppen eines Kontos (Zeile 253).
Ein Tippfehler ergibt keinen Fehler, sondern eine falsche Freigabe oder ein
400, das in der Meldungszeile ganz oben landet — auf dem Handy außer Sicht.

**2.2 Sechs Tabellen mit bis zu sieben Spalten.** Bei 360 px Breite bleiben pro
Spalte ~50 px. Die Tabelle schiebt sich über den Rand, und weil sie in keinem
scrollbaren Behälter steckt, scrollt die ganze Seite waagerecht.

**2.3 Die Aktionsknöpfe.** Vier bis fünf Textknöpfe pro Zeile, mit
`margin-right: 6px` aneinandergehängt, in einer Tabellenzelle. Sie brechen
unkontrolliert um und liegen unter der 44-px-Grenze, die man mit dem Daumen
sicher trifft.

**2.4 Die Anlege-Zeilen.** `.row` mit `flex-wrap` und `flex: 1 1 100px` ergibt
auf schmalen Geräten Felder von 100 px Breite nebeneinander statt untereinander.

---

## 3. Was daraus wird

### 3.1 Statt `prompt()`: ein `<dialog>` mit echten Bedienelementen

Das native `<dialog>`-Element, mit CSS gestaltet — kein selbstgebautes
Overlay, keine Bibliothek. `showModal()` bringt Fokusfalle, Escape und den
`::backdrop` mit; das Formular darin schließt per `method="dialog"`.

**Freigaben** (der wichtigste Fall) bekommen einen eigenen Dialog:

```
Freigaben für „Team-Vault"

  Admin            [Schreiben ▾]  [×]
  #team            [Lesen    ▾]  [×]

  Hinzufügen:  [ Konto oder Gruppe ▾ ]  [Schreiben ▾]  [+]

                              [Abbrechen]  [Speichern]
```

Die Auswahlliste wird aus `/api/users` und `/api/groups` gefüllt — Gruppen mit
`#` davor und in einer eigenen `<optgroup>`. Damit ist die Frage „wie heißt das
Konto?" beantwortet, bevor sie entsteht, und die Syntax entfällt ersatzlos.
Gespeichert wird wie bisher mit einem `PUT` auf `/api/vaults/{id}/access`, das
den ganzen Satz ersetzt.

**Gruppenmitglieder** und **lokale Gruppen eines Kontos**: derselbe Dialog in
einfacher Form — eine Liste mit Kästchen, aus den vorhandenen Konten bzw.
Gruppen erzeugt.

**Löschabfragen** bleiben `confirm()`. Eine Ja/Nein-Frage funktioniert dort
überall und braucht keine Eingabe.

### 3.2 Tabellen, die auf dem Handy Karten werden

Unterhalb von 720 px wird jede Zeile zu einer Karte: die Spaltenüberschrift
wandert über `data-label` vor den Wert, die Kopfzeile verschwindet. Kein
zweites Markup, nur CSS — die Tabelle bleibt für Tastatur und Vorleser eine
Tabelle.

```css
@media (max-width: 720px) {
  .list thead { display: none; }
  .list tr { display: block; border: 1px solid …; border-radius: …; }
  .list td { display: grid; grid-template-columns: 8rem 1fr; }
  .list td::before { content: attr(data-label); color: var(--text-dim); }
}
```

### 3.3 Aktionen als Symbolknöpfe

Wie auf der Website (`.icon-btn`, 32 px, im Raster zentriert), hier auf 40 px
für Finger, in einem `flex`-Behälter mit `gap` statt `margin-right`. Auf
`(hover: none)` bleiben sie voll sichtbar — der Kommentar in der `admin.css`
der Website sagt genau warum.

### 3.4 Anlege-Zeilen als Formulare

`.form` mit `flex-direction: column` und `gap`, ab 720 px zweispaltig. Jedes
Feld bekommt eine echte `<label>` statt eines Platzhalters — ein Platzhalter
verschwindet beim Tippen, und auf dem Handy ist das die einzige Beschriftung.

---

## 4. Reihenfolge

| Schritt | Inhalt | Fertig, wenn |
|---|---|---|
| 1 | `/static`-Mount, `vault.css`, Schriften, CSP verschärft | Anmeldeseite im neuen Design, keine inline-Styles mehr |
| 2 | `base.html` und `login.html` umgestellt | beides bei 360 px ohne Querscrollen |
| 3 | Verwaltung: Struktur, Karten-Tabellen, Symbolknöpfe, Formulare | alle sechs Abschnitte bei 360 px bedienbar |
| 4 | Freigabe-, Mitglieder- und Gruppendialog | keine `prompt()` mehr im Projekt |
| 5 | Vault-Anwendung: Tokens, Schrift, Knöpfe | Anwendung und Serverseiten sehen wie eine Familie aus |
| 6 | Anforderungen, README, Tests | SEC-20-Policy nachgezogen, Tests grün |

## 5. Was ausdrücklich nicht passiert

- Keine Animationen aus `motion.css`. Ein Werkzeug, keine Bühne — dieselbe
  Begründung steht im Kopf der `admin.css` der Website.
- Kein Hellmodus. Beide Projekte sind `color-scheme: dark`.
- Keine Änderung an der API. Der Umbau ist Oberfläche; die Endpunkte bleiben,
  wie sie sind, samt ihrer Tests.
