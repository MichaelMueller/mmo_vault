# syntax=docker/dockerfile:1

# MMO Vault ist eine einzelne statische HTML-Datei ohne Abhängigkeiten und ohne
# Build-Schritt. Es gibt daher nichts zu kompilieren und keine Build-Stage —
# das Image besteht aus nginx plus dem Auslieferverzeichnis.
#
# Bauen:    docker build -t mmo-vault:1.9.0 .
# Starten:  docker run --rm -p 127.0.0.1:4080:8080 mmo-vault:1.9.0
# Aufrufen: http://127.0.0.1:4080/
#
# WICHTIG: Über eine andere Adresse als localhost MUSS TLS davor stehen.
# crypto.subtle gibt es nur in einem Secure Context; über http:// auf einer
# LAN-IP oder Domain fehlt die Web-Crypto-API und der Vault lässt sich weder
# anlegen noch entsperren. Details in der README.

FROM nginx:1.27-alpine

LABEL org.opencontainers.image.title="MMO Vault" \
      org.opencontainers.image.description="Lokaler Passwortmanager als einzelne HTML-Datei" \
      org.opencontainers.image.version="1.9.0" \
      org.opencontainers.image.licenses="Apache-2.0"

# Ersetzt die Hauptkonfiguration komplett. Der Default-Server des Images erwartet
# index.html und wird entfernt, damit er nicht über conf.d/ wieder hereinkommt.
COPY docker/nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf \
 && rm -rf /usr/share/nginx/html

# Auslieferverzeichnis: ein eigener Pfad statt /usr/share/nginx/html, weil dort im
# Basisimage die nginx-Willkommensseite und 50x.html liegen — die würden sonst
# unter /index.html erreichbar bleiben.
COPY mmo_vault/public_html/ /srv/mmo-vault/

# Rechte explizit setzen: aus einem Windows-Build-Kontext kommt die Datei sonst mit
# Ausführungsbit an. Verzeichnis und Datei brauchen unterschiedliche Modi — ein
# gemeinsames COPY --chmod=644 nimmt dem Verzeichnis das x-Bit und nginx antwortet
# dann auf alles mit 403.
RUN chmod 755 /srv/mmo-vault && chmod 644 /srv/mmo-vault/*

# Unprivilegiert ab Start — der Benutzer nginx (uid 101) existiert im Basisimage.
# Zusammen mit dem Port 8080 aus der Konfiguration braucht der Container keine
# Capabilities und läuft mit read-only Wurzeldateisystem (siehe compose.yaml).
USER nginx

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
