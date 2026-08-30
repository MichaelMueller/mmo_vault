# syntax=docker/dockerfile:1

# Two ways to run MMO Vault, and one Dockerfile for both.
#
#   static   nginx plus the single HTML file. No Python, no database, no state.
#            This is the whole application: a file the browser opens.
#   server   the FastAPI service. Sign-in through an identity provider, an
#            allowlist, groups, shared vaults, history - and it serves the same
#            HTML file, with the two changes from injection.py.
#
#   docker build --target static -t mmo-vault:2.1.0 .
#   docker build --target server -t mmo-vault-server:2.1.0 .
#
# Or through compose, where the profile picks the target:
#   docker compose up -d                     -> static
#   docker compose --profile server up -d    -> server
#
# IMPORTANT for both: over any address other than localhost there MUST be TLS in
# front. crypto.subtle only exists in a secure context, and the identity
# providers accept only https redirect URIs - over http:// on a LAN address
# neither works. Details in the README.


# =============================================================================
# static - unchanged from the versions before the server existed
# =============================================================================
FROM nginx:1.27-alpine AS static

LABEL org.opencontainers.image.title="MMO Vault" \
      org.opencontainers.image.description="Lokaler Passwortmanager als einzelne HTML-Datei" \
      org.opencontainers.image.version="2.1.0" \
      org.opencontainers.image.licenses="Apache-2.0"

# Replaces the main configuration entirely. The image's default server expects
# index.html and is removed so it cannot come back in through conf.d/.
COPY docker/nginx.conf /etc/nginx/nginx.conf
RUN rm -f /etc/nginx/conf.d/default.conf \
 && rm -rf /usr/share/nginx/html

# Its own directory rather than /usr/share/nginx/html: the base image keeps the
# nginx welcome page and 50x.html there, and both would stay reachable.
COPY mmo_vault/public_html/ /srv/mmo-vault/

# Permissions set explicitly: from a Windows build context the file arrives with
# the execute bit. Directory and file need different modes - a shared
# COPY --chmod=644 takes the x bit off the directory and nginx answers 403.
RUN chmod 755 /srv/mmo-vault && chmod 644 /srv/mmo-vault/*

# Unprivileged from the start - the nginx user (uid 101) exists in the base
# image. Together with port 8080 from the configuration the container needs no
# capabilities and runs with a read-only root filesystem (see compose.yaml).
USER nginx
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/ || exit 1
CMD ["nginx", "-g", "daemon off;"]


# =============================================================================
# builder - dependencies into a virtual environment
# =============================================================================
FROM python:3.13-slim AS builder

# Only the requirements first: this layer is cached as long as they do not
# change, and rebuilding after a code change stays quick.
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /venv \
 && /venv/bin/pip install --no-cache-dir --upgrade pip \
 && /venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt


# =============================================================================
# server - the FastAPI service
# =============================================================================
FROM python:3.13-slim AS server

LABEL org.opencontainers.image.title="MMO Vault Server" \
      org.opencontainers.image.description="Serverbetrieb mit OIDC-Anmeldung, Gruppen und Vault-Historie" \
      org.opencontainers.image.version="2.1.0" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=builder /venv /venv

WORKDIR /app
COPY mmo_vault.py alembic.ini /app/
COPY mmo_vault/ /app/mmo_vault/

# The data directory is the one writable place. Everything else can stay
# read-only, which is what compose.yaml relies on.
RUN mkdir -p /app/var/vaults \
 && chown -R 10001:10001 /app/var

# A fixed, unprivileged uid rather than a named user: it has to match whoever
# owns the volume on the host, and a name says nothing about that.
USER 10001:10001

# The only two environment variables the service reads. Everything else -
# origin, providers, limits - lives in the database and is set by `setup`
# once and by the administration afterwards.
ENV PATH="/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MMO_VAULT_DIR=/app/var \
    MMO_VAULT_DATABASE_URL=sqlite:////app/var/mmo_vault.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)"

# Setup runs as its own one-off, not on every start - it writes the origin,
# the primary provider and the first administrators into the database:
#   docker compose --profile server run --rm mmo-vault-server setup
ENTRYPOINT ["python", "/app/mmo_vault.py"]
CMD ["start", "--host", "0.0.0.0"]
