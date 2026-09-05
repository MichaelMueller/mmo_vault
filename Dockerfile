# syntax=docker/dockerfile:1

# The MMO Vault server.
#
#   docker build -t mmo-vault-server:2.2.0 .
#   docker compose up -d --build
#
# The other way to run MMO Vault needs no image at all: download
# mmo_vault/public_html/mmo_vault.html and open it in a browser.
#
# IMPORTANT: over any address other than localhost there MUST be TLS in front.
# crypto.subtle only exists in a secure context, and the identity providers
# accept only https redirect URIs - over http:// on a LAN address neither
# works. Details in the README.


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
      org.opencontainers.image.version="2.2.0" \
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

EXPOSE 4080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:4080/api/health').status==200 else 1)"

# Setup runs as its own one-off, not on every start - it writes the origin,
# the primary provider and the first administrators into the database:
#   docker compose run --rm mmo-vault-server setup
ENTRYPOINT ["python", "/app/mmo_vault.py"]
CMD ["start", "--host", "0.0.0.0"]
