# MMO Vault

**A password manager in a single HTML file.** No installation, no dependencies, no build step — the vault is an encrypted file that belongs to you and that you store yourself. Double-click it and it works, with no server anywhere.

An optional server exists for the case the single file cannot cover: several people, one vault. It stores ciphertext and nothing else — the master password is entered in the browser and never reaches it.

| Unlocking | Working |
|---|---|
| [![Login screen with vault file selection](docs/login_screen.png)](docs/login_screen.png) | [![Main view with entries, tags and search](docs/main_screen.png)](docs/main_screen.png) |

---

## Overview

- **AES-256-GCM**, key from PBKDF2-HMAC-SHA256 with 600,000 iterations, 16-byte salt, own 96-bit IV per block. Old files are raised to the current iteration count on unlock.
- **No network connection**, enforced by `default-src 'none'; connect-src 'none'` — no CDN, no fonts, no telemetry.
- **Two entry types:** login (URL, username, password, 2FA, notes) and free text with Markdown.
- **Custom fields** on free-text entries: any number of labelled fields — a line of text, a password, or a multi-line block. Each row carries a copy button, and tapping the row copies as well.
- **2FA/TOTP** per RFC 6238, including 8 digits and SHA-256/512. QR codes import as an image where the browser offers `BarcodeDetector`.
- **File attachments** in their own encrypted blocks, decrypted on download rather than on unlock.
- **Tags, full-text search and field filters** (`id=42`, `tag=work`, `typ=freitext`), combinable; `#search=…` as a deep link.
- **Record versions and a trash.** Every change keeps the previous state; restoring is itself reversible. Nothing expires on its own — the application warns about the file size and deletes in bulk on request.
- **CSV import** with fixed English column names and a template in the dialog.
- **Auto-lock** with countdown, 5 minutes by default. Locking discards keys, entries and revealed values.
- **German and English**, switchable at any time.

Chrome and Edge save directly into the file and import QR codes; Firefox and Safari fall back to downloading and to manual entry. Details, file format and threat model: [docs/requirements.md](docs/requirements.md).

> **Backups are mandatory and there is no password recovery.** The application versions records, not the file. If the master password is gone, the data is gone. A self-built tool, not audited security software.

---

## The local file

1. Download [mmo_vault/public_html/mmo_vault.html](mmo_vault/public_html/mmo_vault.html).
2. Open it in a browser — a double-click is enough.
3. **Create a new file**, choose a master password, add entries, **Save**.

On the first save the browser asks for a location and writes into that file from then on. Browsers without the File System Access API download a copy each time instead.

Serving the file over the network needs **HTTPS**: `crypto.subtle` only exists in a secure context, and over `http://` on anything but `localhost` the vault can neither be created nor unlocked. The application detects this and says so instead of failing cryptically.

---

## Server installation

The server adds sign-in through an identity provider (Microsoft 365, Google, or any OIDC provider with discovery), an allowlist per provider that decides who gets in, groups — managed locally or mirrored from the provider at sign-in — vaults shared with people or groups, a file lock plus ETag against lost writes, and an unlimited history of every save. It serves the application itself; there is no separate web server.

**It needs a reverse proxy in front of it, terminating TLS.** That is a precondition, not a recommendation: the service speaks plain HTTP and binds to loopback, browsers only offer `crypto.subtle` in a secure context, and the identity providers accept `https` redirect URIs only. Without HTTPS the vault can neither be created nor unlocked from anywhere but `localhost`. Whichever proxy you already run — nginx, Caddy, Traefik, Apache — is the right one; see [Reverse proxy](#reverse-proxy) below.

It reads exactly two environment variables; everything else lives in the database and is changed at `/admin` without a restart:

| Variable | Meaning | Default |
|---|---|---|
| `MMO_VAULT_DIR` | data directory: vault files and, by default, the SQLite database | `/app/var` in the container |
| `MMO_VAULT_DATABASE_URL` | SQLAlchemy URL | `sqlite:///<MMO_VAULT_DIR>/mmo_vault.db` |

`setup` asks for the public origin, the primary identity provider and the first administrator addresses, and writes them into the database. It runs once, before the first start.

### With compose from this repository

```bash
docker compose run --rm mmo-vault-server setup
docker compose up -d --build                     # → http://127.0.0.1:4080/
```

Port and bind address come from `VAULT_PORT` and `VAULT_BIND`.

### With plain Docker

```bash
docker build -t mmo-vault-server:2.1.0 .
docker volume create vault-data

docker run --rm -it -v vault-data:/app/var mmo-vault-server:2.1.0 setup

docker run -d --name mmo-vault-server --restart unless-stopped \
  -p 127.0.0.1:4080:4080 -v vault-data:/app/var \
  --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true \
  mmo-vault-server:2.1.0
```

### Inside an existing compose stack

One service to paste in, without publishing a port — the reverse proxy in the same network reaches it at `http://vault:4080`:

```yaml
services:
  vault:
    build: { context: ./mmo-vault }          # or: image: mmo-vault-server:2.1.0
    restart: unless-stopped
    environment:
      MMO_VAULT_DIR: /app/var
    volumes:
      - vault-data:/app/var
    networks: [proxy]
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]

volumes:
  vault-data:
```

Run the one-off setup with `docker compose run --rm vault setup`.

### Backup scripts

Every executable file in `<MMO_VAULT_DIR>/backup_scripts/` runs after a vault was saved or restored — in name order, so `10-copy` goes before `20-notify`. The directory is created by `setup`; until something lies in it, nothing happens.

The scripts run *after* the response, so a slow one never delays the save, and none of them can break one: a script that fails, hangs (cut off after 120 s) or cannot be started is logged and otherwise ignored — the vault is already written at that point. `chmod -x` parks a script without moving it; names starting with `.` or `_` are skipped.

What a script gets, in its environment — no arguments, no shell, so a vault name cannot turn into a command:

| Variable | |
|---|---|
| `MMO_VAULT_FILE` | absolute path of the file that just changed |
| `MMO_VAULT_NAME` | the vault's name as shown in the interface |
| `MMO_VAULT_ID` | its id, which is also its directory under `vaults/` |
| `MMO_VAULT_GENERATION` | number of the generation just kept |
| `MMO_VAULT_ACTOR` | who saved |
| `MMO_VAULT_DIR` | the data directory |

What travels is ciphertext, which is what makes a copy into a sync folder defensible at all — the target never sees anything readable.

[`mmo_vault/examples/backup_scripts/10-nextcloud.sh`](mmo_vault/examples/backup_scripts/10-nextcloud.sh) writes the vault over a fixed path in Nextcloud and scans it in. Always the same file name — the server keeps every generation anyway, so the folder has no reason to grow:

```sh
#!/bin/sh
set -eu

CONTAINER=nextcloud
NC_USER=admin          # the user id = the directory name under data/, often a mail address
FOLDER=Vault-Backup

TARGET="$NC_USER/files/$FOLDER"

# The name comes from the interface and may contain anything, a slash
# included. One filter, so it stays a file name.
NAME=$(printf '%s' "$MMO_VAULT_NAME" | tr -c 'A-Za-z0-9._-' '_')
DEST="/var/www/html/data/$TARGET/$NAME.ndjson"

docker exec -u www-data "$CONTAINER" mkdir -p "/var/www/html/data/$TARGET"
docker cp "$MMO_VAULT_FILE" "$CONTAINER:$DEST"
docker exec "$CONTAINER" chown www-data:www-data "$DEST"     # docker cp writes as root
docker exec -u www-data "$CONTAINER" php occ files:scan --path="$TARGET" --quiet
```

Files placed in the data directory from outside stay invisible to Nextcloud until they are scanned — that is what the last line is for. It does **not** produce Nextcloud versions, though: those only come from writes that go through Nextcloud itself. For versions, and without needing a scan at all, upload over WebDAV with an app password:

```sh
curl -fsS -u "$NC_USER:$NC_APP_PASSWORD" -T "$MMO_VAULT_FILE" \
  "https://nc.example/remote.php/dav/files/$NC_USER/Vault-Backup/$NAME.ndjson"
```

The docker variant needs access to the Docker socket, which the vault container deliberately does not have — mounting it would hand the service root on the host. Use it when the service runs on the host, and the WebDAV one otherwise.

### Reverse proxy

The proxy terminates TLS and forwards to port 4080. Two things belong there rather than in the service:

- **HSTS** (`Strict-Transport-Security`) — a response header that tells the browser to use HTTPS for this domain for the given period, without asking. After the first visit an `http://` link or a typed address is upgraded by the browser itself, so an attacker on the network never gets an unencrypted request to intercept. It has to be set by whatever terminates TLS, because it only counts on a connection that was already encrypted. Start with a short `max-age` and raise it once the certificate renewal is proven — while it is in force, the domain cannot be served over plain HTTP.
- **`X-Forwarded-For`**, if real client addresses should show up in the log. The service trusts forwarding headers only from the addresses in `forwarded_allow_ips`.

Everything else (`frame-ancestors 'none'`, `nosniff`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`) the service sets itself.

If you publish a port instead of sharing a Docker network, bind it to loopback: with `-p 4080:4080` Docker writes its own iptables rules **ahead of** ufw and firewalld, and the port is reachable from the network although the firewall shows it as blocked. `127.0.0.1:4080:4080` never creates that rule.

### Registering the provider

Register a web application at the provider with the redirect URI `https://<origin>/auth/oidc/<provider-name>/callback` — `setup` prints it. Microsoft needs a concrete tenant; the open aliases `common`, `organizations` and `consumers` are refused, because an address is only trustworthy if your own tenant administers it. Group mirroring needs `GroupMember.Read.All` (Microsoft, delegated) or `cloud-identity.groups.readonly` (Google Workspace).

### What the server does and does not see

The delivered copy of the application differs from the file on disk in exactly two places: `connect-src 'none'` becomes `connect-src 'self'`, and an inline script adds the adapter that talks to the service. It is readable in plain text at `/api/injection`. The file on disk stays untouched — downloaded and opened offline it still cannot open a connection.

Whoever controls the server can delete vault files, roll them back or inject code into the delivered application, but cannot read the vaults. Whoever controls the identity provider can sign in as any listed address. Everyone who can write to a shared vault knows the same master password — after revoking a share, change it.

If the provider is unreachable, `python mmo_vault.py export-vault <name>` writes any vault, current or from any generation, to standard output; the file opens with the local application as usual.

---

## Licence and origin

See [LICENSE](LICENSE). Developed by Michael Müller as part of the MMO tool series for personal projects.
