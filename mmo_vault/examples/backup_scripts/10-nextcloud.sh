#!/bin/sh
# Copies the saved vault over a fixed path in Nextcloud and scans it in.
#
#     cp 10-nextcloud.sh /root/mmo_vault/var/backup_scripts/
#     chmod +x /root/mmo_vault/var/backup_scripts/10-nextcloud.sh
#
# Always the same file name, so the folder does not fill up. The vault's own
# history on the server keeps every generation anyway.
#
# What travels is ciphertext - Nextcloud, its database and its backups never
# see anything readable.
#
# Available in the environment: MMO_VAULT_FILE, MMO_VAULT_NAME, MMO_VAULT_ID,
# MMO_VAULT_GENERATION, MMO_VAULT_ACTOR, MMO_VAULT_DIR.
#
# NOTE ON VERSIONS: writing into the data directory and scanning does NOT give
# Nextcloud versions - those come only from writes that go through Nextcloud
# itself. If you want them, upload over WebDAV instead, which also needs no
# scan at all:
#
#     curl -fsS -u "$NC_USER:$NC_APP_PASSWORD" -T "$MMO_VAULT_FILE" \
#       "https://nc.example/remote.php/dav/files/$NC_USER/Vault-Backup/$NAME.ndjson"
#
# The docker variant below needs access to the Docker socket, which the vault
# container does not have by design - use it when the service runs on the host.

set -eu

CONTAINER=nextcloud

# The Nextcloud user id, which is the directory name under data/ - often a mail
# address rather than a login name. Read it off the path:
#   /var/www/html/data/mmuelleronline83@googlemail.com/files/...
#                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ this
NC_USER=admin
FOLDER=Vault-Backup

TARGET="$NC_USER/files/$FOLDER"

# The name comes from the interface and may contain anything, including a
# slash. One filter, so it stays a file name.
NAME=$(printf '%s' "$MMO_VAULT_NAME" | tr -c 'A-Za-z0-9._-' '_')
DEST="/var/www/html/data/$TARGET/$NAME.ndjson"

docker exec -u www-data "$CONTAINER" mkdir -p "/var/www/html/data/$TARGET"
docker cp "$MMO_VAULT_FILE" "$CONTAINER:$DEST"
# docker cp writes as root; without this Nextcloud cannot read its own file.
docker exec "$CONTAINER" chown www-data:www-data "$DEST"
docker exec -u www-data "$CONTAINER" php occ files:scan --path="$TARGET" --quiet
