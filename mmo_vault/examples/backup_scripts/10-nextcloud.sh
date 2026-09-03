#!/bin/sh
# Copies the saved vault into a Nextcloud folder and scans it in.
#
#     cp 10-nextcloud.sh /root/mmo_vault/var/backup_scripts/
#     chmod +x /root/mmo_vault/var/backup_scripts/10-nextcloud.sh
#
# Always the same file name - the vault's own history on the server keeps
# every generation anyway. What travels is ciphertext; Nextcloud, its database
# and its backups never see anything readable.
#
# Needs: the Nextcloud data directory readable at NC_DATA, and docker for the
# scan. Files put there from outside stay invisible to Nextcloud until they are
# scanned - and they get no Nextcloud versions, because those only come from
# writes that go through Nextcloud itself.
#
# In the environment: MMO_VAULT_FILE, MMO_VAULT_NAME, MMO_VAULT_ID,
# MMO_VAULT_GENERATION, MMO_VAULT_ACTOR, MMO_VAULT_DIR.

set -eu

NC_DATA=/srv/home_stack/data/nextcloud/data
NC_USER=admin          # the user id = the directory name in NC_DATA
FOLDER=Vault-Backup
CONTAINER=nextcloud

# The name comes from the interface and may contain anything, a slash
# included. One filter, so it stays a file name.
NAME=$(printf '%s' "$MMO_VAULT_NAME" | tr -c 'A-Za-z0-9._-' '_')

mkdir -p "$NC_DATA/$NC_USER/files/$FOLDER"
cp "$MMO_VAULT_FILE" "$NC_DATA/$NC_USER/files/$FOLDER/$NAME.ndjson"

docker exec -u www-data "$CONTAINER" php occ files:scan --path="$NC_USER/files/$FOLDER" --quiet
