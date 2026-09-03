#!/bin/sh
# Copies the saved vault into a Nextcloud folder and lets Nextcloud see it.
#
# Put it in <MMO_VAULT_DIR>/backup_scripts/ and make it executable:
#
#     cp 10-nextcloud.sh /root/mmo_vault/var/backup_scripts/
#     chmod +x /root/mmo_vault/var/backup_scripts/10-nextcloud.sh
#
# It runs after every save, with these in the environment:
#
#     MMO_VAULT_FILE        absolute path of the file that just changed
#     MMO_VAULT_NAME        the vault's name, as shown in the interface
#     MMO_VAULT_ID          its id (the directory name under vaults/)
#     MMO_VAULT_GENERATION  the number of the generation just kept
#     MMO_VAULT_ACTOR       who saved
#     MMO_VAULT_DIR         the data directory
#
# What travels here is ciphertext. Nextcloud, its database and its backups
# never see anything readable - the master password stays in the browser. That
# is what makes a copy into a sync folder defensible in the first place.
#
# REQUIRES access to the Docker socket, which the vault container does not
# have by design (cap_drop: ALL, no socket mounted) - mounting it would hand
# the service root on the host. Two ways out:
#
#   a) run the vault service directly on the host, where docker works anyway
#   b) upload over WebDAV instead of docker, with an app password:
#        curl -fsS -u "$NC_USER:$NC_APP_PASSWORD" -T "$MMO_VAULT_FILE" \
#          "https://nc.example/remote.php/dav/files/$NC_USER/Vault-Backup/$FILE"
#      Nextcloud then knows the file immediately and no scan is needed.

set -eu

NEXTCLOUD_CONTAINER=nextcloud
NEXTCLOUD_USER=admin
FOLDER=Vault-Backup

TARGET="$NEXTCLOUD_USER/files/$FOLDER"
TARGET_PATH="/var/www/html/data/$TARGET"

# The vault name comes from the interface and may contain anything at all.
# Everything outside this set becomes an underscore, so no name can turn into
# a second path or a second argument.
SAFE_NAME=$(printf '%s' "$MMO_VAULT_NAME" | tr -c 'A-Za-z0-9._-' '_')
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FILE="${SAFE_NAME}-${STAMP}-gen${MMO_VAULT_GENERATION}.ndjson"

docker exec -u www-data "$NEXTCLOUD_CONTAINER" mkdir -p "$TARGET_PATH"

# docker cp writes as root; without the chown Nextcloud cannot read its own file.
docker cp "$MMO_VAULT_FILE" "$NEXTCLOUD_CONTAINER:$TARGET_PATH/$FILE"
docker exec "$NEXTCLOUD_CONTAINER" chown www-data:www-data "$TARGET_PATH/$FILE"

# Files placed in the data directory from outside are invisible to Nextcloud
# until they are scanned. Only this folder, not the whole account.
docker exec -u www-data "$NEXTCLOUD_CONTAINER" php occ files:scan --path="$TARGET" --quiet

# Nothing prunes these copies. The vault's own history keeps every generation
# on the server anyway, so this folder is the off-the-box copy - decide for
# yourself how many belong here, for example:
#   docker exec -u www-data "$NEXTCLOUD_CONTAINER" \
#     sh -c "ls -1t '$TARGET_PATH'/${SAFE_NAME}-*.ndjson | tail -n +31 | xargs -r rm --"
