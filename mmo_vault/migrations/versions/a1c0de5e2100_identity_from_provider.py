"""identity from provider: settings in the database, allowlist, no local credentials

Revision ID: a1c0de5e2100
Revises: 630824d9ded0
Create Date: 2026-08-30

Written by hand. This migration changes the operating model of sign-in, so it
carries data across rather than just shapes:

  - settings move from var/config.toml into the `setting` table (read once, if
    the file exists; afterwards the file is ignored)
  - every existing account with a provider binding gets an allowlist entry with
    its admin flag - nobody is locked out by the migration
  - accounts WITHOUT a provider binding (password/passkey only) are disabled:
    they have no way to sign in any more and the administrator decides whether
    to allowlist them or delete them
  - sessions are cleared: their meaning changed, everyone signs in afresh
  - credential, backup_code and webauthn_challenge go away

There is no downgrade. The dropped columns held password hashes that are gone
for good; pretending to restore them would be worse than refusing.
"""
from typing import Sequence, Union

import tomllib

from alembic import op
import sqlalchemy as sa

revision: str = "a1c0de5e2100"
down_revision: Union[str, None] = "630824d9ded0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _settings_from_toml() -> dict[str, str]:
    """The old config.toml, flattened to the new keys - if it is there."""
    from mmo_vault.server import environment

    path = environment.data_dir() / "config.toml"
    if not path.is_file():
        return {}
    with path.open("rb") as handle:
        raw = tomllib.load(handle)

    def as_text(value) -> str:
        if isinstance(value, bool):
            return "true" if value else "false"
        return str(value)

    out: dict[str, str] = {}
    if raw.get("secret_key"):
        out["secret_key"] = str(raw["secret_key"])
    auth = raw.get("auth", {})
    if auth.get("origin"):
        out["origin"] = str(auth["origin"])
    for key in ("session_hours", "session_idle_minutes"):
        if key in auth:
            out[f"auth.{key}"] = as_text(auth[key])
    for key, value in raw.get("server", {}).items():
        if key in ("host", "port", "workers", "proxy_headers", "forwarded_allow_ips"):
            out[f"server.{key}"] = as_text(value)
    for key, value in raw.get("vault", {}).items():
        out[f"vault.{key}"] = as_text(value)
    return out


def upgrade() -> None:
    bind = op.get_bind()

    # ---- settings -----------------------------------------------------------
    op.create_table(
        "setting",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
    )
    for key, value in _settings_from_toml().items():
        bind.execute(
            sa.text("INSERT INTO setting (key, value) VALUES (:k, :v)"),
            {"k": key, "v": value},
        )

    # ---- provider -----------------------------------------------------------
    with op.batch_alter_table("provider") as batch:
        batch.add_column(sa.Column("kind", sa.String(16), nullable=False, server_default="generic"))
        batch.add_column(sa.Column("tenant", sa.String(128), nullable=True))
        batch.add_column(sa.Column("is_primary", sa.Boolean(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("sync_groups", sa.Boolean(), nullable=False, server_default="0"))

    # ---- allowlist, carried over from existing bound accounts ---------------
    op.create_table(
        "allowlist",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider_id", sa.Integer(), sa.ForeignKey("provider.id"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("note", sa.String(255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("user.id"), nullable=True),
        sa.UniqueConstraint("provider_id", "email", name="uq_allowlist_provider_email"),
    )
    bind.execute(sa.text(
        "INSERT INTO allowlist (provider_id, email, is_admin, note, created_at) "
        "SELECT provider_id, lower(email), is_admin, 'carried over by migration', "
        "       CURRENT_TIMESTAMP "
        "FROM user WHERE provider_id IS NOT NULL AND email <> ''"
    ))

    # ---- group --------------------------------------------------------------
    with op.batch_alter_table("group") as batch:
        batch.add_column(sa.Column("source", sa.String(16), nullable=False, server_default="local"))
        batch.add_column(sa.Column("external_id", sa.String(255), nullable=True))
        batch.add_column(sa.Column("last_synced_at", sa.DateTime(), nullable=True))
        batch.create_unique_constraint("uq_group_external", ["provider_id", "external_id"])

    # ---- user: no local credentials any more --------------------------------
    # Accounts that only ever had a password or passkey have no way in now.
    bind.execute(sa.text("UPDATE user SET is_active = 0 WHERE provider_id IS NULL"))
    with op.batch_alter_table("user") as batch:
        batch.drop_column("password_hash")
        batch.drop_column("must_enroll_passkey")
        batch.drop_column("enroll_expires_at")
        batch.drop_column("failed_attempts")
        batch.drop_column("locked_until")
        batch.alter_column("name", type_=sa.String(128))

    # ---- session: meaning changed, start over -------------------------------
    bind.execute(sa.text("DELETE FROM session"))
    with op.batch_alter_table("session") as batch:
        batch.drop_column("enrollment_only")
        batch.drop_column("strong_auth")

    # ---- the local credential tables ----------------------------------------
    op.drop_table("webauthn_challenge")
    op.drop_table("backup_code")
    op.drop_table("credential")


def downgrade() -> None:
    raise NotImplementedError(
        "cannot downgrade past the switch to provider identity: the local "
        "credential columns are dropped and their contents are not recoverable"
    )
