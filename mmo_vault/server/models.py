"""Database schema of the server variant.

Plain SQLAlchemy 2.0 ORM, no SQLite specifics anywhere: the connection string
decides the engine, so PostgreSQL works by changing one environment variable.

Identity is not managed here. It comes from an OIDC provider; the tables below
only record who was let in (allowlist), who has shown up (user), and what they
may do (group, vault_access).
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> dt.datetime:
    """Timestamps are always UTC and always come from the server.

    Returned without a time zone on purpose. SQLite hands DateTime columns back
    as naive values regardless of what went in, so keeping aware values in the
    code would mean comparing aware against naive somewhere down the line - and
    that raises a TypeError at exactly the wrong moment. One convention, applied
    everywhere: naive, and it means UTC.
    """
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Setting(Base):
    """Every setting except where the database is. See config.py."""

    __tablename__ = "setting"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


class Provider(Base):
    """An OIDC identity provider. `kind` decides issuer template, claim rules
    and - if enabled - how groups are fetched."""

    __tablename__ = "provider"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(16), default="generic")  # microsoft | google | generic
    issuer: Mapped[str] = mapped_column(String(255))
    client_id: Mapped[str] = mapped_column(String(255))
    client_secret: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[str] = mapped_column(String(255), default="openid email profile")
    tenant: Mapped[Optional[str]] = mapped_column(String(128))  # microsoft only
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_groups: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Allowlist(Base):
    """Who may sign in through which provider, and whether as administrator.

    Consulted on every sign-in, not only the first: the admin flag is taken from
    here each time, and an address removed from the list is refused next time.
    """

    __tablename__ = "allowlist"

    id: Mapped[int] = mapped_column(primary_key=True)
    provider_id: Mapped[int] = mapped_column(ForeignKey("provider.id"))
    email: Mapped[str] = mapped_column(String(255))  # normalised to lower case
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    note: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id"))

    __table_args__ = (UniqueConstraint("provider_id", "email", name="uq_allowlist_provider_email"),)


class Group(Base):
    """Locally managed, or a mirror of a provider group filled in by sync."""

    __tablename__ = "group"
    # SQLite reuses rowids after a delete. vault_access references groups by
    # bare integer, so a reused id would hand a new group the shares of a
    # deleted one. The delete endpoint cleans those up; this makes reuse
    # impossible on top.
    __table_args__ = (
        UniqueConstraint("provider_id", "external_id", name="uq_group_external"),
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(255), default="")
    source: Mapped[str] = mapped_column(String(16), default="local")  # local | provider
    provider_id: Mapped[Optional[int]] = mapped_column(ForeignKey("provider.id"))
    external_id: Mapped[Optional[str]] = mapped_column(String(255))
    last_synced_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    members: Mapped[list["User"]] = relationship(
        secondary="user_group", back_populates="groups"
    )


class UserGroup(Base):
    __tablename__ = "user_group"

    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("group.id"), primary_key=True)


class User(Base):
    """An account that has signed in at least once. Created by the first
    successful sign-in of an allowlisted address - never by hand."""

    __tablename__ = "user"
    __table_args__ = (
        UniqueConstraint("provider_id", "provider_subject", name="uq_user_provider_subject"),
        # Same reasoning as on Group: ids must never come back.
        {"sqlite_autoincrement": True},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    email: Mapped[str] = mapped_column(String(255), default="")
    # The identity is this pair, never the mail address.
    provider_id: Mapped[int] = mapped_column(ForeignKey("provider.id"))
    provider_subject: Mapped[str] = mapped_column(String(255))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime)

    groups: Mapped[list[Group]] = relationship(
        secondary="user_group", back_populates="members"
    )


class Session(Base):
    """Server-side session. Kept in the database so it can be revoked."""

    __tablename__ = "session"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")


class Vault(Base):
    __tablename__ = "vault"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(String(255), default="")
    created_by: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    etag: Mapped[str] = mapped_column(String(64), default="")
    # Counts up only. Deriving the next number from max(seq) would hand a
    # number out again after a deletion, and an audit entry saying "restored
    # from #1" would then point at a different state than it did.
    next_generation: Mapped[int] = mapped_column(Integer, default=1)


class VaultAccess(Base):
    """Shared with a user or a group; the wider permission wins."""

    __tablename__ = "vault_access"

    id: Mapped[int] = mapped_column(primary_key=True)
    vault_id: Mapped[str] = mapped_column(ForeignKey("vault.id"))
    subject_type: Mapped[str] = mapped_column(String(8))  # 'user' | 'group'
    subject_id: Mapped[int] = mapped_column(Integer)
    permission: Mapped[str] = mapped_column(String(16))  # 'read' | 'readwrite'

    __table_args__ = (
        UniqueConstraint("vault_id", "subject_type", "subject_id", name="uq_vault_subject"),
    )


class VaultLock(Base):
    """Advisory lock. The ETag decides, this only keeps people out of each
    other's way."""

    __tablename__ = "vault_lock"

    vault_id: Mapped[str] = mapped_column(ForeignKey("vault.id"), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    token: Mapped[str] = mapped_column(String(64))
    acquired_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)


class Generation(Base):
    """One kept version of a whole vault file. Never expires on its own."""

    __tablename__ = "generation"

    id: Mapped[int] = mapped_column(primary_key=True)
    vault_id: Mapped[str] = mapped_column(ForeignKey("vault.id"))
    seq: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    author_id: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id"))
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    note: Mapped[str] = mapped_column(String(255), default="")

    __table_args__ = (UniqueConstraint("vault_id", "seq", name="uq_generation_seq"),)


class AuditLog(Base):
    """Who did what. Never any content."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_id: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id"))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
