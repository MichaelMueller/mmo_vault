"""Database schema of the server variant.

Plain SQLAlchemy 2.0 ORM, no SQLite specifics anywhere: the connection string
decides the engine, so PostgreSQL works by changing one line in the config.

The schema already contains the tables of the later phases (vaults, locks,
generations, providers). They cost nothing while unused and spare a migration
that would otherwise have to rewrite half the model.
"""

from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
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


class Provider(Base):
    """An OIDC identity provider, configurable per user and per group."""

    __tablename__ = "provider"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    issuer: Mapped[str] = mapped_column(String(255))
    client_id: Mapped[str] = mapped_column(String(255))
    client_secret: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[str] = mapped_column(String(255), default="openid email profile")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Group(Base):
    __tablename__ = "group"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str] = mapped_column(String(255), default="")
    provider_id: Mapped[Optional[int]] = mapped_column(ForeignKey("provider.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    members: Mapped[list["User"]] = relationship(
        secondary="user_group", back_populates="groups"
    )


class UserGroup(Base):
    __tablename__ = "user_group"

    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"), primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("group.id"), primary_key=True)


class User(Base):
    __tablename__ = "user"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    email: Mapped[str] = mapped_column(String(255), default="")
    # Only set while an account still has to register a passkey, and discarded
    # for good afterwards - a password must not survive as a permanent way in.
    password_hash: Mapped[Optional[str]] = mapped_column(String(255))
    must_enroll_passkey: Mapped[bool] = mapped_column(Boolean, default=True)
    enroll_expires_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Identity at an OIDC provider. The pair (provider, subject) is the identity,
    # never the mail address.
    provider_id: Mapped[Optional[int]] = mapped_column(ForeignKey("provider.id"))
    provider_subject: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime)

    groups: Mapped[list[Group]] = relationship(
        secondary="user_group", back_populates="members"
    )
    credentials: Mapped[list["Credential"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("provider_id", "provider_subject", name="uq_user_provider_subject"),
    )


class Credential(Base):
    """A registered passkey. Nothing in here is secret."""

    __tablename__ = "credential"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(Integer, default=0)
    label: Mapped[str] = mapped_column(String(64), default="")
    # Whether the credential is syncable ("backup eligible"). Used to warn a
    # user whose only passkey would not survive losing the device.
    backup_eligible: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime)

    user: Mapped[User] = relationship(back_populates="credentials")


class BackupCode(Base):
    """One-time recovery codes, handed out when a passkey is registered."""

    __tablename__ = "backup_code"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    code_hash: Mapped[str] = mapped_column(String(255))
    used_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class Session(Base):
    """Server-side session. Kept in the database so it can be revoked."""

    __tablename__ = "session"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("user.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime)
    # A session created with a password while must_enroll_passkey is set may do
    # nothing but register a passkey.
    enrollment_only: Mapped[bool] = mapped_column(Boolean, default=False)
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
