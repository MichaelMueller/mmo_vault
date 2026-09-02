"""Settings, stored in the database.

There is no configuration file. Everything the service needs beyond *where the
database is* lives in the `setting` table as flat key/value pairs and is read
into this typed structure. A missing key means its default - so a database
written by an older version keeps working, and the administration only stores
what was actually changed.

Reading is cheap (a dozen rows) and happens per request, which is what makes a
change in the administration take effect without a restart. The exception is
`server.*`: uvicorn reads those once at start-up.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field, fields, is_dataclass

from sqlalchemy.orm import Session as DbSession

from .models import Setting


@dataclass
class ServerConfig:
    """Read once by `start`, handed to uvicorn."""

    host: str = "127.0.0.1"
    # The same port inside the container and on the host, so there is one
    # number to remember. 8000 would only say "a Python service lives here".
    port: int = 4080
    workers: int = 1
    # Only when a reverse proxy really sits in front. It makes the service
    # trust forwarding headers from the addresses below.
    proxy_headers: bool = False
    forwarded_allow_ips: str = "127.0.0.1"


@dataclass
class AuthConfig:
    session_hours: int = 12
    session_idle_minutes: int = 30


@dataclass
class VaultConfig:
    # A structural ceiling, not a quota. The browser struggles long before this.
    max_size_bytes: int = 25 * 1024 * 1024
    # Longer than the client-side auto-lock of five minutes on purpose: the
    # lock must not expire before the person editing does.
    lock_ttl_seconds: int = 600
    # Nothing is ever cleaned up automatically. This is the mark from which the
    # interface says so; the decision what goes stays with a person.
    history_warn_bytes: int = 200 * 1024 * 1024


@dataclass
class Config:
    # The public address, e.g. https://vault.example. Mandatory: the OIDC
    # redirect URIs are built from it, and they have to be right before the
    # first sign-in can happen.
    origin: str = ""
    # Signs the short-lived OAuth state cookie. Generated on first use.
    secret_key: str = ""
    server: ServerConfig = field(default_factory=ServerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    vault: VaultConfig = field(default_factory=VaultConfig)

    def is_ready(self) -> bool:
        return bool(self.origin) and bool(self.secret_key)


# ------------------------------------------------------------------ flattening


def _flatten(obj, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for f in fields(obj):
        value = getattr(obj, f.name)
        key = f"{prefix}{f.name}"
        if is_dataclass(value):
            out.update(_flatten(value, key + "."))
        elif isinstance(value, bool):
            out[key] = "true" if value else "false"
        else:
            out[key] = str(value)
    return out


def _assign(obj, key: str, raw: str) -> None:
    """Sets one dotted key on the structure, converting to the field's type."""
    head, _, rest = key.partition(".")
    for f in fields(obj):
        if f.name != head:
            continue
        current = getattr(obj, f.name)
        if rest:
            if is_dataclass(current):
                _assign(current, rest, raw)
            return
        if f.type in ("bool", bool):
            setattr(obj, f.name, raw.strip().lower() in ("1", "true", "yes", "on"))
        elif f.type in ("int", int):
            setattr(obj, f.name, int(raw))
        else:
            setattr(obj, f.name, raw)
        return
    # Unknown keys are ignored on purpose: a newer version may have written
    # them, and an older one must not fall over that.


def load(db: DbSession) -> Config:
    config = Config()
    for row in db.query(Setting):
        _assign(config, row.key, row.value)
    return config


def save(db: DbSession, config: Config) -> None:
    """Writes every field - including defaults.

    Storing defaults too means the table shows the whole effective state, and a
    later change of a default in the code does not silently alter a running
    installation.
    """
    existing = {row.key: row for row in db.query(Setting)}
    for key, value in _flatten(config).items():
        if key in existing:
            existing[key].value = value
        else:
            db.add(Setting(key=key, value=value))


def ensure_secret_key(db: DbSession, config: Config) -> Config:
    """Generates the state-signing key once and persists it."""
    if not config.secret_key:
        config.secret_key = secrets.token_urlsafe(48)
        row = db.query(Setting).filter(Setting.key == "secret_key").one_or_none()
        if row is None:
            db.add(Setting(key="secret_key", value=config.secret_key))
        else:
            row.value = config.secret_key
    return config


class NotConfigured(RuntimeError):
    """Raised when the service is started before `setup` ran."""

    def __init__(self, missing: list[str]):
        super().__init__(", ".join(missing))
        self.missing = missing

    def __str__(self) -> str:
        return (
            "The service is not set up yet - missing: " + ", ".join(self.missing)
            + ".\nRun `python mmo_vault.py setup` first."
        )
