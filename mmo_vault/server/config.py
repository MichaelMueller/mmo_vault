"""Configuration of the server variant.

Everything lives in one TOML file under var/, written by `setup` and read by
`start`. Deliberately a plain dataclass and the standard library instead of a
settings framework: the file is short, it is written by exactly one place, and
a missing key should produce a clear message rather than a stack trace.
"""

from __future__ import annotations

import os
import secrets
import tomllib
from dataclasses import dataclass, field, asdict
from pathlib import Path

# The project root is three levels up: config.py -> server -> mmo_vault -> root.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
VAR_DIR = PROJECT_ROOT / "var"
CONFIG_PATH = VAR_DIR / "config.toml"

DEFAULT_DATABASE_URL = "sqlite:///var/mmo_vault.db"


@dataclass
class ServerConfig:
    """Uvicorn and the public identity of the service."""

    host: str = "127.0.0.1"
    port: int = 8000
    workers: int = 1
    # Only switch this on when a reverse proxy really sits in front. It makes
    # the service trust X-Forwarded-For, and that changes who counts as local.
    proxy_headers: bool = False


@dataclass
class AuthConfig:
    """Everything about who may sign in and how."""

    # WebAuthn relying party. Asked for during setup instead of guessed from the
    # Host header: a later change invalidates every passkey.
    rp_id: str = "localhost"
    rp_name: str = "MMO Vault"
    origin: str = "http://localhost:8000"
    # Password sign-in over loopback. Off by default - see docs/plan_server.md,
    # chapter 5.4, for why the peer address alone is not enough to decide this.
    allow_local_password_login: bool = False
    # How long a freshly created account may use its password to register a
    # passkey. After that the window has to be reopened with `enroll`.
    enrollment_hours: int = 72
    session_hours: int = 12
    session_idle_minutes: int = 30


@dataclass
class VaultConfig:
    """Limits around the stored vault files."""

    # A structural ceiling, not a quota. A vault beyond this is almost always a
    # mistake, and the browser would struggle with it long before the server.
    max_size_bytes: int = 25 * 1024 * 1024
    # Deliberately longer than the client-side auto-lock of five minutes: the
    # lock must not expire before the person editing does.
    lock_ttl_seconds: int = 600
    # Nothing is ever cleaned up automatically, so the history grows with every
    # save. Instead of a deadline there is a mark from which the interface says
    # so - the decision what goes stays with a person.
    history_warn_bytes: int = 200 * 1024 * 1024


@dataclass
class Config:
    database_url: str = DEFAULT_DATABASE_URL
    secret_key: str = ""
    server: ServerConfig = field(default_factory=ServerConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    vault: VaultConfig = field(default_factory=VaultConfig)

    # ---------------------------------------------------------------- loading

    @classmethod
    def load(cls, path: Path | None = None) -> "Config":
        path = path or CONFIG_PATH
        if not path.exists():
            raise ConfigMissing(path)
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
        return cls(
            database_url=raw.get("database_url", DEFAULT_DATABASE_URL),
            secret_key=raw.get("secret_key", ""),
            server=ServerConfig(**raw.get("server", {})),
            auth=AuthConfig(**raw.get("auth", {})),
            # A missing section falls back to the defaults, so a configuration
            # written by an older version keeps working.
            vault=VaultConfig(**raw.get("vault", {})),
        )

    # ---------------------------------------------------------------- writing

    def save(self, path: Path | None = None) -> Path:
        path = path or CONFIG_PATH
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_toml(), encoding="utf-8")
        # The file holds the session secret. On Windows this is largely
        # cosmetic, but the service runs on Linux where it is not.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return path

    def to_toml(self) -> str:
        lines = [
            "# MMO Vault - configuration of the server variant.",
            "# Written by `python mmo_vault.py setup`. Holds the session secret:",
            "# keep it readable by the service account only.",
            "",
            _toml_pair("database_url", self.database_url),
            _toml_pair("secret_key", self.secret_key),
            "",
            "[server]",
        ]
        lines += [_toml_pair(k, v) for k, v in asdict(self.server).items()]
        lines += ["", "[auth]"]
        lines += [_toml_pair(k, v) for k, v in asdict(self.auth).items()]
        lines += ["", "[vault]"]
        lines += [_toml_pair(k, v) for k, v in asdict(self.vault).items()]
        return "\n".join(lines) + "\n"

    # ---------------------------------------------------------------- helpers

    def resolved_database_url(self) -> str:
        """Turns a relative SQLite path into an absolute one.

        Without this the database would land wherever the process happens to be
        started from - a trap that only shows up in production, as an empty
        vault list.
        """
        prefix = "sqlite:///"
        if not self.database_url.startswith(prefix):
            return self.database_url
        raw = self.database_url[len(prefix):]
        path = Path(raw)
        if path.is_absolute():
            return self.database_url
        return prefix + str((PROJECT_ROOT / path).resolve())


class ConfigMissing(FileNotFoundError):
    """Raised when the service is started before it was set up."""

    def __init__(self, path: Path):
        super().__init__(str(path))
        self.path = path

    def __str__(self) -> str:
        return (
            f"No configuration found at {self.path}.\n"
            "Run `python mmo_vault.py setup` first."
        )


def _toml_pair(key: str, value: object) -> str:
    if isinstance(value, bool):
        return f"{key} = {'true' if value else 'false'}"
    if isinstance(value, int):
        return f"{key} = {value}"
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'{key} = "{escaped}"'


def new_secret_key() -> str:
    return secrets.token_urlsafe(48)
