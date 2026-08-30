"""The two things that come from the environment - and nothing else.

    MMO_VAULT_DIR           the data directory (default: var/ in the project)
    MMO_VAULT_DATABASE_URL  the SQLAlchemy URL (default: SQLite in that directory)

Every other setting lives in the database (see config.py). The split is
deliberate: these two are what you need to *find* the configuration, so they
cannot themselves be in it.

Read at call time rather than at import time, so tests can point a process at a
temporary directory without reloading modules.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DIR_VARIABLE = "MMO_VAULT_DIR"
DATABASE_VARIABLE = "MMO_VAULT_DATABASE_URL"


def data_dir() -> Path:
    raw = os.environ.get(DIR_VARIABLE)
    return (Path(raw) if raw else PROJECT_ROOT / "var").resolve()


def database_url() -> str:
    """Absolute by construction.

    A relative SQLite path would land wherever the process happens to be
    started from - a trap that only shows up in production, as an empty vault
    list.
    """
    raw = os.environ.get(DATABASE_VARIABLE)
    if raw:
        return raw
    return f"sqlite:///{(data_dir() / 'mmo_vault.db').as_posix()}"


def vaults_dir() -> Path:
    return data_dir() / "vaults"
