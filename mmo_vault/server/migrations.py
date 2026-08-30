"""Running Alembic from inside the application.

`setup` and `start` have to be able to bring the schema up to date and to tell
whether it is, without anyone having to remember a second command line tool.
"""

from __future__ import annotations

from alembic import command
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine

from .environment import PROJECT_ROOT

ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"


def alembic_config(url: str | None = None) -> AlembicConfig:
    config = AlembicConfig(str(ALEMBIC_INI))
    # Alembic resolves script_location relative to the current directory, which
    # is not necessarily the project root when the service is started elsewhere.
    config.set_main_option("script_location", str(PROJECT_ROOT / "mmo_vault" / "migrations"))
    if url:
        # Handed in explicitly rather than left to env.py: with --config the
        # caller may well mean a different database than var/config.toml names,
        # and a migration against the wrong database is a quiet disaster.
        config.set_main_option("sqlalchemy.url", url)
    return config


def upgrade_to_head(url: str | None = None) -> None:
    command.upgrade(alembic_config(url), "head")


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def pending_migrations(engine: Engine) -> bool:
    """True when the database is behind the code.

    Deliberately checked at start-up: a service that runs against an outdated
    schema fails later, in the middle of a request, with a message that says
    nothing about the actual cause.
    """
    return current_revision(engine) != head_revision()
