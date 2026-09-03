"""setup, start and export-vault - and the two environment variables."""

from __future__ import annotations

import json
import logging

import pytest

from mmo_vault.server import config as settings
from mmo_vault.server import db, environment, migrations, storage
from mmo_vault.server.app import create_app
from mmo_vault.server.cli import main
from mmo_vault.server.config import NotConfigured
from mmo_vault.server.models import Allowlist, Provider, Setting

from .conftest import ADMIN_EMAIL, HEADERS, ORIGIN, run_setup


def test_setup_writes_everything_into_the_database(configured, data_dir):
    """Nothing lands in a file: no config.toml, all of it rows."""
    assert not (data_dir / "config.toml").exists()
    assert (data_dir / "vaults").is_dir()
    with db.session_scope() as session:
        config = settings.load(session)
        assert config.origin == ORIGIN
        assert config.secret_key, "the state-signing key has to be generated"
        provider = session.query(Provider).one()
        assert provider.is_primary and provider.kind == "generic"
        assert provider.issuer == "https://idp.example"
        entry = session.query(Allowlist).one()
        assert (entry.email, entry.is_admin) == (ADMIN_EMAIL, True)


def test_setup_refuses_a_second_run_without_force(configured, capsys):
    assert run_setup() == 1
    assert "already a primary provider" in capsys.readouterr().out


def test_force_replaces_credentials_and_adds_admins_but_deletes_nothing(configured):
    assert run_setup("--force", "--client-secret", "neu", "--admins",
                     f"{ADMIN_EMAIL}, zweiter@example.test") == 0
    with db.session_scope() as session:
        assert session.query(Provider).count() == 1
        assert session.query(Provider).one().client_secret == "neu"
        emails = sorted(e.email for e in session.query(Allowlist))
        assert emails == [ADMIN_EMAIL, "zweiter@example.test"]


def test_setup_refuses_an_insecure_origin(data_dir):
    with pytest.raises(SystemExit):
        run_setup("--origin", "http://vault.example")


def test_setup_refuses_microsoft_without_a_real_tenant(data_dir):
    with pytest.raises(SystemExit):
        main(["setup", "--non-interactive", "--origin", ORIGIN, "--kind", "microsoft",
              "--tenant", "common", "--client-id", "c", "--client-secret", "s",
              "--admins", ADMIN_EMAIL])


def test_setup_needs_at_least_one_administrator(data_dir):
    with pytest.raises(SystemExit):
        main(["setup", "--non-interactive", "--origin", ORIGIN, "--kind", "generic",
              "--issuer", "https://idp.example", "--client-id", "c", "--client-secret", "s",
              "--admins", ""])


def test_the_environment_decides_where_things_are(monkeypatch, tmp_path):
    monkeypatch.setenv("MMO_VAULT_DIR", str(tmp_path / "anderswo"))
    monkeypatch.delenv("MMO_VAULT_DATABASE_URL", raising=False)
    assert environment.data_dir() == (tmp_path / "anderswo").resolve()
    assert environment.database_url().startswith("sqlite:///")
    assert environment.database_url().endswith("anderswo/mmo_vault.db")
    assert environment.vaults_dir() == (tmp_path / "anderswo").resolve() / "vaults"


def test_the_app_refuses_to_start_unconfigured(data_dir):
    """A sentence on the console instead of a sign-in page without buttons."""
    migrations.upgrade_to_head()
    with pytest.raises(NotConfigured) as excinfo:
        create_app()
    assert "origin" in str(excinfo.value)
    assert "provider" in str(excinfo.value)


def test_start_reports_what_is_missing(data_dir, capsys):
    migrations.upgrade_to_head()
    assert main(["start"]) == 1
    assert "not set up yet" in capsys.readouterr().err


def test_a_missing_setting_falls_back_to_its_default(configured):
    """A database written by an older version keeps working."""
    with db.session_scope() as session:
        session.query(Setting).filter(Setting.key == "auth.session_hours").delete()
    with db.session_scope() as session:
        assert settings.load(session).auth.session_hours == 12


def test_export_vault_prints_the_ciphertext(admin, capsys):
    vault_id = admin.post("/api/vaults", json={"name": "Team-Vault"}, headers=HEADERS).json()["id"]
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "Admin", "permission": "readwrite"}]})
    token = admin.post(f"/api/vaults/{vault_id}/lock", headers=HEADERS).json()["token"]
    text = "\n".join([
        json.dumps({"type": "header", "format": "mmo-vault-v3", "salt": "AAAA", "iterations": 600000}),
        json.dumps({"type": "text", "iv": "AAAA", "data": "GEHEIM"}),
    ])
    admin.put(f"/api/vaults/{vault_id}/content", content=text,
              headers={**HEADERS, "If-Match": '""', "X-Vault-Lock": token})

    # By id, and by unique name - the emergency path when the provider is down.
    assert main(["export-vault", vault_id]) == 0
    assert capsys.readouterr().out == text
    assert main(["export-vault", "Team-Vault"]) == 0
    assert capsys.readouterr().out == text
    assert main(["export-vault", "Team-Vault", "--generation", "1"]) == 0
    assert capsys.readouterr().out == text
    assert main(["export-vault", "gibtsnicht"]) == 1


def test_migrating_does_not_silence_the_service(configured, caplog):
    """Alembic's fileConfig switches off every existing logger by default.

    Migrations run inside the service - on setup, and as the schema check on
    start - so the default would leave it mute from that moment on, with
    nothing saying why. Backup scripts report through the log; this is what
    makes that reporting arrive at all.
    """
    migrations.upgrade_to_head()
    with caplog.at_level("INFO", logger="mmo_vault.server.hooks"):
        logging.getLogger("mmo_vault.server.hooks").error("still audible")
    assert [r.getMessage() for r in caplog.records] == ["still audible"]


def test_migrate_brings_an_old_schema_up_to_date(data_dir, capsys):
    """The step `start` refuses to take by itself.

    Reachable without overriding the container entrypoint and without
    `setup --force`, which would ask for every provider detail again.
    """
    from alembic import command

    migrations.upgrade_to_head()
    command.downgrade(migrations.alembic_config(), "-1")
    engine = db.init()
    assert migrations.pending_migrations(engine)

    assert main(["migrate"]) == 0
    out = capsys.readouterr().out
    assert "Migrating" in out and "Done." in out
    assert not migrations.pending_migrations(db.init())

    # Running it again says so instead of doing anything.
    assert main(["migrate"]) == 0
    assert "up to date" in capsys.readouterr().out


def test_start_names_a_command_that_exists(data_dir, capsys):
    """The old message pointed at `setup --force` and bare `alembic`, neither
    of which is reachable in the container without an entrypoint override."""
    migrations.upgrade_to_head()
    from alembic import command
    command.downgrade(migrations.alembic_config(), "-1")

    assert main(["start"]) == 1
    err = capsys.readouterr().err
    assert "mmo_vault.py migrate" in err
    assert "docker compose run --rm mmo-vault-server migrate" in err
