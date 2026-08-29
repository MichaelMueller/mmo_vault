"""Tests for setup, start and enroll.

Every test runs against its own database and its own config file, so nothing
here touches the var/ directory of a real installation.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mmo_vault.server import db, security
from mmo_vault.server.app import create_app
from mmo_vault.server.cli import main
from mmo_vault.server.config import Config
from mmo_vault.server.models import User, utcnow


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    """A config file and database inside the test's temporary directory."""
    path = tmp_path / "config.toml"
    monkeypatch.setattr("mmo_vault.server.cli.VAR_DIR", tmp_path)
    return path


def run_setup(config_path, *extra: str) -> int:
    return main([
        "--config", str(config_path),
        "setup",
        "--non-interactive",
        "--database-url", f"sqlite:///{config_path.parent / 'test.db'}",
        "--admin-name", "admin",
        "--admin-password", "einSicheresBootstrapPasswort",
        "--rp-id", "vault.example",
        "--origin", "https://vault.example",
        *extra,
    ])


def test_setup_creates_config_and_admin(config_path):
    assert run_setup(config_path) == 0

    config = Config.load(config_path)
    assert config.auth.rp_id == "vault.example"
    assert config.secret_key, "a session secret has to be generated"
    # The dangerous option has to stay off unless it was asked for.
    assert config.auth.allow_local_password_login is False
    assert config.server.proxy_headers is False

    db.init(config)
    with db.session_scope() as session:
        admin = session.query(User).one()
        assert admin.is_admin
        assert security.verify_password(admin.password_hash, "einSicheresBootstrapPasswort")
        # The password is a bootstrap credential: registration is mandatory and
        # the window has an end.
        assert admin.must_enroll_passkey
        assert admin.enroll_expires_at > utcnow()


def test_setup_refuses_to_overwrite(config_path, capsys):
    assert run_setup(config_path) == 0
    assert run_setup(config_path) == 1
    assert "already a configuration" in capsys.readouterr().out


def test_setup_rejects_a_weak_password(config_path):
    with pytest.raises(SystemExit):
        main([
            "--config", str(config_path),
            "setup", "--non-interactive",
            "--database-url", f"sqlite:///{config_path.parent / 'test.db'}",
            "--admin-name", "admin",
            "--admin-password", "kurz",
            "--rp-id", "vault.example",
        ])


def test_schema_is_stamped_so_migrations_can_follow(config_path):
    """setup has to go through Alembic, not create_all.

    Otherwise the version table stays empty and the next migration tries to
    create tables that are already there.
    """
    from mmo_vault.server import migrations

    assert run_setup(config_path) == 0
    engine = db.init(Config.load(config_path))
    assert migrations.current_revision(engine) == migrations.head_revision()
    assert not migrations.pending_migrations(engine)


def test_enroll_reopens_the_window(config_path, capsys):
    assert run_setup(config_path) == 0
    config = Config.load(config_path)
    db.init(config)

    # Simulate a finished registration: no password left, no obligation.
    with db.session_scope() as session:
        admin = session.query(User).one()
        admin.password_hash = None
        admin.must_enroll_passkey = False
        admin.enroll_expires_at = None

    assert main(["--config", str(config_path), "enroll", "admin"]) == 0
    output = capsys.readouterr().out
    assert "One-time password:" in output
    password = output.split("One-time password:")[1].split("\n")[0].strip()

    db.init(config)
    with db.session_scope() as session:
        admin = session.query(User).one()
        assert admin.must_enroll_passkey
        assert security.verify_password(admin.password_hash, password)
        assert admin.enroll_expires_at > utcnow()


def test_enroll_reports_an_unknown_account(config_path, capsys):
    assert run_setup(config_path) == 0
    assert main(["--config", str(config_path), "enroll", "nobody"]) == 1
    assert "No account named" in capsys.readouterr().err


def test_start_without_configuration(tmp_path, capsys):
    missing = tmp_path / "nothing.toml"
    assert main(["--config", str(missing), "start"]) == 1
    assert "setup" in capsys.readouterr().err


def test_health_endpoint(config_path):
    assert run_setup(config_path) == 0
    with TestClient(create_app(Config.load(config_path))) as client:
        response = client.get("/api/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        # The schema stays closed: this is a service for a handful of people.
        assert client.get("/docs").status_code == 404
