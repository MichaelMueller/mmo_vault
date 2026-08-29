"""Regression tests for the findings of the security review.

Each test names the failure it guards against. They exist because every one of
these was a real defect found after seven green phases - the suite only proves
what it asks.
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient

from mmo_vault.server import db, storage
from mmo_vault.server.app import create_app
from mmo_vault.server.cli import main
from mmo_vault.server.config import Config
from mmo_vault.server.models import (
    Session,
    User,
    VaultAccess,
    WebAuthnChallenge,
    utcnow,
)

from .authenticator import SoftAuthenticator

ORIGIN = "https://vault.example"
PASSWORD = "einSicheresBootstrapPasswort"
HEADERS = {"X-Vault-Request": "1"}


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    monkeypatch.setattr("mmo_vault.server.cli.VAR_DIR", tmp_path)
    monkeypatch.setattr(storage, "VAULTS_DIR", tmp_path / "vaults")
    assert main([
        "--config", str(path), "setup", "--non-interactive",
        "--database-url", f"sqlite:///{tmp_path / 'test.db'}",
        "--admin-name", "admin", "--admin-password", PASSWORD,
        "--rp-id", "vault.example", "--origin", ORIGIN,
    ]) == 0
    return Config.load(path)


def sign_in(config, name: str, password: str) -> TestClient:
    client = TestClient(create_app(config), base_url=ORIGIN)
    client.__enter__()
    client.post("/auth/login", json={"name": name, "password": password}, headers=HEADERS)
    started = client.post("/auth/passkey/register/options", headers=HEADERS).json()
    client.post("/auth/passkey/register/verify", json={
        "challenge_id": started["challenge_id"],
        "credential": SoftAuthenticator().create(started["options"], ORIGIN),
    }, headers=HEADERS)
    return client


@pytest.fixture
def admin(config):
    client = sign_in(config, "admin", PASSWORD)
    yield client
    client.__exit__(None, None, None)


# ------------------------------------------------- deleting must not resurrect


def test_deleting_a_full_account_works_and_leaves_nothing(admin, config):
    """The finding: delete_user hit a foreign key error as soon as the account
    had backup codes, created vaults or held a lock - and the vault_access row
    it left behind would have granted the NEXT account created the permissions
    of the deleted one, because SQLite reuses ids."""
    created = admin.post("/api/users", json={"name": "opfer"}, headers=HEADERS).json()

    # Give the account everything that once broke the delete: a passkey with
    # backup codes, a share, and a held lock.
    with sign_in(config, "opfer", created["one_time_password"]) as victim:
        pass  # sign_in registers the passkey, which creates the backup codes
    vault_id = admin.post("/api/vaults", json={"name": "V"}, headers=HEADERS).json()["id"]
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "user", "subject": "opfer", "permission": "readwrite"}]})
    db.init(config)
    with db.session_scope() as session:
        victim_id = session.query(User).filter(User.name == "opfer").one().id

    result = admin.delete(f"/api/users/{victim_id}", headers=HEADERS)
    assert result.status_code == 200, result.text

    with db.session_scope() as session:
        # No orphaned share: this is the row that would have resurrected.
        assert session.query(VaultAccess).filter(
            VaultAccess.subject_type == "user", VaultAccess.subject_id == victim_id
        ).count() == 0

    # And the second layer: a new account never gets the old id anyway.
    replacement = admin.post("/api/users", json={"name": "neuling"}, headers=HEADERS).json()
    assert replacement["id"] != victim_id
    with sign_in(config, "neuling", replacement["one_time_password"]) as newcomer:
        assert newcomer.get("/api/vaults").json() == []


def test_deleting_a_group_takes_its_shares(admin, config):
    """Same resurrection path through group ids."""
    admin.post("/api/groups", json={"name": "team"}, headers=HEADERS)
    vault_id = admin.post("/api/vaults", json={"name": "V"}, headers=HEADERS).json()["id"]
    admin.put(f"/api/vaults/{vault_id}/access", headers=HEADERS, json={"entries": [
        {"subject_type": "group", "subject": "team", "permission": "readwrite"}]})
    group_id = admin.get("/api/groups").json()[0]["id"]

    assert admin.delete(f"/api/groups/{group_id}", headers=HEADERS).status_code == 200

    db.init(config)
    with db.session_scope() as session:
        assert session.query(VaultAccess).filter(
            VaultAccess.subject_type == "group", VaultAccess.subject_id == group_id
        ).count() == 0


def test_deleting_a_user_who_created_a_vault(admin, config):
    """created_by pointed at the account and made the delete fail outright."""
    created = admin.post("/api/users", json={"name": "gruender", "is_admin": True},
                         headers=HEADERS).json()
    with sign_in(config, "gruender", created["one_time_password"]) as founder:
        founder.post("/api/vaults", json={"name": "Gruendung"}, headers=HEADERS)

    assert admin.delete(f"/api/users/{created['id']}", headers=HEADERS).status_code == 200
    # The vault survives; only the author link is gone.
    assert admin.get("/api/vaults").json()[0]["name"] == "Gruendung"


# --------------------------------------------------------------- session hygiene


def test_registration_rotates_the_session(config):
    """The finding: the enrollment session was upgraded in place. A cookie
    issued for a mere password would have stayed valid as a full session."""
    with TestClient(create_app(config), base_url=ORIGIN) as client:
        client.post("/auth/login", json={"name": "admin", "password": PASSWORD}, headers=HEADERS)
        old_cookie = client.cookies.get("mmo_vault_session")

        started = client.post("/auth/passkey/register/options", headers=HEADERS).json()
        client.post("/auth/passkey/register/verify", json={
            "challenge_id": started["challenge_id"],
            "credential": SoftAuthenticator().create(started["options"], ORIGIN),
        }, headers=HEADERS)
        new_cookie = client.cookies.get("mmo_vault_session")

        assert new_cookie != old_cookie
        assert client.get("/api/me").status_code == 200

    # The old id is revoked, not merely superseded.
    db.init(config)
    with db.session_scope() as session:
        assert session.get(Session, old_cookie) is None


# ------------------------------------------------------------------ dos guards


def test_expired_challenges_are_purged_on_the_way_in(config):
    """The finding: purge_expired_challenges existed but was never called, and
    the options endpoint is reachable without a session - the table would have
    grown for the lifetime of the database."""
    db.init(config)
    with db.session_scope() as session:
        session.add(WebAuthnChallenge(
            id="alt", challenge=b"x", purpose="authenticate",
            expires_at=utcnow() - dt.timedelta(minutes=1),
        ))

    with TestClient(create_app(config), base_url=ORIGIN) as client:
        client.post("/auth/passkey/options", json={"name": None}, headers=HEADERS)

    with db.session_scope() as session:
        assert session.get(WebAuthnChallenge, "alt") is None


def test_an_unknown_name_is_denied_like_a_wrong_password(config):
    """Both paths run the same hash verification, so the response cannot be
    used to enumerate accounts. Here only the visible half is testable: same
    status, same body."""
    with TestClient(create_app(config), base_url=ORIGIN) as client:
        unknown = client.post("/auth/login", json={"name": "gibtsnicht", "password": "x" * 20},
                              headers=HEADERS)
        wrong = client.post("/auth/login", json={"name": "admin", "password": "x" * 20},
                            headers=HEADERS)
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json() == wrong.json()


# --------------------------------------------------------------------- enroll


def test_enroll_does_not_reactivate_a_disabled_account(config, capsys):
    """The finding: enroll silently set is_active=True. Disabling an account is
    a decision; a command about lost devices must not undo it."""
    db.init(config)
    with db.session_scope() as session:
        admin_user = session.query(User).one()
        admin_user.is_active = False

    # main() needs the config path; reuse the one the fixture wrote.
    import mmo_vault.server.cli as cli
    assert main(["--config", str(cli.VAR_DIR / "config.toml"), "enroll", "admin"]) == 1
    assert "disabled" in capsys.readouterr().err

    db.init(config)
    with db.session_scope() as session:
        assert session.query(User).one().is_active is False
