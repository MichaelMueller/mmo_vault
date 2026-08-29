"""Users, groups and providers - and the guards around them."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mmo_vault.server import db, security
from mmo_vault.server.app import create_app
from mmo_vault.server.cli import main
from mmo_vault.server.config import Config
from mmo_vault.server.models import Group, Provider, Session, User

from .authenticator import SoftAuthenticator

ORIGIN = "https://vault.example"
PASSWORD = "einSicheresBootstrapPasswort"
HEADERS = {"X-Vault-Request": "1"}


@pytest.fixture
def config(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    monkeypatch.setattr("mmo_vault.server.cli.VAR_DIR", tmp_path)
    assert main([
        "--config", str(path), "setup", "--non-interactive",
        "--database-url", f"sqlite:///{tmp_path / 'test.db'}",
        "--admin-name", "admin", "--admin-password", PASSWORD,
        "--rp-id", "vault.example", "--origin", ORIGIN,
    ]) == 0
    return Config.load(path)


@pytest.fixture
def admin(config):
    """A client signed in as an administrator with a registered passkey."""
    with TestClient(create_app(config), base_url=ORIGIN) as client:
        client.post("/auth/login", json={"name": "admin", "password": PASSWORD}, headers=HEADERS)
        started = client.post("/auth/passkey/register/options", headers=HEADERS).json()
        device = SoftAuthenticator()
        client.post(
            "/auth/passkey/register/verify",
            json={
                "challenge_id": started["challenge_id"],
                "credential": device.create(started["options"], ORIGIN),
                "label": "Laptop",
            },
            headers=HEADERS,
        )
        yield client


# ---------------------------------------------------------------------- users


def test_a_new_account_gets_a_one_time_password(admin):
    result = admin.post("/api/users", json={"name": "kollege", "email": "k@example.test"},
                        headers=HEADERS)
    assert result.status_code == 201, result.text
    body = result.json()
    # Created, but not usable yet: a passkey has to come first.
    assert body["must_enroll_passkey"] is True
    assert body["enroll_expires_at"] is not None
    assert len(body["one_time_password"]) >= 16


def test_the_new_account_can_only_register(admin, config):
    created = admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).json()

    with TestClient(create_app(config), base_url=ORIGIN) as client:
        signed_in = client.post(
            "/auth/login",
            json={"name": "kollege", "password": created["one_time_password"]},
            headers=HEADERS,
        )
        assert signed_in.status_code == 200
        assert signed_in.json()["enrollment_required"] is True
        assert client.get("/api/me").status_code == 403
        # And of course no administration.
        assert client.get("/api/users").status_code == 403


def test_a_normal_account_may_not_administer(admin, config):
    created = admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).json()
    with TestClient(create_app(config), base_url=ORIGIN) as client:
        client.post("/auth/login", json={"name": "kollege",
                                         "password": created["one_time_password"]}, headers=HEADERS)
        started = client.post("/auth/passkey/register/options", headers=HEADERS).json()
        device = SoftAuthenticator()
        client.post("/auth/passkey/register/verify",
                    json={"challenge_id": started["challenge_id"],
                          "credential": device.create(started["options"], ORIGIN)},
                    headers=HEADERS)
        assert client.get("/api/me").status_code == 200
        assert client.get("/api/users").status_code == 403


def test_duplicate_names_are_refused(admin):
    admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS)
    assert admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).status_code == 409


def test_the_last_administrator_is_protected(admin, config):
    """The service must not be able to lock itself out."""
    db.init(config)
    with db.session_scope() as session:
        admin_id = session.query(User).filter(User.name == "admin").one().id

    assert admin.patch(f"/api/users/{admin_id}", json={"is_admin": False},
                       headers=HEADERS).status_code == 409
    assert admin.patch(f"/api/users/{admin_id}", json={"is_active": False},
                       headers=HEADERS).status_code == 409
    assert admin.delete(f"/api/users/{admin_id}", headers=HEADERS).status_code == 409

    # With a second administrator it is allowed.
    second = admin.post("/api/users", json={"name": "zweiter", "is_admin": True},
                        headers=HEADERS).json()
    assert admin.patch(f"/api/users/{admin_id}", json={"is_admin": False},
                       headers=HEADERS).status_code == 200
    assert second["is_admin"] is True


def test_disabling_an_account_revokes_its_sessions(admin, config):
    created = admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).json()
    with TestClient(create_app(config), base_url=ORIGIN) as client:
        client.post("/auth/login", json={"name": "kollege",
                                         "password": created["one_time_password"]}, headers=HEADERS)

        admin.patch(f"/api/users/{created['id']}", json={"is_active": False}, headers=HEADERS)
        # The open session is gone, not merely useless.
        assert client.post("/auth/passkey/register/options", headers=HEADERS).status_code == 401

    db.init(config)
    with db.session_scope() as session:
        assert session.query(Session).filter(Session.user_id == created["id"]).count() == 0


def test_enroll_from_the_interface(admin, config):
    created = admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).json()
    result = admin.post(f"/api/users/{created['id']}/enroll", headers=HEADERS)
    assert result.status_code == 200
    new_password = result.json()["one_time_password"]
    assert new_password != created["one_time_password"]

    with TestClient(create_app(config), base_url=ORIGIN) as client:
        assert client.post("/auth/login", json={"name": "kollege", "password": new_password},
                           headers=HEADERS).status_code == 200


def test_a_lost_passkey_can_be_removed(admin, config):
    db.init(config)
    with db.session_scope() as session:
        user = session.query(User).filter(User.name == "admin").one()
        user_id, credential_id = user.id, user.credentials[0].id

    assert admin.delete(f"/api/users/{user_id}/credentials/{credential_id}",
                        headers=HEADERS).status_code == 200
    assert admin.get("/api/users").json()[0]["credentials"] == []


# --------------------------------------------------------------------- groups


def test_groups_and_memberships(admin):
    assert admin.post("/api/groups", json={"name": "team", "description": "Abteilung"},
                      headers=HEADERS).status_code == 201
    created = admin.post("/api/users", json={"name": "kollege", "groups": ["team"]},
                         headers=HEADERS)
    assert created.status_code == 201
    assert created.json()["groups"] == ["team"]

    groups = admin.get("/api/groups").json()
    assert groups[0]["members"] == 1

    # An unknown group is an error, not a silently ignored value.
    assert admin.post("/api/users", json={"name": "x", "groups": ["gibtsnicht"]},
                      headers=HEADERS).status_code == 400


def test_deleting_a_group_keeps_the_accounts(admin, config):
    admin.post("/api/groups", json={"name": "team"}, headers=HEADERS)
    admin.post("/api/users", json={"name": "kollege", "groups": ["team"]}, headers=HEADERS)
    group_id = admin.get("/api/groups").json()[0]["id"]

    assert admin.delete(f"/api/groups/{group_id}", headers=HEADERS).status_code == 200
    names = [u["name"] for u in admin.get("/api/users").json()]
    assert "kollege" in names


# ------------------------------------------------------------------ providers


def test_the_client_secret_is_write_only(admin):
    result = admin.post("/api/providers", json={
        "name": "google", "issuer": "https://accounts.google.com",
        "client_id": "abc", "client_secret": "streng-geheim",
    }, headers=HEADERS)
    assert result.status_code == 201
    assert "client_secret" not in result.json()
    listed = admin.get("/api/providers").json()[0]
    assert "client_secret" not in listed
    assert listed["issuer"] == "https://accounts.google.com"


def test_a_provider_in_use_cannot_be_deleted(admin):
    admin.post("/api/providers", json={
        "name": "google", "issuer": "https://accounts.google.com",
        "client_id": "abc", "client_secret": "geheim",
    }, headers=HEADERS)
    provider_id = admin.get("/api/providers").json()[0]["id"]
    admin.post("/api/users", json={"name": "kollege", "provider_id": provider_id}, headers=HEADERS)

    assert admin.delete(f"/api/providers/{provider_id}", headers=HEADERS).status_code == 409


def test_enabled_providers_show_up_before_sign_in(admin, config):
    admin.post("/api/providers", json={
        "name": "google", "issuer": "https://accounts.google.com",
        "client_id": "abc", "client_secret": "geheim",
    }, headers=HEADERS)
    admin.post("/api/providers", json={
        "name": "intern", "issuer": "https://idp.example", "client_id": "x",
        "client_secret": "y", "enabled": False,
    }, headers=HEADERS)

    with TestClient(create_app(config), base_url=ORIGIN) as anonymous:
        body = anonymous.get("/api/config").json()
        assert [p["name"] for p in body["providers"]] == ["google"]


# ---------------------------------------------------------------------- pages


def test_pages_route_by_session_state(admin, config):
    """Where a session lands is decided by what it may do."""
    assert admin.get("/admin").status_code == 200
    # Since phase 6 the root serves the vault application - for administrators
    # too. The administration keeps its own address.
    landing = admin.get("/", follow_redirects=False)
    assert landing.status_code == 200
    assert "window.mmoVaultServer" in landing.text

    with TestClient(create_app(config), base_url=ORIGIN) as anonymous:
        assert anonymous.get("/login").status_code == 200
        assert anonymous.get("/", follow_redirects=False).headers["location"] == "/login"
        # An anonymous visitor must not reach the administration.
        assert anonymous.get("/admin").status_code == 401

    created = admin.post("/api/users", json={"name": "kollege"}, headers=HEADERS).json()
    with TestClient(create_app(config), base_url=ORIGIN) as client:
        client.post("/auth/login", json={"name": "kollege",
                                         "password": created["one_time_password"]}, headers=HEADERS)
        # An enrolment session has exactly one destination.
        assert client.get("/", follow_redirects=False).headers["location"] == "/enroll"
        assert client.get("/enroll").status_code == 200
        assert client.get("/admin").status_code == 403


def test_the_login_page_offers_the_enabled_providers(admin, config):
    admin.post("/api/providers", json={
        "name": "google", "issuer": "https://accounts.google.com",
        "client_id": "abc", "client_secret": "geheim",
    }, headers=HEADERS)
    with TestClient(create_app(config), base_url=ORIGIN) as anonymous:
        page = anonymous.get("/login").text
        assert "/auth/oidc/google" in page
        # And nothing that would give away accounts.
        assert "admin" not in page.lower().split("<script")[0]
