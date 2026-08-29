"""Signing in: passkeys, the enrollment obligation, backup codes, sessions.

Runs against a real software authenticator (tests/authenticator.py), so the
WebAuthn verification in the service is genuinely exercised.
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient

from mmo_vault.server import db, deps, security, sessions
from mmo_vault.server.app import create_app
from mmo_vault.server.cli import main
from mmo_vault.server.config import Config
from mmo_vault.server.models import BackupCode, Credential, Session, User, utcnow

from .authenticator import SoftAuthenticator

ORIGIN = "https://vault.example"
RP_ID = "vault.example"
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
        "--rp-id", RP_ID, "--origin", ORIGIN,
    ]) == 0
    return Config.load(path)


@pytest.fixture
def client(config):
    with TestClient(create_app(config), base_url=ORIGIN) as test_client:
        yield test_client


def login_with_password(client, name: str = "admin", password: str = PASSWORD):
    return client.post("/auth/login", json={"name": name, "password": password}, headers=HEADERS)


def register_passkey(client, device: SoftAuthenticator, label: str = "Laptop"):
    started = client.post("/auth/passkey/register/options", headers=HEADERS)
    assert started.status_code == 200, started.text
    body = started.json()
    credential = device.create(body["options"], ORIGIN)
    return client.post(
        "/auth/passkey/register/verify",
        json={"challenge_id": body["challenge_id"], "credential": credential, "label": label},
        headers=HEADERS,
    )


def login_with_passkey(client, device: SoftAuthenticator, name: str | None = "admin"):
    started = client.post("/auth/passkey/options", json={"name": name}, headers=HEADERS)
    assert started.status_code == 200, started.text
    body = started.json()
    credential = device.get(body["options"], ORIGIN)
    return client.post(
        "/auth/passkey/verify",
        json={"challenge_id": body["challenge_id"], "credential": credential},
        headers=HEADERS,
    )


# ------------------------------------------------------- the bootstrap window


def test_password_session_may_only_register(client):
    """The whole point of the enrollment session.

    Between setup and the first sign-in the account is protected by a password
    alone. That is acceptable only because the session it grants can do nothing
    else.
    """
    assert login_with_password(client).json()["enrollment_required"] is True

    # Everything that is not the registration has to be refused.
    assert client.get("/api/me").status_code == 403
    assert client.post("/auth/passkey/register/options", headers=HEADERS).status_code == 200


def test_registration_completes_the_bootstrap(client, config):
    login_with_password(client)
    device = SoftAuthenticator()
    result = register_passkey(client, device)
    assert result.status_code == 200, result.text
    body = result.json()
    assert len(body["backup_codes"]) == security.BACKUP_CODE_COUNT

    # The session is a full one now.
    me = client.get("/api/me")
    assert me.status_code == 200
    assert me.json()["user"] == "admin"

    db.init(config)
    with db.session_scope() as session:
        admin = session.query(User).one()
        # The password is discarded, not merely ignored: a permanent password
        # would keep open the path the passkey is meant to close.
        assert admin.password_hash is None
        assert admin.must_enroll_passkey is False
        assert admin.enroll_expires_at is None
        assert session.query(Credential).count() == 1


def test_password_is_refused_once_a_passkey_exists(client):
    login_with_password(client)
    register_passkey(client, SoftAuthenticator())
    client.post("/auth/logout", headers=HEADERS)

    assert login_with_password(client).status_code == 401


def test_expired_window_refuses_the_password(client, config):
    db.init(config)
    with db.session_scope() as session:
        admin = session.query(User).one()
        admin.enroll_expires_at = utcnow() - dt.timedelta(minutes=1)

    assert login_with_password(client).status_code == 401


# ------------------------------------------------------------------ passkeys


def test_sign_in_with_a_passkey(client):
    login_with_password(client)
    device = SoftAuthenticator()
    register_passkey(client, device)
    client.post("/auth/logout", headers=HEADERS)
    assert client.get("/api/me").status_code == 401

    result = login_with_passkey(client, device)
    assert result.status_code == 200, result.text
    assert result.json() == {"user": "admin", "is_admin": True}
    assert client.get("/api/me").json()["is_admin"] is True


def test_sign_in_without_naming_the_account(client):
    """Discoverable credentials: the browser picks, the service does not have
    to say whether an account exists."""
    login_with_password(client)
    device = SoftAuthenticator()
    register_passkey(client, device)
    client.post("/auth/logout", headers=HEADERS)

    assert login_with_passkey(client, device, name=None).status_code == 200


def test_a_challenge_works_only_once(client):
    login_with_password(client)
    device = SoftAuthenticator()
    register_passkey(client, device)
    client.post("/auth/logout", headers=HEADERS)

    started = client.post("/auth/passkey/options", json={"name": "admin"}, headers=HEADERS).json()
    credential = device.get(started["options"], ORIGIN)
    first = client.post(
        "/auth/passkey/verify",
        json={"challenge_id": started["challenge_id"], "credential": credential},
        headers=HEADERS,
    )
    assert first.status_code == 200
    replay = client.post(
        "/auth/passkey/verify",
        json={"challenge_id": started["challenge_id"], "credential": credential},
        headers=HEADERS,
    )
    assert replay.status_code == 401


def test_an_unknown_passkey_is_refused(client):
    login_with_password(client)
    register_passkey(client, SoftAuthenticator())
    client.post("/auth/logout", headers=HEADERS)

    stranger = SoftAuthenticator()
    started = client.post("/auth/passkey/options", json={"name": "admin"}, headers=HEADERS).json()
    result = client.post(
        "/auth/passkey/verify",
        json={"challenge_id": started["challenge_id"], "credential": stranger.get(started["options"], ORIGIN)},
        headers=HEADERS,
    )
    assert result.status_code == 401


def test_a_second_passkey_can_be_added(client):
    login_with_password(client)
    first = SoftAuthenticator()
    register_passkey(client, first, label="Laptop")
    # A full session may register further devices - that is the recommended
    # protection against losing the only one.
    result = register_passkey(client, SoftAuthenticator(), label="Token")
    assert result.status_code == 200
    assert result.json()["credentials"] == 2
    # No new backup codes: the existing ones stay valid.
    assert result.json()["backup_codes"] == []


# -------------------------------------------------------------- backup codes


def test_a_backup_code_forces_a_new_passkey(client, config):
    login_with_password(client)
    codes = register_passkey(client, SoftAuthenticator()).json()["backup_codes"]
    client.post("/auth/logout", headers=HEADERS)

    result = client.post(
        "/auth/backup-code", json={"name": "admin", "code": codes[0]}, headers=HEADERS
    )
    assert result.status_code == 200
    # Using a code means the device is gone, so the session is restricted again.
    assert result.json()["enrollment_required"] is True
    assert result.json()["codes_left"] == len(codes) - 1
    assert client.get("/api/me").status_code == 403

    assert register_passkey(client, SoftAuthenticator(), label="Ersatz").status_code == 200
    assert client.get("/api/me").status_code == 200


def test_a_backup_code_works_only_once(client):
    login_with_password(client)
    codes = register_passkey(client, SoftAuthenticator()).json()["backup_codes"]
    client.post("/auth/logout", headers=HEADERS)

    assert client.post("/auth/backup-code", json={"name": "admin", "code": codes[0]},
                       headers=HEADERS).status_code == 200
    client.post("/auth/logout", headers=HEADERS)
    assert client.post("/auth/backup-code", json={"name": "admin", "code": codes[0]},
                       headers=HEADERS).status_code == 401


# ------------------------------------------------------------------- the rest


def test_csrf_header_is_required(client):
    """SameSite=Lax already blocks the cross-site form post; the header closes
    the rest."""
    assert client.post("/auth/login", json={"name": "admin", "password": PASSWORD}).status_code == 403


def test_wrong_password_locks_the_account(client, config):
    for _ in range(deps.MAX_FAILED_ATTEMPTS):
        assert login_with_password(client, password="falsch").status_code == 401
    # Locked out - the correct password does not help now either.
    assert login_with_password(client).status_code == 401

    db.init(config)
    with db.session_scope() as session:
        assert session.query(User).one().locked_until is not None


def test_logout_revokes_the_session(client, config):
    login_with_password(client)
    register_passkey(client, SoftAuthenticator())
    assert client.post("/auth/logout", headers=HEADERS).status_code == 200
    assert client.get("/api/me").status_code == 401

    db.init(config)
    with db.session_scope() as session:
        assert session.query(Session).count() == 0


def test_an_idle_session_expires(client, config):
    login_with_password(client)
    register_passkey(client, SoftAuthenticator())

    db.init(config)
    with db.session_scope() as session:
        record = session.query(Session).one()
        record.last_seen_at = utcnow() - dt.timedelta(
            minutes=config.auth.session_idle_minutes + 1
        )

    assert client.get("/api/me").status_code == 401


def test_public_config_says_nothing_about_accounts(client):
    body = client.get("/api/config").json()
    assert body["server"] is True
    assert body["rp_id"] == RP_ID
    assert "users" not in body


# ------------------------------------------------- the loopback exception


def fake_request(host: str, headers: dict[str, str] | None = None):
    """A request straight from the ASGI scope, without a real socket."""
    from starlette.requests import Request

    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    return Request({"type": "http", "method": "POST", "path": "/auth/login",
                    "headers": raw, "client": (host, 12345)})


def test_only_a_real_loopback_peer_counts_as_local():
    assert deps.is_local_request(fake_request("127.0.0.1")) is True
    assert deps.is_local_request(fake_request("::1")) is True
    assert deps.is_local_request(fake_request("192.168.1.10")) is False


def test_a_forwarding_header_disproves_locality():
    """The trap this whole design turns on.

    A reverse proxy on the same host connects from 127.0.0.1, so the peer
    address alone would open the password path to the entire internet. The
    presence of a forwarding header proves something sits in between - and
    since anyone can set a header, it may only ever count against permission.
    """
    assert deps.is_local_request(
        fake_request("127.0.0.1", {"X-Forwarded-For": "203.0.113.9"})
    ) is False
    assert deps.is_local_request(
        fake_request("127.0.0.1", {"Forwarded": "for=203.0.113.9"})
    ) is False


def test_password_login_stays_shut_without_the_option(config):
    """After the bootstrap a password is worthless - unless it was deliberately
    allowed over loopback."""
    db.init(config)
    with db.session_scope() as session:
        user = session.query(User).one()
        user.must_enroll_passkey = False
        user.enroll_expires_at = None

    with db.session_scope() as session:
        user = session.query(User).one()
        assert config.auth.allow_local_password_login is False
        assert deps.password_login_allowed(fake_request("127.0.0.1"), config, user) is False

        config.auth.allow_local_password_login = True
        assert deps.password_login_allowed(fake_request("127.0.0.1"), config, user) is True
        # Switched on, but not from outside, and not through a proxy.
        assert deps.password_login_allowed(fake_request("203.0.113.9"), config, user) is False
        assert deps.password_login_allowed(
            fake_request("127.0.0.1", {"X-Forwarded-For": "203.0.113.9"}), config, user
        ) is False
