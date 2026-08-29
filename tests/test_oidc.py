"""Binding an OIDC identity to an existing account.

The redirect dance itself belongs to Authlib and needs a real provider; what is
tested here is the part this service is responsible for - who is let in, and on
what grounds.
"""

from __future__ import annotations

import pytest

from mmo_vault.server import db
from mmo_vault.server.cli import main
from mmo_vault.server.config import Config
from mmo_vault.server.models import Group, Provider, User
from mmo_vault.server.routers.oidc import _allowed_provider_ids, _find_user

PASSWORD = "einSicheresBootstrapPasswort"


@pytest.fixture
def session(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    monkeypatch.setattr("mmo_vault.server.cli.VAR_DIR", tmp_path)
    assert main([
        "--config", str(path), "setup", "--non-interactive",
        "--database-url", f"sqlite:///{tmp_path / 'test.db'}",
        "--admin-name", "admin", "--admin-password", PASSWORD,
        "--rp-id", "vault.example", "--origin", "https://vault.example",
    ]) == 0
    db.init(Config.load(path))
    with db.session_scope() as db_session:
        yield db_session


@pytest.fixture
def provider(session):
    record = Provider(name="google", issuer="https://accounts.google.com",
                      client_id="abc", client_secret="geheim")
    session.add(record)
    session.flush()
    return record


def make_user(session, provider, **kwargs) -> User:
    defaults = dict(name="kollege", email="kollege@example.test", provider_id=provider.id,
                    must_enroll_passkey=True)
    defaults.update(kwargs)
    user = User(**defaults)
    session.add(user)
    session.flush()
    return user


VERIFIED = {"email": "kollege@example.test", "email_verified": True}


def test_the_first_sign_in_binds_the_identity(session, provider):
    user = make_user(session, provider)
    found = _find_user(session, provider, provider.issuer, "sub-123", VERIFIED)

    assert found is user
    assert user.provider_subject == "sub-123"
    # The binding replaces the bootstrap password.
    assert user.must_enroll_passkey is False
    assert user.password_hash is None


def test_the_subject_wins_over_the_mail_address(session, provider):
    """Once bound, the address no longer decides.

    Otherwise a changed mail address at the provider would silently point at a
    different account.
    """
    bound = make_user(session, provider, name="gebunden", email="alt@example.test",
                      provider_subject="sub-123")
    make_user(session, provider, name="andere", email="neu@example.test")

    found = _find_user(session, provider, provider.issuer, "sub-123",
                       {"email": "neu@example.test", "email_verified": True})
    assert found is bound


def test_an_unverified_address_binds_nothing(session, provider):
    """The decisive guard.

    A provider that lets people choose their own address could otherwise take
    over any account whose address it happens to know.
    """
    make_user(session, provider)
    assert _find_user(session, provider, provider.issuer, "sub-123",
                      {"email": "kollege@example.test", "email_verified": False}) is None
    assert _find_user(session, provider, provider.issuer, "sub-123", {"email": ""}) is None


def test_an_unknown_address_creates_nothing(session, provider):
    """No self-registration: an account is created by an administrator."""
    assert _find_user(session, provider, provider.issuer, "sub-999",
                      {"email": "fremd@example.test", "email_verified": True}) is None
    assert session.query(User).filter(User.name == "fremd@example.test").count() == 0


def test_a_second_subject_cannot_take_over(session, provider):
    make_user(session, provider, provider_subject="sub-123")
    assert _find_user(session, provider, provider.issuer, "sub-456", VERIFIED) is None


def test_a_disabled_account_stays_out(session, provider):
    make_user(session, provider, is_active=False)
    assert _find_user(session, provider, provider.issuer, "sub-123", VERIFIED) is None


def test_the_provider_has_to_be_allowed(session, provider):
    """An account without this provider is not bound to it either."""
    make_user(session, provider, provider_id=None)
    assert _find_user(session, provider, provider.issuer, "sub-123", VERIFIED) is None


def test_a_group_can_grant_the_provider(session, provider):
    group = Group(name="team", provider_id=provider.id)
    session.add(group)
    session.flush()
    user = make_user(session, provider, provider_id=None)
    user.groups = [group]
    session.flush()

    assert provider.id in _allowed_provider_ids(user)
    found = _find_user(session, provider, provider.issuer, "sub-123", VERIFIED)
    assert found is user


# ------------------------------------------------------------------- wiring


def test_the_redirect_endpoint_answers_with_a_redirect(tmp_path, monkeypatch):
    """Guards against a mistake the unit tests above cannot see.

    Authlib's Starlette integration is asynchronous. A synchronous endpoint
    would hand FastAPI a coroutine to serialise, and the sign-in would end in a
    500 - without any of the logic below ever being wrong.
    """
    from fastapi.responses import RedirectResponse
    from fastapi.testclient import TestClient

    from mmo_vault.server.app import create_app
    from mmo_vault.server.routers import oidc as oidc_module

    path = tmp_path / "config.toml"
    monkeypatch.setattr("mmo_vault.server.cli.VAR_DIR", tmp_path)
    assert main([
        "--config", str(path), "setup", "--non-interactive",
        "--database-url", f"sqlite:///{tmp_path / 'test.db'}",
        "--admin-name", "admin", "--admin-password", PASSWORD,
        "--rp-id", "vault.example", "--origin", "https://vault.example",
    ]) == 0
    config = Config.load(path)
    db.init(config)
    with db.session_scope() as session:
        session.add(Provider(name="google", issuer="https://accounts.google.com",
                             client_id="abc", client_secret="geheim"))

    class StubClient:
        async def authorize_redirect(self, request, redirect_uri):
            # The redirect URI has to come from the configuration, never from
            # the Host header.
            assert redirect_uri == "https://vault.example/auth/oidc/google/callback"
            return RedirectResponse("https://accounts.google.com/o/oauth2/auth", status_code=302)

    monkeypatch.setattr(oidc_module, "_oauth_client", lambda config, provider: StubClient())

    with TestClient(create_app(config), base_url="https://vault.example") as client:
        result = client.get("/auth/oidc/google", follow_redirects=False)
        assert result.status_code == 302
        assert result.headers["location"].startswith("https://accounts.google.com")
        assert client.get("/auth/oidc/gibtsnicht", follow_redirects=False).status_code == 404
