"""Shared fixtures.

Every test runs against its own data directory and database, pointed at through
the two environment variables - exactly the way a deployment is configured.

There is no password to sign in with any more, so tests do not go through the
OIDC dance either. They call the same function the callback calls, admit(),
with the claims a provider would deliver, and then attach the resulting session
to the test client. The redirect dance itself belongs to Authlib.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from mmo_vault.server import db, sessions
from mmo_vault.server import config as settings
from mmo_vault.server.app import create_app
from mmo_vault.server.cli import main
from mmo_vault.server.models import Allowlist, Provider, User
from mmo_vault.server.routers.oidc import admit

ORIGIN = "https://vault.example"
ADMIN_EMAIL = "admin@example.test"
HEADERS = {"X-Vault-Request": "1"}


def run_setup(*extra: str) -> int:
    return main([
        "setup", "--non-interactive",
        "--origin", ORIGIN,
        "--kind", "generic", "--provider-name", "idp",
        "--issuer", "https://idp.example",
        "--client-id", "client", "--client-secret", "secret",
        "--admins", ADMIN_EMAIL,
        *extra,
    ])


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    """Points the process at a fresh data directory and database."""
    monkeypatch.setenv("MMO_VAULT_DIR", str(tmp_path))
    monkeypatch.setenv("MMO_VAULT_DATABASE_URL", f"sqlite:///{(tmp_path / 'test.db').as_posix()}")
    return tmp_path


@pytest.fixture
def configured(data_dir):
    """setup has run: origin, one generic provider, one admin on the allowlist."""
    assert run_setup() == 0
    db.init()
    return data_dir


def claims_for(email: str, subject: str | None = None, **extra) -> dict:
    """What a generic provider would say about this person."""
    base = {
        "sub": subject or f"sub-{email}",
        "email": email,
        "email_verified": True,
        "name": email.split("@")[0].capitalize(),
    }
    base.update(extra)
    return base


def provider(session) -> Provider:
    return session.query(Provider).filter(Provider.is_primary.is_(True)).one()


def sign_in(client: TestClient, email: str, **claim_overrides) -> User:
    """Signs the given address in as the provider would, and attaches the
    session cookie to the client. Returns the account."""
    with db.session_scope() as session:
        user = admit(session, provider(session), claims_for(email, **claim_overrides))
        assert user is not None, f"{email} was not admitted - is it allowlisted?"
        config = settings.load(session)
        record = sessions.create(session, config, user)
        session.flush()
        cookie = record.id
        user_id = user.id
    client.cookies.set(sessions.COOKIE_NAME, cookie)
    with db.session_scope() as session:
        return session.get(User, user_id)


def allowlist(email: str, *, is_admin: bool = False) -> None:
    with db.session_scope() as session:
        session.add(Allowlist(provider_id=provider(session).id, email=email.lower(), is_admin=is_admin))


@pytest.fixture
def app(configured):
    return create_app()


@pytest.fixture
def admin(app):
    """A client signed in as the initial administrator."""
    with TestClient(app, base_url=ORIGIN) as client:
        sign_in(client, ADMIN_EMAIL)
        yield client


@pytest.fixture
def anonymous(app):
    with TestClient(app, base_url=ORIGIN) as client:
        yield client


def user_client(app, email: str, *, is_admin: bool = False) -> TestClient:
    """A second signed-in client. Allowlists the address first if needed."""
    with db.session_scope() as session:
        exists = session.query(Allowlist).filter(Allowlist.email == email.lower()).count()
    if not exists:
        allowlist(email, is_admin=is_admin)
    client = TestClient(app, base_url=ORIGIN)
    client.__enter__()
    sign_in(client, email)
    return client


@pytest.fixture
def anyio_backend():
    """Async tests run on asyncio only - trio is not installed."""
    return "asyncio"
