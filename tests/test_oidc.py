"""Who gets in: the allowlist decides, the provider vouches.

admit() is the whole of the sign-in logic that belongs to this service; the
redirect dance around it belongs to Authlib and needs a real provider.
"""

from __future__ import annotations

import pytest

from mmo_vault.server import db, providers
from mmo_vault.server.models import Allowlist, AuditLog, Provider, User
from mmo_vault.server.routers.oidc import admit

from .conftest import ADMIN_EMAIL, claims_for, provider


@pytest.fixture
def session(configured):
    with db.session_scope() as db_session:
        yield db_session


# ------------------------------------------------------------------ admission


def test_an_allowlisted_address_creates_an_account_on_first_sign_in(session):
    user = admit(session, provider(session), claims_for(ADMIN_EMAIL, "sub-1"))
    assert user is not None
    assert user.provider_subject == "sub-1"
    assert user.is_admin is True
    assert user.email == ADMIN_EMAIL
    assert session.query(AuditLog).filter(AuditLog.action == "account_created").count() == 1


def test_an_unlisted_address_gets_nothing(session):
    """No self-registration: the list is the door."""
    assert admit(session, provider(session), claims_for("fremd@example.test")) is None
    assert session.query(User).count() == 0
    denied = session.query(AuditLog).filter(AuditLog.action == "login_denied").one()
    assert "not allowlisted" in denied.detail


def test_the_subject_is_the_identity_not_the_address(session):
    """Once bound, a changed address at the provider does not make a second
    account - and an unrelated account with that address is not touched."""
    admit(session, provider(session), claims_for(ADMIN_EMAIL, "sub-1"))
    session.add(Allowlist(provider_id=provider(session).id, email="neu@example.test"))
    session.flush()
    # Same subject, new address that also happens to be allowlisted.
    again = admit(session, provider(session), claims_for("neu@example.test", "sub-1"))
    assert again is not None
    assert session.query(User).count() == 1
    assert again.email == "neu@example.test"


def test_the_admin_flag_follows_the_allowlist_every_time(session):
    user = admit(session, provider(session), claims_for(ADMIN_EMAIL, "sub-1"))
    assert user.is_admin

    entry = session.query(Allowlist).filter(Allowlist.email == ADMIN_EMAIL).one()
    entry.is_admin = False
    session.flush()
    again = admit(session, provider(session), claims_for(ADMIN_EMAIL, "sub-1"))
    assert again.is_admin is False


def test_removed_from_the_list_means_disabled_at_next_sign_in(session):
    user = admit(session, provider(session), claims_for(ADMIN_EMAIL, "sub-1"))
    session.query(Allowlist).filter(Allowlist.email == ADMIN_EMAIL).delete()
    session.flush()

    assert admit(session, provider(session), claims_for(ADMIN_EMAIL, "sub-1")) is None
    session.flush()
    session.refresh(user)
    # The account stays, with its history; it just does not work any more.
    assert user.is_active is False


def test_a_relisted_account_works_again(session):
    user = admit(session, provider(session), claims_for(ADMIN_EMAIL, "sub-1"))
    user.is_active = False
    session.flush()
    again = admit(session, provider(session), claims_for(ADMIN_EMAIL, "sub-1"))
    assert again.is_active is True


def test_a_token_without_a_subject_is_refused(session):
    claims = claims_for(ADMIN_EMAIL)
    del claims["sub"]
    assert admit(session, provider(session), claims) is None


# -------------------------------------------------------------- verification


def test_an_unverified_address_binds_nothing(session):
    """The guard that keeps a provider with free address choice from taking
    over an account whose address it merely knows."""
    claims = claims_for(ADMIN_EMAIL, email_verified=False)
    assert admit(session, provider(session), claims) is None
    assert session.query(User).count() == 0


def test_addresses_are_matched_case_insensitively(session):
    user = admit(session, provider(session), claims_for("Admin@Example.Test"))
    assert user is not None
    assert user.email == ADMIN_EMAIL


# ------------------------------------------------------- provider differences


def _microsoft(session) -> Provider:
    p = Provider(name="m365", kind="microsoft", tenant="tenant-1",
                 issuer=providers.issuer_for("microsoft", "tenant-1", ""),
                 client_id="c", client_secret="s")
    session.add(p)
    session.flush()
    session.add(Allowlist(provider_id=p.id, email="chef@firma.example", is_admin=True))
    session.flush()
    return p


def test_microsoft_trusts_the_tenant_instead_of_email_verified(session):
    """Microsoft never sets email_verified. The tenant id is the guarantee."""
    p = _microsoft(session)
    claims = {"sub": "ms-1", "tid": "tenant-1", "preferred_username": "Chef@Firma.Example",
              "name": "Der Chef"}
    user = admit(session, p, claims)
    assert user is not None
    assert user.email == "chef@firma.example"
    assert user.name == "Der Chef"


def test_microsoft_refuses_a_foreign_tenant(session):
    """An address is only trustworthy if OUR tenant administers it."""
    p = _microsoft(session)
    claims = {"sub": "ms-2", "tid": "someone-elses-tenant", "email": "chef@firma.example"}
    assert admit(session, p, claims) is None


def test_microsoft_open_tenants_are_refused_at_configuration(session):
    for alias in ("common", "organizations", "consumers"):
        with pytest.raises(providers.ProviderConfigError):
            providers.validate("microsoft", "", alias)


def test_issuer_templates():
    assert providers.issuer_for("microsoft", "abc", "") == "https://login.microsoftonline.com/abc/v2.0"
    assert providers.issuer_for("google", None, "") == "https://accounts.google.com"
    assert providers.issuer_for("generic", None, "https://idp.example/") == "https://idp.example"


def test_group_scope_only_when_sync_is_on():
    assert "GroupMember" not in providers.scopes_for("microsoft", False)
    assert "GroupMember.Read.All" in providers.scopes_for("microsoft", True)
    assert "cloud-identity" in providers.scopes_for("google", True)
    # generic has no group source
    assert providers.scopes_for("generic", True) == providers.BASE_SCOPES
