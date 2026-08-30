"""Group sync: mirror, replace, never lock out."""

from __future__ import annotations

import json

import httpx
import pytest

from mmo_vault.server import db, sync
from mmo_vault.server.models import Allowlist, AuditLog, Group, Provider, User
from mmo_vault.server.routers.oidc import admit, sync_groups_on_login

from .conftest import ADMIN_EMAIL, claims_for

G = sync.ExternalGroup


@pytest.fixture
def session(configured):
    with db.session_scope() as db_session:
        yield db_session


def microsoft(session) -> Provider:
    p = Provider(name="m365", kind="microsoft", tenant="tenant-1",
                 issuer="https://login.microsoftonline.com/tenant-1/v2.0",
                 client_id="c", client_secret="s", sync_groups=True)
    session.add(p)
    session.flush()
    session.add(Allowlist(provider_id=p.id, email="chef@firma.example", is_admin=False))
    session.flush()
    return p


def chef(session, p) -> User:
    user = admit(session, p, {"sub": "ms-1", "tid": "tenant-1", "email": "chef@firma.example",
                              "name": "Chef"})
    assert user is not None
    return user


def group_names(user) -> list[str]:
    return sorted(g.name for g in user.groups)


# --------------------------------------------------------------------- apply


def test_sync_creates_provider_groups_and_memberships(session):
    p = microsoft(session)
    user = chef(session, p)
    assert sync.apply(session, p, user, [G("g1", "Vertrieb"), G("g2", "Einkauf")]) == 2
    assert group_names(user) == ["Einkauf", "Vertrieb"]
    mirrored = session.query(Group).filter(Group.source == "provider").all()
    assert {g.external_id for g in mirrored} == {"g1", "g2"}
    assert all(g.provider_id == p.id and g.last_synced_at is not None for g in mirrored)


def test_the_next_sync_replaces_but_leaves_local_groups_alone(session):
    p = microsoft(session)
    user = chef(session, p)
    local = Group(name="handverlesen", source="local")
    session.add(local)
    session.flush()
    user.groups.append(local)
    sync.apply(session, p, user, [G("g1", "Vertrieb"), G("g2", "Einkauf")])

    # Dropped from Einkauf, added to Leitung at the provider.
    sync.apply(session, p, user, [G("g1", "Vertrieb"), G("g3", "Leitung")])
    assert group_names(user) == ["Leitung", "Vertrieb", "handverlesen"]
    # The provider group that lost its member still exists (others may be in it).
    assert session.query(Group).filter(Group.external_id == "g2").count() == 1


def test_the_external_id_is_the_identity_and_renames_follow(session):
    p = microsoft(session)
    user = chef(session, p)
    sync.apply(session, p, user, [G("g1", "Vertrieb")])
    sync.apply(session, p, user, [G("g1", "Sales")])
    assert session.query(Group).filter(Group.source == "provider").count() == 1
    assert group_names(user) == ["Sales"]


def test_a_name_collision_with_a_local_group_is_resolved(session):
    """Shares address groups by name; two groups called 'team' would make a
    share ambiguous. The provider group yields."""
    p = microsoft(session)
    user = chef(session, p)
    session.add(Group(name="team", source="local"))
    session.flush()
    sync.apply(session, p, user, [G("g1", "team")])
    assert group_names(user) == ["team (m365)"]
    assert session.query(Group).filter(Group.name == "team", Group.source == "local").count() == 1


def test_groups_of_another_provider_are_not_touched(session):
    p = microsoft(session)
    user = chef(session, p)
    other = Provider(name="other", kind="google", issuer="https://accounts.google.com",
                     client_id="c", client_secret="s", sync_groups=True)
    session.add(other)
    session.flush()
    foreign = Group(name="fremd", source="provider", provider_id=other.id, external_id="x")
    session.add(foreign)
    session.flush()
    user.groups.append(foreign)
    sync.apply(session, p, user, [G("g1", "Vertrieb")])
    assert group_names(user) == ["Vertrieb", "fremd"]


def test_duplicates_in_the_answer_are_harmless(session):
    p = microsoft(session)
    user = chef(session, p)
    assert sync.apply(session, p, user, [G("g1", "A"), G("g1", "A")]) == 1


# --------------------------------------------------------------------- fetch


def graph(pages: list[dict], status: int = 200) -> httpx.MockTransport:
    """A fake Graph that serves the given pages in order."""
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert request.headers["authorization"] == "Bearer tok"
        if status != 200:
            return httpx.Response(status, json={"error": "nope"})
        return httpx.Response(200, json=pages[len(calls) - 1])

    transport = httpx.MockTransport(handler)
    transport.calls = calls  # type: ignore[attr-defined]
    return transport


@pytest.mark.anyio
async def test_microsoft_follows_paging_and_skips_roles(session):
    p = microsoft(session)
    transport = graph([
        {"value": [
            {"@odata.type": "#microsoft.graph.group", "id": "g1", "displayName": "Vertrieb"},
            {"@odata.type": "#microsoft.graph.directoryRole", "id": "r1", "displayName": "Global Admin"},
        ], "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/memberOf?$skiptoken=abc"},
        {"value": [{"@odata.type": "#microsoft.graph.group", "id": "g2", "displayName": "Einkauf"}]},
    ])
    groups = await sync.fetch_groups(p, "tok", "chef@firma.example", transport=transport)
    assert groups == [G("g1", "Vertrieb"), G("g2", "Einkauf")]
    assert len(transport.calls) == 2
    assert "skiptoken" in str(transport.calls[1].url)


@pytest.mark.anyio
async def test_google_queries_the_own_address(session):
    p = Provider(name="g", kind="google", issuer="https://accounts.google.com",
                 client_id="c", client_secret="s", sync_groups=True)
    session.add(p)
    session.flush()
    transport = graph([
        {"memberships": [{"group": "groups/abc", "displayName": "Alle",
                          "groupKey": {"id": "alle@firma.example"}}],
         "nextPageToken": "t2"},
        {"memberships": [{"group": "groups/def", "groupKey": {"id": "chefs@firma.example"}}]},
    ])
    groups = await sync.fetch_groups(p, "tok", "chef@firma.example", transport=transport)
    assert groups == [G("groups/abc", "Alle"), G("groups/def", "chefs@firma.example")]
    first = transport.calls[0].url
    assert "member_key_id" in str(first) and "chef%40firma.example" in str(first)
    assert "pageToken=t2" in str(transport.calls[1].url)


@pytest.mark.anyio
async def test_an_error_status_is_a_sync_failure(session):
    p = microsoft(session)
    with pytest.raises(sync.SyncFailed):
        await sync.fetch_groups(p, "tok", "chef@firma.example", transport=graph([], status=403))


@pytest.mark.anyio
async def test_a_network_error_is_a_sync_failure(session):
    p = microsoft(session)

    def handler(request):
        raise httpx.ConnectTimeout("slow")

    with pytest.raises(sync.SyncFailed):
        await sync.fetch_groups(p, "tok", "chef@firma.example", transport=httpx.MockTransport(handler))


# ------------------------------------------------------------------- at login


@pytest.mark.anyio
async def test_a_failed_sync_keeps_the_last_state_and_is_audited(session):
    """The rule the whole design rests on: the provider being down changes
    nothing about who is in which group - and does not stop the sign-in."""
    p = microsoft(session)
    user = chef(session, p)
    sync.apply(session, p, user, [G("g1", "Vertrieb")])

    await sync_groups_on_login(session, p, user, "tok", transport=graph([], status=500))
    assert group_names(user) == ["Vertrieb"]
    failed = session.query(AuditLog).filter(AuditLog.action == "group_sync_failed").one()
    assert "500" in failed.detail

    await sync_groups_on_login(session, p, user, "", transport=graph([]))
    assert session.query(AuditLog).filter(AuditLog.action == "group_sync_failed").count() == 2


@pytest.mark.anyio
async def test_a_successful_sync_at_login(session):
    p = microsoft(session)
    user = chef(session, p)
    transport = graph([{"value": [
        {"@odata.type": "#microsoft.graph.group", "id": "g1", "displayName": "Vertrieb"}]}])
    await sync_groups_on_login(session, p, user, "tok", transport=transport)
    assert group_names(user) == ["Vertrieb"]
    assert session.query(AuditLog).filter(AuditLog.action == "group_sync").count() == 1


def test_only_microsoft_and_google_with_the_switch_on(session):
    p = microsoft(session)
    assert sync.supports(p)
    p.sync_groups = False
    assert not sync.supports(p)
    generic = session.query(Provider).filter(Provider.kind == "generic").one()
    generic.sync_groups = True
    assert not sync.supports(generic)
