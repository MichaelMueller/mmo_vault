"""Group sync at sign-in: the person's own token, the person's own groups.

No service account and no background job. Whoever signs in brings their
group list along; the service mirrors it into provider groups and replaces
that person's provider memberships with it. Local groups are never touched.

The trade-off is spelled out in the plan: a change at the provider shows up
at the next sign-in, not before. And a failed fetch changes nothing - it
neither locks anyone out nor promotes anyone.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx
from sqlalchemy.orm import Session as DbSession

from .models import Group, Provider, User, utcnow

log = logging.getLogger(__name__)

GRAPH_MEMBER_OF = "https://graph.microsoft.com/v1.0/me/memberOf"
GRAPH_GROUP_TYPE = "#microsoft.graph.group"
CLOUD_IDENTITY_SEARCH = "https://cloudidentity.googleapis.com/v1/groups/-/memberships:searchDirectGroups"
TIMEOUT_SECONDS = 10.0
MAX_PAGES = 50  # nobody is in thousands of groups; a looping nextLink is


@dataclass(frozen=True)
class ExternalGroup:
    external_id: str
    name: str


class SyncFailed(Exception):
    """The provider did not answer usably. The caller decides what that means."""


def supports(provider: Provider) -> bool:
    return bool(provider.sync_groups) and provider.kind in ("microsoft", "google")


# --------------------------------------------------------------------- fetch


async def fetch_groups(provider: Provider, access_token: str, email: str,
                       transport: httpx.AsyncBaseTransport | None = None) -> list[ExternalGroup]:
    """Asks the provider for the signed-in person's direct groups.

    `transport` exists for the tests; production leaves it None.
    """
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS, headers=headers,
                                     transport=transport) as client:
            if provider.kind == "microsoft":
                return await _fetch_microsoft(client)
            if provider.kind == "google":
                return await _fetch_google(client, email)
    except httpx.HTTPError as err:
        raise SyncFailed(f"{type(err).__name__}: {err}") from err
    return []


async def _get_json(client: httpx.AsyncClient, url: str, params: dict | None = None) -> dict:
    response = await client.get(url, params=params)
    if response.status_code != 200:
        raise SyncFailed(f"{url.split('?')[0]} answered {response.status_code}")
    try:
        body = response.json()
    except ValueError as err:
        raise SyncFailed("response is not JSON") from err
    if not isinstance(body, dict):
        raise SyncFailed("response is not an object")
    return body


async def _fetch_microsoft(client: httpx.AsyncClient) -> list[ExternalGroup]:
    """GET /me/memberOf, following @odata.nextLink. Directory roles and
    administrative units come back from the same call and are skipped."""
    groups: list[ExternalGroup] = []
    url: str | None = GRAPH_MEMBER_OF
    params: dict | None = {"$select": "id,displayName", "$top": "999"}
    for _ in range(MAX_PAGES):
        if url is None:
            break
        body = await _get_json(client, url, params)
        params = None  # nextLink carries its own query string
        for item in body.get("value", []):
            if item.get("@odata.type") != GRAPH_GROUP_TYPE:
                continue
            external_id = str(item.get("id") or "").strip()
            if external_id:
                groups.append(ExternalGroup(external_id, str(item.get("displayName") or external_id)))
        url = body.get("@odata.nextLink")
    return groups


async def _fetch_google(client: httpx.AsyncClient, email: str) -> list[ExternalGroup]:
    """Cloud Identity searchDirectGroups for the person's own address.

    A private Gmail account has no groups; the answer is simply empty.
    """
    groups: list[ExternalGroup] = []
    quoted = email.replace("\\", "\\\\").replace("'", "\\'")
    params: dict = {"query": f"member_key_id == '{quoted}'", "pageSize": "500"}
    for _ in range(MAX_PAGES):
        body = await _get_json(client, CLOUD_IDENTITY_SEARCH, params)
        for item in body.get("memberships", []):
            external_id = str(item.get("group") or "").strip()  # groups/{id}
            if not external_id:
                continue
            name = item.get("displayName") or (item.get("groupKey") or {}).get("id") or external_id
            groups.append(ExternalGroup(external_id, str(name)))
        token = body.get("nextPageToken")
        if not token:
            break
        params = {**params, "pageToken": token}
    return groups


# --------------------------------------------------------------------- apply


def apply(db: DbSession, provider: Provider, user: User, fetched: list[ExternalGroup]) -> int:
    """Mirrors the fetched list into provider groups and replaces this
    person's memberships in groups of this provider. Returns the count.

    Pure database logic, so it can be tested without a provider.
    """
    seen: dict[str, ExternalGroup] = {}
    for item in fetched:
        seen.setdefault(item.external_id, item)

    existing = {
        g.external_id: g
        for g in db.query(Group).filter(Group.source == "provider", Group.provider_id == provider.id)
    }
    now = utcnow()
    mirrored: list[Group] = []
    for external_id, item in seen.items():
        group = existing.get(external_id)
        if group is None:
            group = Group(source="provider", provider_id=provider.id, external_id=external_id,
                          name=_free_name(db, item.name, provider), description="")
            db.add(group)
        elif group.name != item.name and not _name_taken(db, item.name, exclude=group):
            group.name = item.name  # renamed at the provider; follow if we can
        group.last_synced_at = now
        mirrored.append(group)
    db.flush()

    # Replace memberships of this provider's groups; everything else stays.
    kept = [g for g in user.groups if not (g.source == "provider" and g.provider_id == provider.id)]
    user.groups = kept + mirrored
    db.flush()
    return len(mirrored)


def _name_taken(db: DbSession, name: str, exclude: Group | None = None) -> bool:
    query = db.query(Group).filter(Group.name == name)
    if exclude is not None and exclude.id is not None:
        query = query.filter(Group.id != exclude.id)
    return query.count() > 0


def _free_name(db: DbSession, wanted: str, provider: Provider) -> str:
    """Shares address groups by name, so the name has to stay unique. A
    provider group that collides with a local one gets the provider's name
    appended, then a counter."""
    wanted = (wanted or "").strip()[:100] or "group"
    if not _name_taken(db, wanted):
        return wanted
    candidate = f"{wanted} ({provider.name})"
    counter = 2
    while _name_taken(db, candidate):
        candidate = f"{wanted} ({provider.name} {counter})"
        counter += 1
    return candidate
