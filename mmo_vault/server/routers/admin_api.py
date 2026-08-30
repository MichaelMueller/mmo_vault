"""Administration: providers, allowlist, accounts, groups, settings.

Two rules run through the whole file:

  - Nobody is created here. Accounts come into being through sign-in; what an
    administrator manages is the allowlist that decides who may.
  - The service must not be able to lock itself out. The last administrator on
    the allowlist can be neither removed nor demoted.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import config as settings
from .. import deps, providers, sessions
from ..config import Config
from ..models import (
    Allowlist,
    AuditLog,
    Generation,
    Group,
    Provider,
    User,
    Vault,
    VaultAccess,
    VaultLock,
)

router = APIRouter(prefix="/api", tags=["admin"])


# ------------------------------------------------------------------- payloads


class ProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9][a-z0-9_-]*$")
    kind: str = Field(pattern="^(microsoft|google|generic)$")
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str = Field(min_length=1, max_length=255)
    tenant: str | None = Field(default=None, max_length=128)
    issuer: str = Field(default="", max_length=255)
    enabled: bool = True
    sync_groups: bool = False
    is_primary: bool = False


class ProviderUpdate(BaseModel):
    client_id: str | None = Field(default=None, min_length=1, max_length=255)
    client_secret: str | None = Field(default=None, min_length=1, max_length=255)
    tenant: str | None = Field(default=None, max_length=128)
    issuer: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None
    sync_groups: bool | None = None
    is_primary: bool | None = None


class AllowlistCreate(BaseModel):
    provider_id: int
    email: str = Field(min_length=3, max_length=255)
    is_admin: bool = False
    note: str = Field(default="", max_length=255)


class AllowlistUpdate(BaseModel):
    is_admin: bool | None = None
    note: str | None = Field(default=None, max_length=255)


class UserUpdate(BaseModel):
    is_active: bool | None = None
    groups: list[str] | None = None


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=255)


class GroupUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=255)
    members: list[str] | None = None


class SettingsUpdate(BaseModel):
    origin: str | None = None
    session_hours: int | None = Field(default=None, ge=1, le=24 * 30)
    session_idle_minutes: int | None = Field(default=None, ge=1, le=24 * 60)
    max_size_bytes: int | None = Field(default=None, ge=1024)
    lock_ttl_seconds: int | None = Field(default=None, ge=30)
    history_warn_bytes: int | None = Field(default=None, ge=0)
    proxy_headers: bool | None = None
    forwarded_allow_ips: str | None = None
    host: str | None = None
    port: int | None = Field(default=None, ge=1, le=65535)
    workers: int | None = Field(default=None, ge=1, le=64)


# -------------------------------------------------------------------- helpers


def _audit(db: DbSession, actor: User, action: str, target: str, detail: str = "") -> None:
    db.add(AuditLog(actor_id=actor.id, action=action, target=target, detail=detail))


def _provider_json(db: DbSession, config: Config, provider: Provider) -> dict:
    # The client secret never leaves the service, not even towards an
    # administrator: it is write-only by design.
    return {
        "id": provider.id,
        "name": provider.name,
        "kind": provider.kind,
        "issuer": provider.issuer,
        "client_id": provider.client_id,
        "tenant": provider.tenant,
        "scopes": provider.scopes,
        "enabled": provider.enabled,
        "sync_groups": provider.sync_groups,
        "is_primary": provider.is_primary,
        "redirect_uri": providers.redirect_uri(config, provider),
        "allowlisted": db.query(Allowlist).filter(Allowlist.provider_id == provider.id).count(),
        "accounts": db.query(User).filter(User.provider_id == provider.id).count(),
    }


def _allowlist_json(db: DbSession, entry: Allowlist) -> dict:
    account = (
        db.query(User)
        .filter(User.provider_id == entry.provider_id, User.email == entry.email)
        .one_or_none()
    )
    return {
        "id": entry.id,
        "provider_id": entry.provider_id,
        "email": entry.email,
        "is_admin": entry.is_admin,
        "note": entry.note,
        # Whether the person has shown up yet - an entry without an account is
        # an invitation not taken.
        "account_id": account.id if account else None,
        "last_login_at": account.last_login_at.isoformat() if account and account.last_login_at else None,
    }


def _user_json(db: DbSession, user: User) -> dict:
    provider = db.get(Provider, user.provider_id)
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "provider": provider.name if provider else "?",
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        "groups": sorted(g.name for g in user.groups),
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _group_json(db: DbSession, group: Group) -> dict:
    provider = db.get(Provider, group.provider_id) if group.provider_id else None
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "source": group.source,
        "provider": provider.name if provider else None,
        "external_id": group.external_id,
        "last_synced_at": group.last_synced_at.isoformat() if group.last_synced_at else None,
        # A mirror whose provider no longer syncs (switch off, provider disabled
        # or gone) keeps its last membership and is marked as frozen.
        "frozen": group.source == "provider"
        and (provider is None or not provider.enabled or not provider.sync_groups),
        "members": sorted(u.name for u in group.members),
    }


def _other_admin_entries_exist(db: DbSession, entry: Allowlist) -> bool:
    return (
        db.query(Allowlist)
        .filter(Allowlist.is_admin.is_(True), Allowlist.id != entry.id)
        .count()
        > 0
    )


def _normalise_email(value: str) -> str:
    address = value.strip().lower()
    if "@" not in address:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="not a mail address")
    return address


# ------------------------------------------------------------------ providers


@router.get("/providers")
def list_providers(
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> list[dict]:
    rows = db.query(Provider).order_by(Provider.is_primary.desc(), Provider.name)
    return [_provider_json(db, config, p) for p in rows]


@router.post("/providers", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(deps.require_csrf_header)])
def create_provider(
    payload: ProviderCreate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    if db.query(Provider).filter(Provider.name == payload.name).count():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="name already taken")
    try:
        providers.validate(payload.kind, payload.issuer, payload.tenant)
    except providers.ProviderConfigError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    provider = Provider(
        name=payload.name,
        kind=payload.kind,
        issuer=providers.issuer_for(payload.kind, payload.tenant, payload.issuer),
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        tenant=payload.tenant.strip() if payload.tenant else None,
        scopes=providers.scopes_for(payload.kind, payload.sync_groups),
        enabled=payload.enabled,
        sync_groups=payload.sync_groups,
        is_primary=False,
    )
    db.add(provider)
    db.flush()
    if payload.is_primary:
        _make_primary(db, provider)
    _audit(db, admin, "provider_created", provider.name, provider.kind)
    return _provider_json(db, config, provider)


def _make_primary(db: DbSession, provider: Provider) -> None:
    db.query(Provider).filter(Provider.id != provider.id).update({Provider.is_primary: False})
    provider.is_primary = True


@router.patch("/providers/{provider_id}", dependencies=[Depends(deps.require_csrf_header)])
def update_provider(
    provider_id: int,
    payload: ProviderUpdate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    provider = db.get(Provider, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")

    changed = payload.model_dump(exclude_unset=True)
    tenant = changed.get("tenant", provider.tenant)
    issuer = changed.get("issuer", provider.issuer if provider.kind == providers.GENERIC else "")
    try:
        providers.validate(provider.kind, issuer, tenant)
    except providers.ProviderConfigError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    for field in ("client_id", "client_secret", "enabled", "sync_groups"):
        if field in changed and changed[field] is not None:
            setattr(provider, field, changed[field])
    if "tenant" in changed:
        provider.tenant = tenant.strip() if tenant else None
    provider.issuer = providers.issuer_for(provider.kind, provider.tenant, issuer)
    provider.scopes = providers.scopes_for(provider.kind, provider.sync_groups)
    if changed.get("is_primary"):
        _make_primary(db, provider)
    if changed.get("enabled") is False and provider.is_primary:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="make another provider primary before disabling this one",
        )
    _audit(db, admin, "provider_changed", provider.name, ", ".join(sorted(changed)))
    return _provider_json(db, config, provider)


@router.delete("/providers/{provider_id}", dependencies=[Depends(deps.require_csrf_header)])
def delete_provider(
    provider_id: int,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    provider = db.get(Provider, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")
    in_use = (
        db.query(Allowlist).filter(Allowlist.provider_id == provider_id).count()
        + db.query(User).filter(User.provider_id == provider_id).count()
    )
    if in_use or provider.is_primary:
        # A provider with people behind it is disabled, not deleted - deleting
        # would orphan accounts and allowlist entries.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="provider is primary or still has allowlist entries or accounts - disable it instead",
        )
    db.delete(provider)
    _audit(db, admin, "provider_deleted", provider.name)
    return {"ok": True}


# ------------------------------------------------------------------ allowlist


@router.get("/allowlist")
def list_allowlist(
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    rows = db.query(Allowlist).order_by(Allowlist.provider_id, Allowlist.email)
    return [_allowlist_json(db, e) for e in rows]


@router.post("/allowlist", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(deps.require_csrf_header)])
def add_to_allowlist(
    payload: AllowlistCreate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    if db.get(Provider, payload.provider_id) is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown provider")
    email = _normalise_email(payload.email)
    if db.query(Allowlist).filter(
        Allowlist.provider_id == payload.provider_id, Allowlist.email == email
    ).count():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="already on the list")
    entry = Allowlist(
        provider_id=payload.provider_id, email=email, is_admin=payload.is_admin,
        note=payload.note, created_by=admin.id,
    )
    db.add(entry)
    db.flush()
    _audit(db, admin, "allowlist_added", email, "admin" if payload.is_admin else "user")
    return _allowlist_json(db, entry)


@router.patch("/allowlist/{entry_id}", dependencies=[Depends(deps.require_csrf_header)])
def update_allowlist(
    entry_id: int,
    payload: AllowlistUpdate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    entry = db.get(Allowlist, entry_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown entry")
    if payload.is_admin is False and entry.is_admin and not _other_admin_entries_exist(db, entry):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot demote: this is the last administrator on the allowlist",
        )
    if payload.is_admin is not None:
        entry.is_admin = payload.is_admin
        # Takes effect at the next sign-in; a running session is ended here so
        # a demotion does not wait for the cookie to expire.
        account = db.query(User).filter(
            User.provider_id == entry.provider_id, User.email == entry.email
        ).one_or_none()
        if account is not None:
            account.is_admin = payload.is_admin
            sessions.revoke_all_for(db, account.id)
    if payload.note is not None:
        entry.note = payload.note
    _audit(db, admin, "allowlist_changed", entry.email, "admin" if entry.is_admin else "user")
    return _allowlist_json(db, entry)


@router.delete("/allowlist/{entry_id}", dependencies=[Depends(deps.require_csrf_header)])
def remove_from_allowlist(
    entry_id: int,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    entry = db.get(Allowlist, entry_id)
    if entry is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown entry")
    if entry.is_admin and not _other_admin_entries_exist(db, entry):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="cannot remove: this is the last administrator on the allowlist",
        )
    # The account, if any, stays with its history and stops working now - not
    # at its next sign-in attempt.
    account = db.query(User).filter(
        User.provider_id == entry.provider_id, User.email == entry.email
    ).one_or_none()
    if account is not None:
        account.is_active = False
        sessions.revoke_all_for(db, account.id)
    db.delete(entry)
    _audit(db, admin, "allowlist_removed", entry.email)
    return {"ok": True}


# ------------------------------------------------------------------- accounts


@router.get("/users")
def list_users(
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    return [_user_json(db, u) for u in db.query(User).order_by(User.name)]


@router.patch("/users/{user_id}", dependencies=[Depends(deps.require_csrf_header)])
def update_user(
    user_id: int,
    payload: UserUpdate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown account")
    if payload.is_active is not None:
        if not payload.is_active and user.is_admin and not db.query(User).filter(
            User.is_admin.is_(True), User.is_active.is_(True), User.id != user.id
        ).count():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="cannot disable: this is the last active administrator")
        user.is_active = payload.is_active
        if not payload.is_active:
            sessions.revoke_all_for(db, user.id)
    if payload.groups is not None:
        # Only local groups are assigned by hand; provider groups are whatever
        # the last sync said.
        local = [g for g in user.groups if g.source != "local"]
        for name in payload.groups:
            group = db.query(Group).filter(Group.name == name, Group.source == "local").one_or_none()
            if group is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=f"unknown local group '{name}'")
            local.append(group)
        user.groups = local
    _audit(db, admin, "account_changed", user.name)
    return _user_json(db, user)


@router.post("/users/{user_id}/revoke-sessions", dependencies=[Depends(deps.require_csrf_header)])
def revoke_sessions(
    user_id: int,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    return {"revoked": sessions.revoke_all_for(db, user_id)}


@router.delete("/users/{user_id}", dependencies=[Depends(deps.require_csrf_header)])
def delete_user(
    user_id: int,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown account")
    if user.is_admin and user.is_active and not db.query(User).filter(
        User.is_admin.is_(True), User.is_active.is_(True), User.id != user.id
    ).count():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="cannot delete: this is the last active administrator")

    # Everything that references the account, spelled out in one place. Half of
    # these have no relationship configured, so the unit of work cannot know -
    # and a leftover vault_access row would grant a later account the
    # permissions of this one.
    sessions.revoke_all_for(db, user.id)
    db.query(VaultLock).filter(VaultLock.user_id == user.id).delete()
    db.query(VaultAccess).filter(
        VaultAccess.subject_type == "user", VaultAccess.subject_id == user.id
    ).delete()
    db.query(Allowlist).filter(Allowlist.created_by == user.id).update({Allowlist.created_by: None})
    db.query(Vault).filter(Vault.created_by == user.id).update({Vault.created_by: None})
    db.query(Generation).filter(Generation.author_id == user.id).update({Generation.author_id: None})
    db.query(AuditLog).filter(AuditLog.actor_id == user.id).update({AuditLog.actor_id: None})
    user.groups = []
    name = user.name
    db.delete(user)
    _audit(db, admin, "account_deleted", name)
    return {"ok": True}


# --------------------------------------------------------------------- groups


@router.get("/groups")
def list_groups(
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    return [_group_json(db, g) for g in db.query(Group).order_by(Group.source, Group.name)]


@router.post("/groups", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(deps.require_csrf_header)])
def create_group(
    payload: GroupCreate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    if db.query(Group).filter(Group.name == payload.name).count():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="name already taken")
    group = Group(name=payload.name, description=payload.description, source="local")
    db.add(group)
    db.flush()
    _audit(db, admin, "group_created", group.name)
    return _group_json(db, group)


@router.patch("/groups/{group_id}", dependencies=[Depends(deps.require_csrf_header)])
def update_group(
    group_id: int,
    payload: GroupUpdate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown group")
    if payload.description is not None:
        group.description = payload.description
    if payload.members is not None:
        if group.source != "local":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail="membership of a provider group comes from the provider")
        members = []
        for name in payload.members:
            user = db.query(User).filter(User.name == name).one_or_none()
            if user is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=f"unknown account '{name}'")
            members.append(user)
        group.members = members
    _audit(db, admin, "group_changed", group.name)
    return _group_json(db, group)


@router.delete("/groups/{group_id}", dependencies=[Depends(deps.require_csrf_header)])
def delete_group(
    group_id: int,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown group")
    # Memberships go with it; the accounts stay. The shares MUST go with it as
    # well - a leftover row would grant a later group the vaults of this one.
    db.query(VaultAccess).filter(
        VaultAccess.subject_type == "group", VaultAccess.subject_id == group.id
    ).delete()
    group.members = []
    name = group.name
    db.delete(group)
    _audit(db, admin, "group_deleted", name)
    return {"ok": True}


# ------------------------------------------------------------------- settings


def _settings_json(config: Config) -> dict:
    return {
        "origin": config.origin,
        "session_hours": config.auth.session_hours,
        "session_idle_minutes": config.auth.session_idle_minutes,
        "max_size_bytes": config.vault.max_size_bytes,
        "lock_ttl_seconds": config.vault.lock_ttl_seconds,
        "history_warn_bytes": config.vault.history_warn_bytes,
        "proxy_headers": config.server.proxy_headers,
        "forwarded_allow_ips": config.server.forwarded_allow_ips,
        "host": config.server.host,
        "port": config.server.port,
        "workers": config.server.workers,
        # secret_key is deliberately absent: nobody needs to see it.
    }


@router.get("/settings")
def get_settings(
    _admin: User = Depends(deps.require_admin),
    config: Config = Depends(deps.get_config),
) -> dict:
    return _settings_json(config)


@router.put("/settings", dependencies=[Depends(deps.require_csrf_header)])
def put_settings(
    payload: SettingsUpdate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    changed = payload.model_dump(exclude_unset=True)
    if "origin" in changed:
        origin = (changed["origin"] or "").strip().rstrip("/")
        if not origin.startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail="origin must be https:// (or plain localhost)")
        config.origin = origin
    for key in ("session_hours", "session_idle_minutes"):
        if key in changed:
            setattr(config.auth, key, changed[key])
    for key in ("max_size_bytes", "lock_ttl_seconds", "history_warn_bytes"):
        if key in changed:
            setattr(config.vault, key, changed[key])
    for key in ("proxy_headers", "forwarded_allow_ips", "host", "port", "workers"):
        if key in changed:
            setattr(config.server, key, changed[key])
    settings.save(db, config)
    _audit(db, admin, "settings_changed", ", ".join(sorted(changed)))
    return _settings_json(config)
