"""Managing users, groups and identity providers.

Everything here is for administrators. Two rules run through the whole file:

  - An account is never created by signing in. Someone has to create it, and
    only then can an identity be bound to it.
  - The service must not be able to lock itself out. The last administrator
    cannot be removed, disabled or demoted - not even by themselves.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import deps, security, sessions
from ..config import Config
from ..models import Credential, Group, Provider, User, utcnow

router = APIRouter(prefix="/api", tags=["admin"])


# ------------------------------------------------------------------- payloads


class UserCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    email: str = Field(default="", max_length=255)
    is_admin: bool = False
    provider_id: int | None = None
    groups: list[str] = Field(default_factory=list)


class UserUpdate(BaseModel):
    email: str | None = Field(default=None, max_length=255)
    is_admin: bool | None = None
    is_active: bool | None = None
    provider_id: int | None = None
    groups: list[str] | None = None


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=255)
    provider_id: int | None = None


class GroupUpdate(BaseModel):
    description: str | None = Field(default=None, max_length=255)
    provider_id: int | None = None


class ProviderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    issuer: str = Field(min_length=1, max_length=255)
    client_id: str = Field(min_length=1, max_length=255)
    client_secret: str = Field(min_length=1, max_length=255)
    scopes: str = "openid email profile"
    enabled: bool = True


class ProviderUpdate(BaseModel):
    issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: str | None = None
    enabled: bool | None = None


# -------------------------------------------------------------------- helpers


def _user_json(user: User) -> dict:
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "is_admin": user.is_admin,
        "is_active": user.is_active,
        # What state the account is in - the interface shows this, because an
        # account without a passkey cannot do anything yet.
        "must_enroll_passkey": user.must_enroll_passkey,
        "enroll_expires_at": user.enroll_expires_at.isoformat() if user.enroll_expires_at else None,
        "provider_id": user.provider_id,
        "groups": sorted(group.name for group in user.groups),
        "credentials": [
            {
                "id": credential.id,
                "label": credential.label,
                "backup_eligible": credential.backup_eligible,
                "last_used_at": credential.last_used_at.isoformat() if credential.last_used_at else None,
            }
            for credential in user.credentials
        ],
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


def _group_json(group: Group, members: int) -> dict:
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "provider_id": group.provider_id,
        "members": members,
    }


def _provider_json(provider: Provider) -> dict:
    # The client secret never leaves the service, not even towards an
    # administrator: it is write-only by design.
    return {
        "id": provider.id,
        "name": provider.name,
        "issuer": provider.issuer,
        "client_id": provider.client_id,
        "scopes": provider.scopes,
        "enabled": provider.enabled,
    }


def _resolve_groups(db: DbSession, names: list[str]) -> list[Group]:
    groups = []
    for name in names:
        group = db.query(Group).filter(Group.name == name).one_or_none()
        if group is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=f"unknown group '{name}'"
            )
        groups.append(group)
    return groups


def _other_admins_exist(db: DbSession, user: User) -> bool:
    return (
        db.query(User)
        .filter(User.is_admin.is_(True), User.is_active.is_(True), User.id != user.id)
        .count()
        > 0
    )


def _protect_last_admin(db: DbSession, user: User, action: str) -> None:
    if user.is_admin and user.is_active and not _other_admins_exist(db, user):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"cannot {action}: this is the last administrator",
        )


def _require_provider(db: DbSession, provider_id: int | None) -> None:
    if provider_id is not None and db.get(Provider, provider_id) is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="unknown provider")


# ---------------------------------------------------------------------- users


@router.get("/users")
def list_users(
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    return [_user_json(user) for user in db.query(User).order_by(User.name)]


@router.post("/users", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(deps.require_csrf_header)])
def create_user(
    payload: UserCreate,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    if db.query(User).filter(User.name == payload.name).count():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="name already taken")
    _require_provider(db, payload.provider_id)

    # A one-time password, exactly like `enroll`: it opens a session that can do
    # nothing but register a passkey, and it expires.
    password = security.generate_password()
    user = User(
        name=payload.name,
        email=payload.email,
        is_admin=payload.is_admin,
        provider_id=payload.provider_id,
        password_hash=security.hash_password(password),
        must_enroll_passkey=True,
        enroll_expires_at=security.enrollment_deadline(config.auth.enrollment_hours),
    )
    user.groups = _resolve_groups(db, payload.groups)
    db.add(user)
    db.flush()
    return {
        **_user_json(user),
        # Shown once. It is not stored anywhere in plain text and cannot be
        # retrieved again - only replaced.
        "one_time_password": password,
    }


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

    if payload.is_admin is False or payload.is_active is False:
        _protect_last_admin(db, user, "demote or disable")

    if payload.email is not None:
        user.email = payload.email
    if payload.is_admin is not None:
        user.is_admin = payload.is_admin
    if payload.is_active is not None:
        user.is_active = payload.is_active
        if not payload.is_active:
            # A disabled account must not keep working through an open session.
            sessions.revoke_all_for(db, user.id)
    if payload.provider_id is not None or "provider_id" in payload.model_fields_set:
        _require_provider(db, payload.provider_id)
        user.provider_id = payload.provider_id
    if payload.groups is not None:
        user.groups = _resolve_groups(db, payload.groups)

    return _user_json(user)


@router.delete("/users/{user_id}", dependencies=[Depends(deps.require_csrf_header)])
def delete_user(
    user_id: int,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown account")
    _protect_last_admin(db, user, "delete")
    sessions.revoke_all_for(db, user.id)
    db.delete(user)
    return {"ok": True}


@router.post("/users/{user_id}/enroll", dependencies=[Depends(deps.require_csrf_header)])
def reopen_enrollment(
    user_id: int,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    """The same thing `mmo_vault.py enroll` does, from the interface."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown account")
    password = security.generate_password()
    user.password_hash = security.hash_password(password)
    user.must_enroll_passkey = True
    user.enroll_expires_at = security.enrollment_deadline(config.auth.enrollment_hours)
    user.failed_attempts = 0
    user.locked_until = None
    return {"one_time_password": password,
            "expires_at": user.enroll_expires_at.isoformat()}


@router.delete("/users/{user_id}/credentials/{credential_id}",
               dependencies=[Depends(deps.require_csrf_header)])
def delete_credential(
    user_id: int,
    credential_id: int,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    """Removes a lost device.

    Removing the last one leaves the account without a way in on purpose - the
    way back is `enroll`, which is a deliberate act with a deadline rather than
    a silently reopened password.
    """
    credential = db.get(Credential, credential_id)
    if credential is None or credential.user_id != user_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown passkey")
    db.delete(credential)
    return {"ok": True}


@router.post("/users/{user_id}/revoke-sessions",
             dependencies=[Depends(deps.require_csrf_header)])
def revoke_sessions(
    user_id: int,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    return {"revoked": sessions.revoke_all_for(db, user_id)}


# --------------------------------------------------------------------- groups


@router.get("/groups")
def list_groups(
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    return [_group_json(group, len(group.members)) for group in db.query(Group).order_by(Group.name)]


@router.post("/groups", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(deps.require_csrf_header)])
def create_group(
    payload: GroupCreate,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    if db.query(Group).filter(Group.name == payload.name).count():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="name already taken")
    _require_provider(db, payload.provider_id)
    group = Group(**payload.model_dump())
    db.add(group)
    db.flush()
    return _group_json(group, 0)


@router.patch("/groups/{group_id}", dependencies=[Depends(deps.require_csrf_header)])
def update_group(
    group_id: int,
    payload: GroupUpdate,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown group")
    if payload.description is not None:
        group.description = payload.description
    if "provider_id" in payload.model_fields_set:
        _require_provider(db, payload.provider_id)
        group.provider_id = payload.provider_id
    return _group_json(group, len(group.members))


@router.delete("/groups/{group_id}", dependencies=[Depends(deps.require_csrf_header)])
def delete_group(
    group_id: int,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    group = db.get(Group, group_id)
    if group is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown group")
    # Memberships go with it; the accounts stay.
    group.members = []
    db.delete(group)
    return {"ok": True}


# ------------------------------------------------------------------ providers


@router.get("/providers")
def list_providers(
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    return [_provider_json(p) for p in db.query(Provider).order_by(Provider.name)]


@router.post("/providers", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(deps.require_csrf_header)])
def create_provider(
    payload: ProviderCreate,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    if db.query(Provider).filter(Provider.name == payload.name).count():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="name already taken")
    provider = Provider(**payload.model_dump())
    db.add(provider)
    db.flush()
    return _provider_json(provider)


@router.patch("/providers/{provider_id}", dependencies=[Depends(deps.require_csrf_header)])
def update_provider(
    provider_id: int,
    payload: ProviderUpdate,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    provider = db.get(Provider, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(provider, field, value)
    return _provider_json(provider)


@router.delete("/providers/{provider_id}", dependencies=[Depends(deps.require_csrf_header)])
def delete_provider(
    provider_id: int,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    provider = db.get(Provider, provider_id)
    if provider is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown provider")
    in_use = (
        db.query(User).filter(User.provider_id == provider_id).count()
        + db.query(Group).filter(Group.provider_id == provider_id).count()
    )
    if in_use:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"still assigned to {in_use} account(s) or group(s)",
        )
    db.delete(provider)
    return {"ok": True}
