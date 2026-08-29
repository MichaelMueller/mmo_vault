"""Vaults: creating, sharing, reading, writing, locking.

The content travels as a raw body with an ETag, not wrapped in JSON. That is
what HTTP already has for exactly this problem: If-Match settles who wrote
last, and no escaping layer sits between the file and the disk.

Two layers guard a write, and the order matters:

  the lock  keeps two people from editing at the same time - advisory
  the ETag  keeps a write from being lost - binding

A lock that expired unnoticed therefore cannot cause damage.
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import deps, storage, vaults
from ..config import Config
from ..models import AuditLog, Generation, Group, User, Vault, VaultAccess, VaultLock, utcnow

router = APIRouter(prefix="/api/vaults", tags=["vaults"])

LOCK_HEADER = "x-vault-lock"


class VaultCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=255)


class VaultUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=255)


class AccessEntry(BaseModel):
    subject_type: str = Field(pattern="^(user|group)$")
    subject: str
    permission: str = Field(pattern="^(read|readwrite)$")


class AccessUpdate(BaseModel):
    entries: list[AccessEntry]


# -------------------------------------------------------------------- helpers


def _audit(db: DbSession, user: User, action: str, target: str, detail: str = "") -> None:
    db.add(AuditLog(actor_id=user.id, action=action, target=target, detail=detail))


def _vault_json(db: DbSession, vault: Vault, permission: str | None, user: User) -> dict:
    lock = vaults.active_lock(db, vault.id)
    return {
        "id": vault.id,
        "name": vault.name,
        "description": vault.description,
        "permission": permission,
        # An administrator without an entry of their own sees the vault but
        # cannot open it. The interface has to be able to tell the difference.
        "manage": user.is_admin,
        "etag": vault.etag or None,
        "empty": not storage.exists(vault.id),
        "size_bytes": vault.size_bytes,
        "locked_by": vaults.holder_name(db, lock) if lock else None,
        "locked_until": lock.expires_at.isoformat() if lock else None,
    }


def _get_vault(db: DbSession, vault_id: str) -> Vault:
    vault = db.get(Vault, vault_id)
    if vault is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="unknown vault")
    return vault


def _require_permission(db: DbSession, user: User, vault_id: str, need: str) -> str:
    permission = vaults.effective_permission(db, user, vault_id)
    if permission is None or (need == vaults.READWRITE and permission != vaults.READWRITE):
        # Same answer for "not shared with you" and "read only": the difference
        # is none of the caller's business.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="no access to this vault")
    return permission


# ------------------------------------------------------------------ managing


@router.get("")
def list_vaults(
    user: User = Depends(deps.require_full_user),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    return [
        _vault_json(db, vault, permission, user)
        for vault, permission in vaults.visible_vaults(db, user)
    ]


@router.post("", status_code=status.HTTP_201_CREATED,
             dependencies=[Depends(deps.require_csrf_header)])
def create_vault(
    payload: VaultCreate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    """Creates an empty shell.

    The vault itself comes into being in the browser of whoever first sets a
    master password. The service never sees it, so it cannot create one.
    """
    vault = Vault(id=str(uuid.uuid4()), name=payload.name,
                  description=payload.description, created_by=admin.id)
    db.add(vault)
    db.flush()
    _audit(db, admin, "vault_created", vault.name)
    return _vault_json(db, vault, None, admin)


@router.patch("/{vault_id}", dependencies=[Depends(deps.require_csrf_header)])
def update_vault(
    vault_id: str,
    payload: VaultUpdate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    vault = _get_vault(db, vault_id)
    if payload.name is not None:
        vault.name = payload.name
    if payload.description is not None:
        vault.description = payload.description
    return _vault_json(db, vault, vaults.effective_permission(db, admin, vault_id), admin)


@router.delete("/{vault_id}", dependencies=[Depends(deps.require_csrf_header)])
def delete_vault(
    vault_id: str,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    vault = _get_vault(db, vault_id)
    name = vault.name
    # Explicitly, and before the vault itself: relying on the unit of work to
    # get the order right fails against the foreign keys, and the message that
    # comes back then says nothing about what actually happened.
    db.query(VaultAccess).filter(VaultAccess.vault_id == vault_id).delete()
    db.query(VaultLock).filter(VaultLock.vault_id == vault_id).delete()
    db.query(Generation).filter(Generation.vault_id == vault_id).delete()
    db.delete(vault)
    # The file goes with it, including everything kept beside it.
    storage.delete(vault_id)
    _audit(db, admin, "vault_deleted", name)
    return {"ok": True}


@router.get("/{vault_id}/access")
def get_access(
    vault_id: str,
    _admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    _get_vault(db, vault_id)
    result = []
    for entry in db.query(VaultAccess).filter(VaultAccess.vault_id == vault_id):
        if entry.subject_type == "user":
            subject = db.get(User, entry.subject_id)
        else:
            subject = db.get(Group, entry.subject_id)
        result.append({
            "subject_type": entry.subject_type,
            "subject": subject.name if subject else "?",
            "permission": entry.permission,
        })
    return result


@router.put("/{vault_id}/access", dependencies=[Depends(deps.require_csrf_header)])
def set_access(
    vault_id: str,
    payload: AccessUpdate,
    admin: User = Depends(deps.require_admin),
    db: DbSession = Depends(deps.get_db),
) -> list[dict]:
    """Replaces the sharing wholesale.

    Deliberately not a patch: whoever edits sharing wants to see the resulting
    state, and a partial update makes it easy to leave an entry behind that
    nobody remembers.
    """
    _get_vault(db, vault_id)
    resolved = []
    for entry in payload.entries:
        if entry.subject_type == "user":
            subject = db.query(User).filter(User.name == entry.subject).one_or_none()
        else:
            subject = db.query(Group).filter(Group.name == entry.subject).one_or_none()
        if subject is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"unknown {entry.subject_type} '{entry.subject}'",
            )
        resolved.append((entry, subject))

    db.query(VaultAccess).filter(VaultAccess.vault_id == vault_id).delete()
    for entry, subject in resolved:
        db.add(VaultAccess(vault_id=vault_id, subject_type=entry.subject_type,
                           subject_id=subject.id, permission=entry.permission))
    _audit(db, admin, "vault_access_changed", vault_id,
           ", ".join(f"{e.subject_type}:{e.subject}={e.permission}" for e in payload.entries))
    return [e.model_dump() for e in payload.entries]


# ------------------------------------------------------------------- content


@router.get("/{vault_id}/content")
def read_content(
    vault_id: str,
    user: User = Depends(deps.require_full_user),
    db: DbSession = Depends(deps.get_db),
):
    _get_vault(db, vault_id)
    _require_permission(db, user, vault_id, vaults.READ)
    text = storage.read(vault_id)
    if text is None:
        # Created but never filled: the browser offers to create a vault here.
        return Response(status_code=status.HTTP_204_NO_CONTENT)
    return PlainTextResponse(
        text,
        media_type="application/x-ndjson",
        headers={"ETag": f'"{storage.compute_etag(text)}"'},
    )


@router.put("/{vault_id}/content", dependencies=[Depends(deps.require_csrf_header)])
async def write_content(
    vault_id: str,
    request: Request,
    user: User = Depends(deps.require_full_user),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    vault = _get_vault(db, vault_id)
    _require_permission(db, user, vault_id, vaults.READWRITE)

    # 1. The lock: whoever writes has to hold it. Advisory, but it keeps two
    #    people from working past each other in the first place.
    lock = vaults.active_lock(db, vault_id)
    token = request.headers.get(LOCK_HEADER)
    if lock is None or lock.token != token:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="no valid lock - acquire one before writing",
        )
    if lock.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="the lock belongs to someone else")

    # 2. The ETag: this is what actually prevents a lost write.
    expected = request.headers.get("if-match")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="If-Match is required",
        )
    current = storage.read(vault_id)
    current_etag = storage.compute_etag(current) if current is not None else ""
    if expected.strip('"') != current_etag:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail="the vault was changed elsewhere in the meantime",
        )

    body = (await request.body()).decode("utf-8")
    try:
        storage.validate(body, config.vault.max_size_bytes)
    except storage.InvalidVault as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    etag, size = storage.write(vault_id, body)
    vault.etag = etag
    vault.size_bytes = size
    # The write counts as activity: the lock must not expire while someone is
    # demonstrably working.
    lock.expires_at = utcnow() + dt.timedelta(seconds=config.vault.lock_ttl_seconds)
    _audit(db, user, "vault_written", vault.name, f"{size} bytes")
    return {"etag": etag, "size_bytes": size}


# --------------------------------------------------------------------- locks


@router.get("/{vault_id}/lock")
def read_lock(
    vault_id: str,
    user: User = Depends(deps.require_full_user),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    _get_vault(db, vault_id)
    _require_permission(db, user, vault_id, vaults.READ)
    lock = vaults.active_lock(db, vault_id)
    return {
        "locked_by": vaults.holder_name(db, lock) if lock else None,
        "locked_until": lock.expires_at.isoformat() if lock else None,
        "mine": bool(lock and lock.user_id == user.id),
    }


@router.post("/{vault_id}/lock", dependencies=[Depends(deps.require_csrf_header)])
def acquire_lock(
    vault_id: str,
    user: User = Depends(deps.require_full_user),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    _get_vault(db, vault_id)
    _require_permission(db, user, vault_id, vaults.READWRITE)
    lock, held_by_other = vaults.acquire(db, config, vault_id, user)
    if lock is None:
        # Not an error to shout about: the caller opens the vault read-only and
        # says who is editing.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"in use by {vaults.holder_name(db, held_by_other)}",
        )
    return {"token": lock.token, "expires_at": lock.expires_at.isoformat()}


@router.put("/{vault_id}/lock", dependencies=[Depends(deps.require_csrf_header)])
def renew_lock(
    vault_id: str,
    request: Request,
    user: User = Depends(deps.require_full_user),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    _get_vault(db, vault_id)
    _require_permission(db, user, vault_id, vaults.READWRITE)
    lock = vaults.renew(db, config, vault_id, request.headers.get(LOCK_HEADER, ""))
    if lock is None:
        # This is how the previous holder learns that the lock was broken.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="the lock is gone")
    return {"token": lock.token, "expires_at": lock.expires_at.isoformat()}


@router.delete("/{vault_id}/lock", dependencies=[Depends(deps.require_csrf_header)])
def release_lock(
    vault_id: str,
    request: Request,
    force: bool = False,
    user: User = Depends(deps.require_full_user),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    _get_vault(db, vault_id)
    if force:
        # Breaking someone else's lock is for administrators, and it is logged.
        if not user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="administrators only")
        broken = vaults.break_lock(db, vault_id)
        if broken:
            _audit(db, user, "vault_lock_broken", vault_id)
        return {"released": broken}
    _require_permission(db, user, vault_id, vaults.READWRITE)
    return {"released": vaults.release(db, vault_id, request.headers.get(LOCK_HEADER, ""))}
