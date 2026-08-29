"""Who may do what with a vault, and who is holding it.

Two things live here that the endpoints only apply:

  - the effective permission, which follows from the account and its groups
  - the advisory lock, which keeps two people out of each other's way

The lock is never what protects the data. That is the ETag: even a lock that
expired unnoticed cannot cause a lost write, because a stale ETag is refused.
"""

from __future__ import annotations

import datetime as dt
import secrets

from sqlalchemy.orm import Session as DbSession

from .config import Config
from .models import User, Vault, VaultAccess, VaultLock, utcnow
from .security import new_session_id

READ = "read"
READWRITE = "readwrite"
# Wider wins where several rules apply to the same account.
_RANK = {READ: 1, READWRITE: 2}


def effective_permission(db: DbSession, user: User, vault_id: str) -> str | None:
    """The permission of this account on this vault, or None.

    Administrators are deliberately not included. They create vaults and hand
    them out; reading the content is a separate matter and needs an entry of its
    own. An administrator who wants access grants it - visibly, in the list.
    """
    subjects = [("user", user.id)] + [("group", group.id) for group in user.groups]
    best: str | None = None
    for subject_type, subject_id in subjects:
        entry = (
            db.query(VaultAccess)
            .filter(
                VaultAccess.vault_id == vault_id,
                VaultAccess.subject_type == subject_type,
                VaultAccess.subject_id == subject_id,
            )
            .one_or_none()
        )
        if entry is None:
            continue
        if best is None or _RANK[entry.permission] > _RANK[best]:
            best = entry.permission
    return best


def visible_vaults(db: DbSession, user: User) -> list[tuple[Vault, str | None]]:
    """The vaults this account gets to see, each with its permission.

    Administrators see all of them - they have to be able to manage what they
    cannot read.
    """
    result = []
    for vault in db.query(Vault).order_by(Vault.name):
        permission = effective_permission(db, user, vault.id)
        if permission is None and not user.is_admin:
            continue
        result.append((vault, permission))
    return result


# --------------------------------------------------------------------- locks


def active_lock(db: DbSession, vault_id: str) -> VaultLock | None:
    """The lock, if there is a live one.

    Expiry is evaluated lazily: an expired lock counts as absent and is cleared
    on sight. That saves a background job whose only purpose would be to delete
    rows nobody looks at.
    """
    lock = db.get(VaultLock, vault_id)
    if lock is None:
        return None
    if lock.expires_at <= utcnow():
        db.delete(lock)
        return None
    return lock


def acquire(db: DbSession, config: Config, vault_id: str, user: User) -> tuple[VaultLock | None, VaultLock | None]:
    """Returns (acquired, held_by_other).

    Taking a lock one already holds renews it - reconnecting after a reload
    should not have to wait for the old one to expire.
    """
    existing = active_lock(db, vault_id)
    if existing is not None and existing.user_id != user.id:
        return None, existing

    deadline = utcnow() + dt.timedelta(seconds=config.vault.lock_ttl_seconds)
    if existing is not None:
        existing.expires_at = deadline
        return existing, None

    lock = VaultLock(
        vault_id=vault_id, user_id=user.id, token=new_session_id(), expires_at=deadline
    )
    db.add(lock)
    return lock, None


def renew(db: DbSession, config: Config, vault_id: str, token: str) -> VaultLock | None:
    lock = active_lock(db, vault_id)
    if lock is None or not secrets.compare_digest(lock.token, token or ""):
        return None
    lock.expires_at = utcnow() + dt.timedelta(seconds=config.vault.lock_ttl_seconds)
    return lock


def release(db: DbSession, vault_id: str, token: str) -> bool:
    lock = active_lock(db, vault_id)
    if lock is None or not secrets.compare_digest(lock.token, token or ""):
        return False
    db.delete(lock)
    return True


def break_lock(db: DbSession, vault_id: str) -> bool:
    """Removes a lock without its token.

    For administrators, when someone left an editor open and went home. The
    previous holder finds out on their next heartbeat.
    """
    lock = db.get(VaultLock, vault_id)
    if lock is None:
        return False
    db.delete(lock)
    return True


def holder_name(db: DbSession, lock: VaultLock | None) -> str | None:
    if lock is None:
        return None
    user = db.get(User, lock.user_id)
    return user.name if user else None
