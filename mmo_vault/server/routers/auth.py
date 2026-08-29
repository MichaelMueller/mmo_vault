"""Signing in, registering passkeys, signing out.

The flow, in one place:

  setup            -> account with a password and must_enroll_passkey
  POST /auth/login -> enrollment session, which may do nothing else
  .../register/*   -> passkey stored, backup codes handed out, password
                      discarded, session promoted to a full one
  from then on     -> POST /auth/passkey/* is the only regular way in
"""

from __future__ import annotations

import secrets as _secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as DbSession

from .. import deps, passkeys, security, sessions
from ..config import Config
from ..models import BackupCode, Session, User, utcnow

router = APIRouter(prefix="/auth", tags=["auth"])

# Verified against when no account (or no hash) exists, so the endpoint takes
# the same time either way. Without it, the quick rejection of an unknown name
# would tell an attacker which accounts exist.
_TIMING_DUMMY_HASH = security.hash_password(_secrets.token_hex(16))


# ------------------------------------------------------------------- payloads


class LoginRequest(BaseModel):
    name: str
    password: str


class PasskeyOptionsRequest(BaseModel):
    name: str | None = None


class PasskeyVerifyRequest(BaseModel):
    challenge_id: str
    credential: dict


class RegisterVerifyRequest(PasskeyVerifyRequest):
    label: str = Field(default="", max_length=64)


class BackupCodeRequest(BaseModel):
    name: str
    code: str


def _record_failure(db: DbSession, user: User) -> None:
    """Counts a failed attempt - and commits it right away.

    Without the commit the rate limiting would be pointless: the rejection
    leaves through an exception, and the surrounding transaction rolls the
    counter back with it. An attacker would get an unlimited budget.
    """
    deps.note_failure(user)
    db.commit()


def _generic_denial() -> HTTPException:
    """One message for every reason.

    Wrong name, wrong password, locked, no such account - all the same to the
    caller, so the endpoint cannot be used to find out which accounts exist.
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="sign-in failed"
    )


# ---------------------------------------------------------------- password


@router.post("/login", dependencies=[Depends(deps.require_csrf_header)])
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    user = db.query(User).filter(User.name == payload.name).one_or_none()
    # The hash is verified on every path, against a dummy when there is nothing
    # real - otherwise the response time gives away which accounts exist.
    stored_hash = user.password_hash if user else None
    password_matches = security.verify_password(
        stored_hash or _TIMING_DUMMY_HASH, payload.password
    ) and stored_hash is not None
    if user is None or not user.is_active or deps.account_locked(user):
        raise _generic_denial()
    if not deps.password_login_allowed(request, config, user):
        raise _generic_denial()
    if not password_matches:
        _record_failure(db, user)
        raise _generic_denial()

    deps.note_success(user)
    # A password only ever yields a restricted session while the account still
    # owes a passkey. Over loopback, with the option switched on, it is a full
    # one - that is the whole of the exception.
    session = sessions.create(
        db, config, user, enrollment_only=user.must_enroll_passkey, request=request
    )
    sessions.attach_cookie(response, config, session)
    return {
        "user": user.name,
        "enrollment_required": user.must_enroll_passkey,
    }


# ----------------------------------------------------------------- passkeys


@router.post("/passkey/options", dependencies=[Depends(deps.require_csrf_header)])
def passkey_options(
    payload: PasskeyOptionsRequest,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    user = None
    if payload.name:
        user = db.query(User).filter(User.name == payload.name).one_or_none()
        # An unknown name yields a challenge as well: whether an account exists
        # is not something this endpoint gives away.
        if user is not None and (not user.is_active or deps.account_locked(user)):
            user = None
    challenge_id, options = passkeys.authentication_options(db, config, user)
    return {"challenge_id": challenge_id, "options": options}


@router.post("/passkey/verify", dependencies=[Depends(deps.require_csrf_header)])
def passkey_verify(
    payload: PasskeyVerifyRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    try:
        credential = passkeys.verify_authentication(
            db, config, payload.challenge_id, payload.credential
        )
    except passkeys.PasskeyError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)
        ) from err

    user = db.get(User, credential.user_id)
    if user is None or not user.is_active:
        raise _generic_denial()

    deps.note_success(user)
    session = sessions.create(db, config, user, enrollment_only=False, request=request)
    sessions.attach_cookie(response, config, session)
    return {"user": user.name, "is_admin": user.is_admin}


@router.post("/passkey/register/options", dependencies=[Depends(deps.require_csrf_header)])
def register_options(
    user: User = Depends(deps.require_user),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    if deps.enrollment_window_closed(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="the registration window has closed - reopen it with `mmo_vault.py enroll`",
        )
    challenge_id, options = passkeys.registration_options(db, config, user)
    return {"challenge_id": challenge_id, "options": options}


@router.post("/passkey/register/verify", dependencies=[Depends(deps.require_csrf_header)])
def register_verify(
    payload: RegisterVerifyRequest,
    request: Request,
    response: Response,
    session: Session = Depends(deps.require_session),
    user: User = Depends(deps.require_user),
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    if deps.enrollment_window_closed(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="the registration window has closed"
        )
    try:
        passkeys.verify_registration(
            db, config, user, payload.challenge_id, payload.credential, payload.label
        )
    except passkeys.PasskeyError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)
        ) from err

    codes: list[str] = []
    if user.must_enroll_passkey:
        # First passkey: the obligation is fulfilled, and with it the password
        # goes - not ignored, discarded. A permanent password would keep open
        # exactly the path the passkeys are meant to close.
        user.must_enroll_passkey = False
        user.enroll_expires_at = None
        user.password_hash = None
        codes = security.generate_backup_codes()
        for code in codes:
            db.add(BackupCode(user_id=user.id, code_hash=security.hash_backup_code(code)))
        # The session changes privilege here, so it changes identity: the old
        # id - issued for a password - is revoked and a fresh one takes over.
        # Anyone who captured the enrollment cookie holds a dead value now.
        sessions.revoke(db, session)
        fresh = sessions.create(db, config, user, enrollment_only=False, request=request)
        sessions.attach_cookie(response, config, fresh)

    return {
        "backup_codes": codes,
        "credentials": len(user.credentials),
        # A passkey that cannot be synced does not survive losing the device.
        # The interface uses this to insist on a second one.
        "backup_eligible": any(c.backup_eligible for c in user.credentials),
    }


# -------------------------------------------------------------- backup codes


@router.post("/backup-code", dependencies=[Depends(deps.require_csrf_header)])
def backup_code(
    payload: BackupCodeRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
) -> dict:
    user = db.query(User).filter(User.name == payload.name).one_or_none()
    if user is None or not user.is_active or deps.account_locked(user):
        raise _generic_denial()

    match = None
    for candidate in db.query(BackupCode).filter(
        BackupCode.user_id == user.id, BackupCode.used_at.is_(None)
    ):
        if security.verify_backup_code(candidate.code_hash, payload.code):
            match = candidate
            break
    if match is None:
        _record_failure(db, user)
        raise _generic_denial()

    match.used_at = utcnow()
    deps.note_success(user)
    # A backup code means the device is gone. The session it opens may do one
    # thing: register a new passkey.
    user.must_enroll_passkey = True
    user.enroll_expires_at = security.enrollment_deadline(config.auth.enrollment_hours)
    session = sessions.create(db, config, user, enrollment_only=True, request=request)
    sessions.attach_cookie(response, config, session)
    remaining = (
        db.query(BackupCode)
        .filter(BackupCode.user_id == user.id, BackupCode.used_at.is_(None))
        .count()
    )
    return {"user": user.name, "enrollment_required": True, "codes_left": remaining}


# ------------------------------------------------------------------- session


@router.post("/logout", dependencies=[Depends(deps.require_csrf_header)])
def logout(
    response: Response,
    session: Session | None = Depends(deps.current_session),
    db: DbSession = Depends(deps.get_db),
) -> dict:
    if session is not None:
        sessions.revoke(db, session)
    sessions.clear_cookie(response)
    return {"ok": True}
