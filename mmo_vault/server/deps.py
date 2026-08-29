"""FastAPI dependencies: who is asking, and may they.

The distinction that matters here is between a full session and an enrollment
session. The latter comes from a password and may do exactly one thing:
register a passkey. Everything else has to be closed to it, otherwise the
window between setup and the first sign-in would be a full administrator
account behind a single factor.
"""

from __future__ import annotations

import datetime as dt
import ipaddress

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DbSession

from . import db as database
from . import sessions
from .config import Config
from .models import Session, User, utcnow

# Chosen to be annoying for a script and unnoticeable for a person.
MAX_FAILED_ATTEMPTS = 5
LOCKOUT = dt.timedelta(minutes=15)

CSRF_HEADER = "x-vault-request"


def get_config(request: Request) -> Config:
    return request.app.state.config


def get_db() -> DbSession:
    yield from database.get_session()


def require_csrf_header(request: Request) -> None:
    """Second line after SameSite=Lax.

    A cross-site form post cannot set a custom header, and a cross-site fetch
    would need CORS permission the service never grants.
    """
    if request.headers.get(CSRF_HEADER) != "1":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="missing X-Vault-Request header",
        )


# ------------------------------------------------------------------- identity


def current_session(
    request: Request,
    db: DbSession = Depends(get_db),
    config: Config = Depends(get_config),
) -> Session | None:
    return sessions.lookup(db, config, request.cookies.get(sessions.COOKIE_NAME))


def require_session(session: Session | None = Depends(current_session)) -> Session:
    if session is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not signed in")
    return session


def require_user(
    session: Session = Depends(require_session),
    db: DbSession = Depends(get_db),
) -> User:
    """A signed-in account, whatever its session may do.

    Only for endpoints that an enrollment session is allowed to reach as well -
    which is the passkey registration and nothing else.
    """
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")
    return user


def require_full_user(
    session: Session = Depends(require_session),
    user: User = Depends(require_user),
) -> User:
    """The regular case: a session that may do more than register a passkey."""
    if session.enrollment_only or user.must_enroll_passkey:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="a passkey has to be registered first",
        )
    return user


def require_admin(user: User = Depends(require_full_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="administrators only")
    return user


def fresh_strong_auth(session: Session, config: Config) -> bool:
    """Whether this session may vouch for its owner right now.

    Strong means passkey or OIDC - never a password. Fresh means the sign-in
    just happened: a session lives for hours, but "this is really me, add a
    new device to my account" is a claim that goes stale in minutes. A stolen
    cookie fails on freshness, a stolen password fails on strength.
    """
    age = utcnow() - session.created_at
    return bool(session.strong_auth) and age <= dt.timedelta(
        minutes=config.auth.reauth_minutes
    )


# ------------------------------------------------------------ local requests


def is_local_request(request: Request) -> bool:
    """Whether this request really came from this machine.

    Three conditions, and all of them are needed. Behind a reverse proxy on the
    same host every request arrives from 127.0.0.1, so the peer address alone
    would open the password path to the entire internet. The presence of a
    forwarding header is proof that something sits in between - and a header
    can be set by anyone, so it may only ever count against permission, never
    for it.
    """
    if request.headers.get("x-forwarded-for") or request.headers.get("forwarded"):
        return False
    client = request.client
    if client is None or not client.host:
        return False
    try:
        return ipaddress.ip_address(client.host).is_loopback
    except ValueError:
        return False


def password_login_allowed(request: Request, config: Config, user: User) -> bool:
    """Password sign-in is the exception, not a way in.

    It exists while an account still has to register a passkey, and - if
    switched on deliberately - over loopback.
    """
    if user.must_enroll_passkey and not enrollment_window_closed(user):
        return True
    return config.auth.allow_local_password_login and is_local_request(request)


def enrollment_window_closed(user: User) -> bool:
    return user.enroll_expires_at is not None and user.enroll_expires_at <= utcnow()


# ------------------------------------------------------------- rate limiting


def account_locked(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > utcnow()


def note_failure(user: User) -> None:
    user.failed_attempts = (user.failed_attempts or 0) + 1
    if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = utcnow() + LOCKOUT
        user.failed_attempts = 0


def note_success(user: User) -> None:
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = utcnow()
