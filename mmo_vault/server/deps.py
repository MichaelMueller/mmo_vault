"""FastAPI dependencies: who is asking, and may they.

Simpler than it used to be. With identity coming from the provider there is no
enrollment state to distinguish, no password path to fence off and nothing to
rate-limit: a session either exists or it does not, and an account is either
active or not.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DbSession

from . import config as settings
from . import db as database
from . import sessions
from .config import Config
from .models import Session, User

CSRF_HEADER = "x-vault-request"


def get_db() -> DbSession:
    yield from database.get_session()


def get_config(db: DbSession = Depends(get_db)) -> Config:
    """Read per request. A dozen rows, and it is what lets a change in the
    administration take effect without a restart."""
    return settings.load(db)


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
    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="account disabled")
    return user


# Kept under its old name so the vault endpoints did not have to change: there
# is no longer a "partial" user, every signed-in account is a full one.
require_full_user = require_user


def require_admin(user: User = Depends(require_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="administrators only")
    return user
