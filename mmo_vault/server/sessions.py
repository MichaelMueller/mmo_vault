"""Server-side sessions.

The cookie carries nothing but an unguessable identifier; everything else is
looked up in the database. That is what makes a session revocable - the point
of not using a self-contained token here.

No signature on the cookie: a 256-bit random value that only means something
after a database lookup gains nothing from being signed.
"""

from __future__ import annotations

import datetime as dt

from fastapi import Request, Response
from sqlalchemy.orm import Session as DbSession

from .config import Config
from .models import Session, User, utcnow
from .security import new_session_id

COOKIE_NAME = "mmo_vault_session"


def create(
    db: DbSession,
    config: Config,
    user: User,
    *,
    enrollment_only: bool,
    request: Request | None = None,
) -> Session:
    session = Session(
        id=new_session_id(),
        user_id=user.id,
        expires_at=utcnow() + dt.timedelta(hours=config.auth.session_hours),
        enrollment_only=enrollment_only,
        ip=(request.client.host if request and request.client else ""),
        user_agent=(request.headers.get("user-agent", "")[:255] if request else ""),
    )
    db.add(session)
    return session


def attach_cookie(response: Response, config: Config, session: Session) -> None:
    response.set_cookie(
        COOKIE_NAME,
        session.id,
        httponly=True,
        # Only over HTTPS - except when the service deliberately runs on plain
        # localhost, where a Secure cookie would simply never arrive.
        secure=config.auth.origin.startswith("https://"),
        samesite="lax",
        max_age=config.auth.session_hours * 3600,
        path="/",
    )


def clear_cookie(response: Response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/")


def lookup(db: DbSession, config: Config, session_id: str | None) -> Session | None:
    """Returns a live session, or None. Expired ones are removed on sight."""
    if not session_id:
        return None
    session = db.get(Session, session_id)
    if session is None:
        return None
    now = utcnow()
    idle_limit = dt.timedelta(minutes=config.auth.session_idle_minutes)
    if session.expires_at <= now or (now - session.last_seen_at) > idle_limit:
        db.delete(session)
        return None
    session.last_seen_at = now
    return session


def revoke(db: DbSession, session: Session) -> None:
    db.delete(session)


def revoke_all_for(db: DbSession, user_id: int) -> int:
    """Used when a device is lost or an account is disabled."""
    count = db.query(Session).filter(Session.user_id == user_id).delete()
    return int(count or 0)


# There is deliberately no promote(): a session that gains privilege gets a
# NEW id (revoke + create in the registration endpoint). Upgrading the old one
# in place would keep a cookie alive that was issued for a mere password.
