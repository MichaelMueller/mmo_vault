"""Signing out.

Signing in lives in oidc.py - there is no other way in. What is left here is
the one operation that does not involve a provider.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session as DbSession

from .. import deps, sessions
from ..models import Session
from ..routing import UnitOfWork

router = APIRouter(prefix="/auth", tags=["auth"], route_class=UnitOfWork)


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
