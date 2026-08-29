"""The pages of the service itself: sign-in, enrolment, administration.

Rendered on the server with Jinja. No build step, no framework, and a Content
Security Policy as narrow as the one in the vault application.

The vault application itself is *not* served here - that follows in phase 6,
where it is injected while being delivered.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from .. import deps, sessions
from ..config import Config
from ..models import Provider, Session, User

router = APIRouter(tags=["pages"])
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
):
    providers = list(
        db.query(Provider).filter(Provider.enabled.is_(True)).order_by(Provider.name)
    )
    return templates.TemplateResponse(
        request, "login.html", {"providers": providers, "origin": config.auth.origin}
    )


@router.get("/enroll", response_class=HTMLResponse)
def enroll_page(
    request: Request,
    session: Session | None = Depends(deps.current_session),
):
    """Only reachable with a session - and pointless without an obligation."""
    if session is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "enroll.html", {})


@router.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    user: User = Depends(deps.require_admin),
    config: Config = Depends(deps.get_config),
):
    return templates.TemplateResponse(
        request, "admin.html", {"user": user, "origin": config.auth.origin}
    )


@router.get("/")
def index(
    request: Request,
    session: Session | None = Depends(deps.current_session),
    db: DbSession = Depends(deps.get_db),
):
    """Sends everyone where they belong.

    An enrolment session has exactly one destination, and it is not the
    application.
    """
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if session.enrollment_only:
        return RedirectResponse("/enroll", status_code=303)
    user = db.get(User, session.user_id)
    if user is not None and user.must_enroll_passkey:
        return RedirectResponse("/enroll", status_code=303)
    # Until phase 6 delivers the vault application, administrators land in the
    # administration and everyone else gets a plain notice.
    if user is not None and user.is_admin:
        return RedirectResponse("/admin", status_code=303)
    return HTMLResponse(
        "<p style='font-family:system-ui;padding:24px'>"
        "Angemeldet. Die Vault-Anwendung folgt in Phase 6.</p>"
    )
