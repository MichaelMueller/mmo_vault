"""The pages of the service itself: sign-in and administration.

Rendered on the server with Jinja. No build step, no framework, and a Content
Security Policy as narrow as the one in the vault application.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from .. import deps, injection
from ..config import Config
from ..models import Provider, Session, User
from ..routing import UnitOfWork

router = APIRouter(tags=["pages"], route_class=UnitOfWork)
templates = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    db: DbSession = Depends(deps.get_db),
    config: Config = Depends(deps.get_config),
):
    providers = list(
        db.query(Provider)
        .filter(Provider.enabled.is_(True))
        .order_by(Provider.is_primary.desc(), Provider.name)
    )
    # ?denied=1 comes from a refused callback: the page says so, without saying why.
    return templates.TemplateResponse(
        request,
        "login.html",
        {"providers": providers, "origin": config.origin, "denied": "denied" in request.query_params},
    )


@router.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    user: User = Depends(deps.require_admin),
    config: Config = Depends(deps.get_config),
):
    return templates.TemplateResponse(
        request, "admin.html", {"user": user, "origin": config.origin}
    )


@router.get("/")
def index(
    session: Session | None = Depends(deps.current_session),
):
    if session is None:
        return RedirectResponse("/login", status_code=303)
    # The application itself, with the two changes from injection.py. Not
    # cached by the browser: it carries the adapter, and a stale copy would
    # point at a session that no longer exists.
    return HTMLResponse(injection.render().html, headers={"Cache-Control": "no-store"})


@router.get("/api/injection", response_class=PlainTextResponse)
def show_injection() -> str:
    """What gets added to the application, in plain text.

    The point of the whole arrangement is that it stays checkable: two string
    replacements, and this is the second one.
    """
    return injection.render().script
