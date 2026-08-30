"""The FastAPI application."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session as DbSession
from starlette.middleware.sessions import SessionMiddleware

from . import config as settings
from . import db, deps
from .config import Config, NotConfigured
from .models import Provider, User
from .routers import admin_api, auth, oidc, pages, vault_api

APP_VERSION = "2.1.0"


def readiness_problems(db_session: DbSession) -> list[str]:
    """What is missing before the service can let anyone in.

    Checked at start-up, so the answer is a sentence on the console rather than
    a sign-in page without a single button on it.
    """
    config = settings.load(db_session)
    problems = []
    if not config.origin:
        problems.append("origin")
    if not db_session.query(Provider).filter(Provider.enabled.is_(True)).count():
        problems.append("an enabled provider")
    from .models import Allowlist  # local import keeps the module graph simple

    if not db_session.query(Allowlist).filter(Allowlist.is_admin.is_(True)).count():
        problems.append("an administrator on the allowlist")
    return problems


def create_app(database_url: str | None = None) -> FastAPI:
    engine = db.init(database_url)

    # The state-signing key has to exist before the middleware is built, and the
    # middleware is built once. Everything else is read per request.
    with db.session_scope() as session:
        config = settings.ensure_secret_key(session, settings.load(session))
        problems = readiness_problems(session)
    if problems:
        raise NotConfigured(problems)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        engine.dispose()

    app = FastAPI(
        title="MMO Vault",
        version=APP_VERSION,
        lifespan=lifespan,
        # No interactive docs: this is a service for a handful of people, not a
        # public API, and the schema would be one more thing reachable without
        # a session.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Authlib keeps the OAuth state between redirect and callback in a signed
    # cookie. Nothing else uses it - the service's own sessions live in the
    # database.
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.secret_key,
        session_cookie="mmo_vault_oauth",
        same_site="lax",
        https_only=config.origin.startswith("https://"),
        max_age=600,
    )

    app.include_router(auth.router)
    app.include_router(oidc.router)
    app.include_router(admin_api.router)
    app.include_router(vault_api.router)
    app.include_router(pages.router)

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": APP_VERSION}

    @app.get("/api/config")
    def public_config(db_session: DbSession = Depends(deps.get_db)) -> dict:
        """What the sign-in page needs before anyone is signed in.

        Lists the enabled providers, primary first, because the page has to
        offer them - and says nothing about accounts.
        """
        rows = (
            db_session.query(Provider)
            .filter(Provider.enabled.is_(True))
            .order_by(Provider.is_primary.desc(), Provider.name)
        )
        return {
            "server": True,
            "providers": [{"name": p.name, "kind": p.kind, "primary": p.is_primary} for p in rows],
        }

    @app.get("/api/me")
    def me(user: User = Depends(deps.require_user)) -> dict:
        return {
            "user": user.name,
            "email": user.email,
            "is_admin": user.is_admin,
            "groups": [group.name for group in user.groups],
        }

    return app
