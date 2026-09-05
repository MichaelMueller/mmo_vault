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
from .routing import UnitOfWork

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

    # The handful of endpoints declared on the application itself further down
    # go through this router, and they read the database like any other. Without
    # this they would keep committing in the dependency teardown, which happens
    # after the answer has been sent - see routing.UnitOfWork. Routers included
    # below keep their own class, so this does not reach them.
    app.router.route_class = UnitOfWork

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

    @app.middleware("http")
    async def security_headers(request, call_next):
        """The headers that a <meta> tag cannot deliver.

        frame-ancestors is the reason this exists: inside a meta tag the
        browser ignores the directive, so it can only be enforced from here -
        and without it the delivered application could be framed. The rest of
        the policy stays where it is, in the meta tag of the application and of
        the service's own pages; a second full policy here would apply
        cumulatively and could only ever narrow it by accident.
        """
        response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", "frame-ancestors 'none'")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        # Only what the application demonstrably does not use. clipboard-write
        # stays allowed - copying a password is the whole point.
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), usb=(), payment=(), interest-cohort=()",
        )
        return response

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
