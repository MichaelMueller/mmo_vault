"""The FastAPI application.

Phase 1 only carries what `start` needs to prove itself: a health endpoint and
the wiring of configuration and database. Authentication, vaults and the
injection of the single-file application follow in the later phases.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from sqlalchemy.orm import Session as DbSession
from starlette.middleware.sessions import SessionMiddleware

from . import db, deps
from .config import Config
from .models import Provider, User
from .routers import admin_api, auth, oidc, pages, vault_api

APP_VERSION = "2.0.0-dev"


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config.load()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db.init(config)
        yield

    app = FastAPI(
        title="MMO Vault",
        version=APP_VERSION,
        lifespan=lifespan,
        # No interactive docs by default: this is a service for a handful of
        # people, not a public API, and the schema would only be one more thing
        # reachable without authentication.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.config = config

    # Authlib keeps the OAuth state between redirect and callback in a signed
    # cookie. Nothing else uses it - the service's own sessions live in the
    # database.
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.secret_key,
        session_cookie="mmo_vault_oauth",
        same_site="lax",
        https_only=config.auth.origin.startswith("https://"),
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
    def public_config(db: DbSession = Depends(deps.get_db)) -> dict:
        """What the sign-in page needs before anyone is signed in.

        Lists the enabled providers, because the page has to offer them - but
        says nothing about accounts. Which provider a particular account may
        use is decided after the provider has spoken, not before.
        """
        providers = db.query(Provider).filter(Provider.enabled.is_(True)).order_by(Provider.name)
        return {
            "server": True,
            "rp_id": config.auth.rp_id,
            "providers": [{"name": p.name} for p in providers],
        }

    @app.get("/api/me")
    def me(user: User = Depends(deps.require_full_user)) -> dict:
        return {
            "user": user.name,
            "email": user.email,
            "is_admin": user.is_admin,
            "groups": [group.name for group in user.groups],
            "credentials": [
                {"label": c.label, "backup_eligible": c.backup_eligible}
                for c in user.credentials
            ],
        }

    return app
