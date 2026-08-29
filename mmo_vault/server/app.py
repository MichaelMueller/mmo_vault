"""The FastAPI application.

Phase 1 only carries what `start` needs to prove itself: a health endpoint and
the wiring of configuration and database. Authentication, vaults and the
injection of the single-file application follow in the later phases.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from . import db
from .config import Config

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

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": APP_VERSION}

    return app
