import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.api import alerts, events, ingest, overview
from app.api.deps import require_api_key
from app.config import Settings
from app.db import create_schema, make_engine, make_session_factory
from app.detection.engine import DetectionEngine
from app.detection.rules import load_rules
from app.ingest import IngestService

log = logging.getLogger("minisiem")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory: tests build an app per test with their own database."""
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        engine = make_engine(settings.database_url)
        create_schema(engine)
        rules = load_rules(settings.rules_dir)  # raises on a bad rule: refuse to start half-blind
        log.info("Loaded %d detection rules from %s", len(rules), settings.rules_dir)
        app.state.settings = settings
        app.state.engine = engine
        app.state.session_factory = make_session_factory(engine)
        app.state.rules = rules
        app.state.ingest = IngestService(settings, DetectionEngine(rules))
        yield
        engine.dispose()

    app = FastAPI(
        title="Mini SIEM",
        version="0.1.0",
        description="Ingests security logs, normalizes them, runs detection rules and raises alerts.",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH"],
        allow_headers=["Content-Type", "X-API-Key"],
    )

    api = APIRouter(prefix="/api/v1", dependencies=[Depends(require_api_key)])
    for module in (ingest, events, alerts, overview):
        api.include_router(module.router)
    app.include_router(api)

    @app.get("/health", tags=["health"])
    def health():
        with app.state.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ok", "rules": len(app.state.rules)}

    return app


app = create_app()
