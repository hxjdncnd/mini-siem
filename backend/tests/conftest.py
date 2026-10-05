from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.parsers import ParseContext

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLES = REPO_ROOT / "samples"


@pytest.fixture
def ctx() -> ParseContext:
    """ "Now" for parser tests: 6 Oct 2026, 00:00 UTC."""
    return ParseContext(now=datetime(2026, 10, 6, tzinfo=UTC), default_tz=UTC)


@pytest.fixture
def database_url(tmp_path, request) -> str:
    """A fresh SQLite file per test, or the database in MINISIEM_TEST_DATABASE_URL (wiped first)
    to run the same suite against PostgreSQL."""
    import os

    url = os.environ.get("MINISIEM_TEST_DATABASE_URL")
    if not url:
        return f"sqlite:///{tmp_path / 'test.db'}"
    from sqlalchemy import create_engine

    from app.models import Base

    engine = create_engine(url)
    Base.metadata.drop_all(engine)
    engine.dispose()
    return url


@pytest.fixture
def settings(database_url) -> Settings:
    return Settings(database_url=database_url, api_key=None, _env_file=None)


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings)) as c:
        yield c


def post_log(client, log_format: str, text: str, **params):
    response = client.post(
        f"/api/v1/ingest/{log_format}", content=text, params=params, headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 200, response.text
    return response.json()


def sample(name: str) -> str:
    return (SAMPLES / name).read_text()


def alerts_by_rule(client) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for alert in client.get("/api/v1/alerts", params={"size": 500}).json()["items"]:
        grouped.setdefault(alert["rule_id"], []).append(alert)
    return grouped
