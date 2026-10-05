from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Everything configurable, overridable with MINISIEM_* environment variables or a .env file."""

    model_config = SettingsConfigDict(env_prefix="MINISIEM_", env_file=".env", extra="ignore")

    # SQLite by default so the project runs with nothing installed; Docker Compose points this at Postgres.
    database_url: str = "sqlite:///./minisiem.db"
    rules_dir: Path = BACKEND_DIR / "rules"
    # Zone assumed for log formats that carry no UTC offset (classic syslog).
    default_timezone: str = "UTC"
    max_lines_per_request: int = 10_000
    # When set, every /api request must send it in the X-API-Key header.
    api_key: str | None = None
    cors_origins: list[str] = ["http://localhost:5173"]
