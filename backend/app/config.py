from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.enums import Severity

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

    # Notifications: POST a JSON message to this URL when an alert at or above the severity is first raised.
    # The body has "text" and "content" fields, so Slack and Discord incoming webhooks accept it as is.
    webhook_url: str | None = None
    webhook_min_severity: Severity = Severity.CRITICAL
    # When set, each request carries X-MiniSIEM-Signature: sha256=<HMAC of the body>, so a receiver can verify it.
    webhook_secret: str | None = None
    webhook_timeout_seconds: float = 5.0

    @field_validator("webhook_url")
    @classmethod
    def _webhook_is_http(cls, value: str | None) -> str | None:
        if value in (None, ""):
            return None
        if not value.startswith(("http://", "https://")):
            raise ValueError("webhook_url must start with http:// or https://")
        return value
