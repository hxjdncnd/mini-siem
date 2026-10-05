import hmac
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Query, Request
from sqlalchemy.orm import Session


def get_session(request: Request) -> Iterator[Session]:
    with request.app.state.session_factory() as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def require_api_key(request: Request, x_api_key: Annotated[str | None, Header()] = None) -> None:
    """No-op unless MINISIEM_API_KEY is configured. Constant-time comparison avoids leaking the key by timing."""
    expected = request.app.state.settings.api_key
    if not expected:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")


class Paging:
    def __init__(
        self,
        page: Annotated[int, Query(ge=0)] = 0,
        size: Annotated[int, Query(ge=1, le=500)] = 50,
    ):
        self.page, self.size = page, size

    @property
    def offset(self) -> int:
        return self.page * self.size


PagingDep = Annotated[Paging, Depends()]


def as_utc(value: datetime | None) -> datetime | None:
    """Query timestamps without an offset are read as UTC."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
