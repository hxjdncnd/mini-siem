"""Server-sent events: lets the dashboard hear about new data instead of polling for it."""

import json
from collections.abc import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

router = APIRouter(tags=["live"])


@router.get(
    "/stream",
    summary="Live feed of ingestion (server-sent events)",
    description="Holds the connection open and sends an `ingest` event whenever a batch is stored, with the "
    "counts and the alerts it raised. Comment lines (`: keepalive`) arrive while it is quiet. Send the X-API-Key "
    "header as usual; the browser's built-in EventSource cannot, so the dashboard reads this with fetch.",
    response_class=StreamingResponse,
)
async def stream(request: Request):
    return StreamingResponse(
        _frames(request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},  # no-buffering hint for nginx
    )


async def _frames(request: Request) -> AsyncIterator[str]:
    subscription = request.app.state.broker.subscribe()
    keepalive = request.app.state.settings.live_keepalive_seconds
    try:
        yield "retry: 3000\n: connected\n\n"
        async for message in subscription.messages(keepalive):
            if message is None:
                yield ": keepalive\n\n"
            else:
                yield f"event: {message['type']}\ndata: {json.dumps(message)}\n\n"
    finally:
        subscription.close()  # runs when the client goes away and the response is cancelled
