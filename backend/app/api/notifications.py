"""Webhook notifications: see whether they are configured, and send a test message."""

from fastapi import APIRouter, HTTPException, Request

from app.notify import Notifier
from app.schemas import NotificationStatus, NotificationTest

router = APIRouter(prefix="/notifications", tags=["notifications"])


def _notifier(request: Request) -> Notifier:
    return request.app.state.ingest.notifier


@router.get("", response_model=NotificationStatus, summary="Is a webhook configured, and for which severities?")
def status(request: Request):
    notifier = _notifier(request)
    return NotificationStatus(
        enabled=notifier.enabled, min_severity=notifier.min_severity, destination=notifier.destination
    )


@router.post(
    "/test",
    response_model=NotificationTest,
    summary="Send a test message to the configured webhook",
    description="Delivers now and reports the receiver's answer, so a bad URL or secret shows up here "
    "instead of during a real incident.",
)
def send_test(request: Request):
    notifier = _notifier(request)
    if not notifier.enabled:
        raise HTTPException(status_code=409, detail="No webhook configured. Set MINISIEM_WEBHOOK_URL and restart.")
    text = "Mini SIEM test notification: if you can read this, alerts will reach this channel."
    result = notifier.send({"event": "test", "text": text, "content": text})
    return NotificationTest(delivered=result.ok, status=result.status, error=result.error)
