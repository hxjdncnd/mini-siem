"""Outbound notifications: tell a chat channel (or any HTTP endpoint) when a serious alert appears.

Delivery happens on a small thread pool *after* the ingest transaction has committed, so a slow or
dead webhook can never delay or fail ingestion. Only the first raise of an alert notifies; later
growth of the same alert stays quiet, otherwise a sustained attack would page someone every batch.
"""

import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlparse

from app.config import Settings
from app.enums import Severity
from app.schemas import AlertOut

log = logging.getLogger("minisiem.notify")
_RANK = {severity: rank for rank, severity in enumerate(Severity)}


@dataclass(frozen=True)
class Delivery:
    ok: bool
    status: int | None = None
    error: str | None = None


def describe(alert: AlertOut) -> str:
    return f"[{alert.severity.value.upper()}] {alert.rule_name}: {alert.summary} (risk {alert.score})"


class Notifier:
    def __init__(self, settings: Settings):
        self.url = settings.webhook_url
        self.min_severity = settings.webhook_min_severity
        self.secret = settings.webhook_secret
        self.timeout = settings.webhook_timeout_seconds
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="webhook") if self.url else None

    @property
    def enabled(self) -> bool:
        return self.url is not None

    @property
    def destination(self) -> str | None:
        """Host only. Webhook URLs usually carry a secret token in the path, which must not leak into the UI."""
        return urlparse(self.url).hostname if self.url else None

    def wants(self, severity: Severity) -> bool:
        return _RANK[severity] >= _RANK[self.min_severity]

    def alerts_created(self, alerts: list[AlertOut]) -> None:
        """Queue a message per new alert that meets the severity bar. Returns immediately."""
        if self._pool is None:
            return
        for alert in alerts:
            if self.wants(alert.severity):
                text = describe(alert)
                payload = {
                    "event": "alert.created",
                    "text": text,
                    "content": text,
                    "alert": alert.model_dump(mode="json"),
                }
                self._pool.submit(self._deliver_quietly, payload)

    def send(self, payload: dict) -> Delivery:
        """Deliver one payload now and say what happened. Never raises."""
        if self.url is None:
            return Delivery(False, error="No webhook configured")
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "mini-siem"}
        if self.secret:
            headers["X-MiniSIEM-Signature"] = (
                "sha256=" + hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
            )
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310 (scheme checked in Settings)
                return Delivery(200 <= response.status < 300, status=response.status)
        except urllib.error.HTTPError as e:
            return Delivery(False, status=e.code, error=f"The receiver answered HTTP {e.code}")
        except (urllib.error.URLError, OSError, ValueError) as e:
            return Delivery(False, error=str(getattr(e, "reason", e)))

    def _deliver_quietly(self, payload: dict) -> None:
        result = self.send(payload)
        if not result.ok:
            log.warning("Webhook delivery failed: %s", result.error)

    def shutdown(self) -> None:
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)
