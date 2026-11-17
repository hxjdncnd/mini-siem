"""Pushing "something was ingested" to open dashboards, so they refresh the moment data arrives.

A broker fans each message out to every connected client (server-sent events). It lives in one
process, which is all this project runs; several workers would each need a shared bus such as
Redis pub/sub in front of this. Publishing never blocks ingestion: a client that cannot keep up
loses its oldest pending messages instead of holding anything up.
"""

import asyncio
import threading
from collections.abc import AsyncIterator

_QUEUE_SIZE = 50


class Subscription:
    def __init__(self, broker: "Broker", loop: asyncio.AbstractEventLoop):
        self._broker = broker
        self._loop = loop
        self.queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=_QUEUE_SIZE)

    def _offer(self, message: dict) -> None:  # runs on the subscriber's event loop
        if self.queue.full():
            self.queue.get_nowait()  # drop the oldest; the newest news matters most
        self.queue.put_nowait(message)

    def close(self) -> None:
        self._broker._remove(self)

    async def messages(self, keepalive: float) -> AsyncIterator[dict | None]:
        """Yield messages as they arrive, and None after `keepalive` seconds of quiet."""
        while True:
            try:
                yield await asyncio.wait_for(self.queue.get(), timeout=keepalive)
            except TimeoutError:
                yield None


class Broker:
    def __init__(self) -> None:
        self._subscriptions: set[Subscription] = set()
        self._lock = threading.Lock()

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscriptions)

    def subscribe(self) -> Subscription:
        """Call from inside the event loop that will read the messages."""
        subscription = Subscription(self, asyncio.get_running_loop())
        with self._lock:
            self._subscriptions.add(subscription)
        return subscription

    def publish(self, message: dict) -> None:
        """Safe to call from any thread (ingest runs in a worker thread). Never blocks."""
        with self._lock:
            targets = list(self._subscriptions)
        for subscription in targets:
            try:
                subscription._loop.call_soon_threadsafe(subscription._offer, message)
            except RuntimeError:
                self._remove(subscription)  # that loop has already shut down

    def _remove(self, subscription: Subscription) -> None:
        with self._lock:
            self._subscriptions.discard(subscription)
