"""The live feed: the broker on its own, then the real endpoint over a real socket.

The endpoint tests start an actual uvicorn server, because server-sent events are a long-lived HTTP
response and an in-process test client cannot read one that never ends.
"""

import asyncio
import contextlib
import json
import threading
import time
import urllib.error
import urllib.request

import pytest
import uvicorn

from app.config import Settings
from app.live import Broker
from app.main import create_app
from tests.test_respond import BRUTE_FORCE_SUCCESS


class TestBroker:
    def test_a_message_published_from_a_worker_thread_reaches_the_subscriber(self):
        async def scenario():
            broker = Broker()
            subscription = broker.subscribe()
            threading.Thread(target=broker.publish, args=({"type": "ingest", "stored": 3},)).start()
            return await asyncio.wait_for(subscription.queue.get(), timeout=2)

        assert asyncio.run(scenario()) == {"type": "ingest", "stored": 3}

    def test_every_subscriber_gets_every_message(self):
        async def scenario():
            broker = Broker()
            first, second = broker.subscribe(), broker.subscribe()
            broker.publish({"type": "ingest"})
            return [await asyncio.wait_for(s.queue.get(), timeout=2) for s in (first, second)]

        assert asyncio.run(scenario()) == [{"type": "ingest"}] * 2

    def test_a_client_that_falls_behind_loses_the_oldest_messages_not_ingestion(self):
        async def scenario():
            broker = Broker()
            subscription = broker.subscribe()
            publisher = threading.Thread(target=lambda: [broker.publish({"n": n}) for n in range(80)])
            publisher.start()
            publisher.join()
            await asyncio.sleep(0.1)  # let the loop deliver them
            return [subscription.queue.get_nowait()["n"] for _ in range(subscription.queue.qsize())]

        kept = asyncio.run(scenario())
        assert len(kept) == 50
        assert kept == list(range(30, 80))

    def test_quiet_periods_yield_a_keepalive_marker(self):
        async def scenario():
            subscription = Broker().subscribe()
            stream = subscription.messages(keepalive=0.05)
            return await anext(stream)

        assert asyncio.run(scenario()) is None

    def test_closing_unsubscribes(self):
        async def scenario():
            broker = Broker()
            subscription = broker.subscribe()
            assert broker.subscriber_count == 1
            subscription.close()
            return broker.subscriber_count

        assert asyncio.run(scenario()) == 0

    def test_publishing_to_a_dead_event_loop_is_harmless(self):
        broker = Broker()

        async def subscribe_then_the_loop_ends():
            broker.subscribe()

        asyncio.run(subscribe_then_the_loop_ends())
        broker.publish({"type": "ingest"})
        assert broker.subscriber_count == 0


@contextlib.contextmanager
def serve(settings: Settings):
    app = create_app(settings)
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", timeout_graceful_shutdown=2)
    )
    server.install_signal_handlers = lambda: None  # not the main thread
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        assert time.monotonic() < deadline, "the test server did not start"
        time.sleep(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}", app
    finally:
        server.should_exit = True
        thread.join(timeout=10)


def open_stream(base: str, headers: dict | None = None):
    return urllib.request.urlopen(urllib.request.Request(f"{base}/api/v1/stream", headers=headers or {}), timeout=5)


def read_frame(response) -> list[str]:
    """The lines of the next server-sent event, without the blank line that ends it."""
    lines: list[str] = []
    while True:
        raw = response.readline()
        assert raw != b"", "the stream closed"
        line = raw.decode().rstrip("\n")
        if line:
            lines.append(line)
        elif lines:
            return lines


def ingest(base: str, text: str, log_format: str = "sshd", headers: dict | None = None) -> dict:
    request = urllib.request.Request(
        f"{base}/api/v1/ingest/{log_format}",
        data=text.encode(),
        headers={"Content-Type": "text/plain", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def event_data(frame: list[str]) -> dict:
    assert frame[0] == "event: ingest", frame
    return json.loads(frame[1].removeprefix("data: "))


@pytest.fixture
def settings(database_url):
    return Settings(database_url=database_url, api_key=None, live_keepalive_seconds=0.2, _env_file=None)


class TestStream:
    def test_a_connected_client_hears_about_new_data_and_the_alerts_it_raised(self, settings):
        with serve(settings) as (base, _app), open_stream(base) as stream:
            assert read_frame(stream) == ["retry: 3000", ": connected"]
            ingest(base, BRUTE_FORCE_SUCCESS)
            message = event_data(next(f for f in iter(lambda: read_frame(stream), None) if f != [": keepalive"]))
        assert message["stored"] == 7
        assert message["alerts_created"] >= 1
        critical = [a for a in message["new_alerts"] if a["severity"] == "critical"]
        assert [a["rule_name"] for a in critical] == ["Successful login after brute force"]
        assert set(critical[0]) == {"id", "rule_name", "severity", "summary", "score"}  # no more than a toast needs

    def test_two_dashboards_both_hear_it(self, settings):
        with serve(settings) as (base, _app), open_stream(base) as first, open_stream(base) as second:
            read_frame(first), read_frame(second)
            ingest(base, BRUTE_FORCE_SUCCESS)
            for stream in (first, second):
                frame = next(f for f in iter(lambda s=stream: read_frame(s), None) if f != [": keepalive"])
                assert event_data(frame)["stored"] == 7

    def test_a_quiet_stream_sends_keepalives_so_proxies_do_not_hang_up(self, settings):
        with serve(settings) as (base, _app), open_stream(base) as stream:
            read_frame(stream)
            assert read_frame(stream) == [": keepalive"]

    def test_a_batch_that_stored_nothing_is_not_announced(self, settings):
        with serve(settings) as (base, _app), open_stream(base) as stream:
            read_frame(stream)
            assert ingest(base, "complete garbage")["stored"] == 0
            ingest(base, BRUTE_FORCE_SUCCESS)
            frame = next(f for f in iter(lambda: read_frame(stream), None) if f != [": keepalive"])
            assert event_data(frame)["stored"] == 7  # the first announcement is the real batch

    def test_a_client_that_goes_away_is_forgotten(self, settings):
        with serve(settings) as (base, app):
            stream = open_stream(base)
            read_frame(stream)
            assert app.state.broker.subscriber_count == 1
            stream.close()
            deadline = time.monotonic() + 5
            while app.state.broker.subscriber_count and time.monotonic() < deadline:
                time.sleep(0.05)
            assert app.state.broker.subscriber_count == 0

    def test_it_needs_the_api_key_when_one_is_set(self, database_url):
        keyed = Settings(database_url=database_url, api_key="s3cret", live_keepalive_seconds=0.2, _env_file=None)
        with serve(keyed) as (base, _app):
            with pytest.raises(urllib.error.HTTPError) as refused:
                open_stream(base)
            assert refused.value.code == 401
            with open_stream(base, {"X-API-Key": "s3cret"}) as stream:
                assert read_frame(stream) == ["retry: 3000", ": connected"]
