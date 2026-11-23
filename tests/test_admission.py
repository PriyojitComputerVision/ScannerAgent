"""Server-wide admission queues (pentest_agent/admission.py) and their use in the
WebSocket endpoint and HTTP middleware."""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from pentest_agent import admission, websocket_server
from pentest_agent.admission import AdmissionQueue, QueueFull, QueueTimeout


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------- queue logic
def test_runs_up_to_max_active_then_queues_fifo_with_positions():
    async def scenario():
        q = AdmissionQueue("t", max_active=2, max_queue=5, update_interval=0.05)
        release = [asyncio.Event() for _ in range(4)]
        order, seen = [], {i: [] for i in range(4)}

        async def job(i):
            async def notify(info):
                seen[i].append(info["position"])
            async with q.admit(notify=notify) as ticket:
                order.append((i, ticket.position_at_arrival))
                await release[i].wait()

        tasks = [asyncio.create_task(job(i)) for i in range(4)]
        await asyncio.sleep(0.05)
        assert q.active == 2 and q.waiting == 2
        assert seen[2][0] == 1 and seen[3][0] == 2   # positions in arrival order
        release[0].set()
        await asyncio.sleep(0.1)
        assert [i for i, _ in order] == [0, 1, 2]     # #2 got the freed slot first
        assert seen[3][-1] == 1                       # #3 moved up to position 1
        for e in release:
            e.set()
        await asyncio.gather(*tasks)
        assert dict(order) == {0: 0, 1: 0, 2: 1, 3: 2}
        assert q.active == 0 and q.waiting == 0
    _run(scenario())


def test_full_queue_raises_with_retry_after_and_snapshot():
    async def scenario():
        q = AdmissionQueue("t", max_active=1, max_queue=1)
        hold = asyncio.Event()

        async def holder():
            async with q.admit():
                await hold.wait()

        tasks = [asyncio.create_task(holder()), asyncio.create_task(holder())]
        await asyncio.sleep(0.01)
        with pytest.raises(QueueFull) as info:
            async with q.admit():
                pass
        assert "Too many requests" in str(info.value) and "try again after some time" in str(info.value)
        assert info.value.retry_after == admission.DEFAULT_RETRY_AFTER
        assert info.value.snapshot == {"active": 1, "max_active": 1, "waiting": 1, "max_queue": 1}
        hold.set()
        await asyncio.gather(*tasks)
    _run(scenario())


def test_cancelled_or_failing_waiter_leaves_queue_and_keeps_slots_consistent():
    async def scenario():
        q = AdmissionQueue("t", max_active=1, max_queue=5, update_interval=0.01)
        hold = asyncio.Event()

        async def holder():
            async with q.admit():
                await hold.wait()

        async def gone(info):
            raise ConnectionError("client disconnected")

        h = asyncio.create_task(holder())
        await asyncio.sleep(0.01)
        waiter = asyncio.create_task(q.admit().__aenter__())
        await asyncio.sleep(0.01)
        assert q.waiting == 1
        waiter.cancel()
        await asyncio.sleep(0.01)
        assert q.waiting == 0
        with pytest.raises(ConnectionError):
            async with q.admit(notify=gone):
                pass
        assert q.waiting == 0
        hold.set()
        await h
        assert q.active == 0
        async with q.admit() as t:  # a free slot is usable right away
            assert t.position_at_arrival == 0
    _run(scenario())


def test_wait_timeout_and_estimate_from_recent_durations():
    async def scenario():
        clock = [0.0]
        q = AdmissionQueue("t", max_active=2, max_queue=5, clock=lambda: clock[0])
        async with q.admit():
            clock[0] += 30
        assert q.estimate_wait(1) == 30 and q.estimate_wait(3) == 60
        q2 = AdmissionQueue("t2", max_active=1, max_queue=5)
        hold = asyncio.Event()

        async def holder():
            async with q2.admit():
                await hold.wait()

        h = asyncio.create_task(holder())
        await asyncio.sleep(0.01)
        with pytest.raises(QueueTimeout):
            async with q2.admit(timeout=0.2):
                pass
        assert q2.waiting == 0
        hold.set()
        await h
    _run(scenario())


def test_zero_max_active_disables_the_queue():
    async def scenario():
        q = AdmissionQueue("t", max_active=0, max_queue=0)
        async with q.admit(), q.admit() as t:
            assert t.position_at_arrival == 0
    _run(scenario())


# ---------------------------------------------------------------- server wiring
def test_ws_full_queue_returns_429_and_closes_4429(monkeypatch):
    q = websocket_server.ws_queue
    monkeypatch.setattr(q, "max_active", 1)
    monkeypatch.setattr(q, "max_queue", 0)
    q._active = 1  # one scan already running
    c = TestClient(websocket_server.app)
    with c.websocket_connect("/ws?session_id=x") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error" and msg["code"] == 429 and msg["retry_after"] >= 1
        assert "Too many requests" in msg["message"] and msg["queue"]["active"] == 1
        with pytest.raises(Exception) as info:
            ws.receive_json()
        assert getattr(info.value, "code", None) == 4429


def test_ws_queued_client_gets_position_updates_and_leaves_on_disconnect(monkeypatch):
    q = websocket_server.ws_queue
    monkeypatch.setattr(q, "max_active", 1)
    monkeypatch.setattr(q, "max_queue", 5)
    monkeypatch.setattr(q, "update_interval", 0.05)
    q._active = 1
    c = TestClient(websocket_server.app)
    with c.websocket_connect("/ws?session_id=q1") as ws:
        first = ws.receive_json()
        assert first["type"] == "queued" and first["position"] == 1
        assert "starts after 1 more scan(s) finish" in first["message"]
        again = ws.receive_json()  # periodic update while waiting
        assert again["type"] == "queued" and again["position"] == 1
    # The next update fails to send, so the waiter leaves the queue.
    for _ in range(50):
        if q.waiting == 0:
            break
        import time
        time.sleep(0.05)
    assert q.waiting == 0


def test_http_full_queue_returns_429_and_healthz_stays_open(monkeypatch):
    q = websocket_server.http_queue
    monkeypatch.setattr(q, "max_active", 1)
    monkeypatch.setattr(q, "max_queue", 0)
    c = TestClient(websocket_server.app)
    ok = c.get("/reports/")
    assert ok.status_code == 200 and ok.headers["x-queue-position"] == "0"
    q._active = 1
    r = c.get("/reports/")
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert "Too many requests" in r.json()["detail"]
    health = c.get("/healthz")
    assert health.status_code == 200
    assert health.json()["queues"]["http"]["active"] == 1
