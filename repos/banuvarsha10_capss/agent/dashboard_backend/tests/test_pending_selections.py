"""Tests for dashboard_backend/pending_selections.py — the blocking-queue
registry behind Part E's 'choose per device' attack-scenario picker."""

import queue
import threading
import time

from dashboard_backend import pending_selections


def test_resolve_delivers_the_value_to_a_waiting_get():
    q = pending_selections.register("run1", 0)
    assert pending_selections.resolve("run1", 0, "flooding") is True
    assert q.get(timeout=1) == "flooding"
    pending_selections.unregister("run1", 0)


def test_resolve_returns_false_when_nothing_is_registered():
    assert pending_selections.resolve("no-such-run", 0, "flooding") is False


def test_unregister_makes_a_later_resolve_return_false():
    pending_selections.register("run2", 0)
    pending_selections.unregister("run2", 0)
    assert pending_selections.resolve("run2", 0, "flooding") is False


def test_a_blocked_waiter_unblocks_once_resolved_from_another_thread():
    q = pending_selections.register("run3", 0)
    result = {}

    def waiter():
        result["value"] = q.get(timeout=5)

    t = threading.Thread(target=waiter)
    t.start()
    time.sleep(0.05)  # give the waiter a moment to actually block on .get()
    assert pending_selections.resolve("run3", 0, "replay") is True
    t.join(timeout=2)
    assert result["value"] == "replay"
    pending_selections.unregister("run3", 0)


def test_different_device_indices_do_not_cross_deliver():
    q0 = pending_selections.register("run4", 0)
    q1 = pending_selections.register("run4", 1)
    pending_selections.resolve("run4", 1, "mixed")
    assert q1.get(timeout=1) == "mixed"
    assert q0.empty()
    pending_selections.unregister("run4", 0)
    pending_selections.unregister("run4", 1)
