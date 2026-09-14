"""Tests for dashboard_backend/run_control.py — the stop-attack task's
process-local cancellation-flag registry."""

from dashboard_backend import run_control


def test_request_stop_returns_false_for_unknown_run_id():
    assert run_control.request_stop("does-not-exist") is False


def test_is_cancelled_false_before_stop_requested():
    run_control.register("run-a")
    try:
        assert run_control.is_cancelled("run-a") is False
    finally:
        run_control.unregister("run-a")


def test_request_stop_then_is_cancelled_true():
    run_control.register("run-b")
    try:
        assert run_control.request_stop("run-b") is True
        assert run_control.is_cancelled("run-b") is True
    finally:
        run_control.unregister("run-b")


def test_is_cancelled_false_for_unregistered_run_id():
    assert run_control.is_cancelled("never-registered") is False


def test_unregister_then_stop_request_returns_false():
    run_control.register("run-c")
    run_control.unregister("run-c")
    assert run_control.request_stop("run-c") is False


def test_two_runs_are_independent():
    run_control.register("run-d")
    run_control.register("run-e")
    try:
        run_control.request_stop("run-d")
        assert run_control.is_cancelled("run-d") is True
        assert run_control.is_cancelled("run-e") is False
    finally:
        run_control.unregister("run-d")
        run_control.unregister("run-e")
