"""dashboard_backend/run_control.py

Process-local registry of in-flight batch-run cancellation flags.
POST /api/attack-test/{run_id}/stop sets a run's flag; the streaming
worker (main.py's _stream_devices) checks it at the safe point BETWEEN
devices (never starts a device that hasn't been started yet), and
run_live_device() checks it at the safe points BETWEEN real steps within
the device currently in flight (after baseline, after attack, after each
stability replay — never mid real nr-ue launch).

No new process-cleanup logic is needed for this: launch_nr_ue_once()
already terminates its nr-ue process in its own `finally` block after
EVERY launch, success or failure (see live_mode.py's _terminate_nr_ue) —
so as long as cancellation is only ever checked BETWEEN launches, not
mid-launch, there is never an orphaned real subprocess to clean up
specially.
"""

from __future__ import annotations

import threading
from typing import Dict

_lock = threading.Lock()
_cancelled: Dict[str, threading.Event] = {}


def register(run_id: str) -> None:
    """Called once, right before a run's stream starts."""
    with _lock:
        _cancelled[run_id] = threading.Event()


def request_stop(run_id: str) -> bool:
    """Called by the stop endpoint. Returns False if run_id is unknown
    (already finished, or never existed) — caller should surface that as
    a 404 rather than silently succeeding."""
    with _lock:
        ev = _cancelled.get(run_id)
    if ev is None:
        return False
    ev.set()
    return True


def is_cancelled(run_id: str) -> bool:
    with _lock:
        ev = _cancelled.get(run_id)
    return ev.is_set() if ev else False


def unregister(run_id: str) -> None:
    """Called once the run's stream has fully finished (normally or via
    cancellation) — prevents indefinite growth of this registry and a
    late/stale stop request from ever matching a different, later run
    that happens to reuse... (run_ids are uuid4-derived, so reuse is not a
    real risk, but there is no reason to keep a finished run's entry)."""
    with _lock:
        _cancelled.pop(run_id, None)
