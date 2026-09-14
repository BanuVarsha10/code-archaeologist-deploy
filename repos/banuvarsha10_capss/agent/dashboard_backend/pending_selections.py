"""dashboard_backend/pending_selections.py

Process-local registry of pending per-device attack-scenario selections
(Part E "choose per device" mode). While a batch run is in that mode, the
streaming worker thread genuinely blocks — via queue.Queue.get(timeout=...)
— after a device's baseline registration completes, waiting for the user to
pick that device's attack scenario. POST /api/attack-test/select-scenario
resolves the wait by putting the chosen scenario onto that same queue.

Keyed by f"{run_id}:{device_index}" so this stays correct even if the
backend process is ever serving more than one concurrent run.
"""

from __future__ import annotations

import queue
import threading
from typing import Dict

_lock = threading.Lock()
_pending: Dict[str, "queue.Queue[str]"] = {}


def register(run_id: str, device_index: int) -> "queue.Queue[str]":
    """Called by the streaming worker right before it blocks on this
    device's selection. Returns the queue the worker should .get() from."""
    key = f"{run_id}:{device_index}"
    q: "queue.Queue[str]" = queue.Queue(maxsize=1)
    with _lock:
        _pending[key] = q
    return q


def resolve(run_id: str, device_index: int, attack_scenario: str) -> bool:
    """Called by the POST endpoint. Returns False if nothing is currently
    waiting for this run_id/device_index (already resolved, the wait timed
    out, or the run hasn't reached this device yet) — the caller should
    surface that as 404, not silently succeed."""
    key = f"{run_id}:{device_index}"
    with _lock:
        q = _pending.get(key)
    if q is None:
        return False
    try:
        q.put_nowait(attack_scenario)
        return True
    except queue.Full:
        return False


def unregister(run_id: str, device_index: int) -> None:
    """Called by the streaming worker once it stops waiting (selection
    received OR timed out) — prevents a late/duplicate POST from resolving
    a queue nobody is reading anymore."""
    key = f"{run_id}:{device_index}"
    with _lock:
        _pending.pop(key, None)
