"""dashboard_backend/device_pool.py

Persistent pool of real Live Mode device identities, stored ACROSS sessions
(dashboard_backend/device_pool.json, gitignored — separate from the
dashboard's experience store) so most Attack Testing runs REUSE the same
handful of real devices instead of always generating fresh ones. This is
what gives the Experience Timeline panel genuine multi-session history
instead of single-run snapshots: a "returning" device's real experience
entries (written by assess_adaptation()/CAPSSAgent exactly as before —
this module never touches the experience store) accumulate every time it's
reused.

Fresh devices remain available as an explicit, separate action ("New
devices to add" in the UI) — needed for demonstrating cold-start +
cross-UE RAG, which requires a device with NO prior experience.

Capped at MAX_LIVE_DEVICES (20) entries. When adding a device would exceed
the cap, the entry contributing LEAST to the longitudinal story is evicted
first: fewest total_times_run, ties broken by oldest first_seen (the
"stalest and least-used" entry goes first) — see DevicePool.add_new().

invalid_subscriber devices NEVER enter this pool (see
pipeline_service.py's module docstring for why: that scenario's whole
premise is a never-provisioned identity, which is incompatible with being
a real, reusable subscriber) — callers are responsible for keeping those
ad hoc and never calling add_new()/record_run() for them.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

from dashboard_backend.live_mode import LiveCredentials, MAX_LIVE_DEVICES

POOL_PATH = Path(os.path.dirname(os.path.abspath(__file__))) / "device_pool.json"


@dataclass
class PoolDevice:
    imsi: str
    suci: str
    key_hex: str
    opc_hex: str
    first_seen: str          # ISO timestamp of when this device was first added
    total_times_run: int      # incremented once per session this device is selected for


class DevicePool:
    """Not a singleton — tests construct their own instance against a
    tmp_path file; the app uses one shared instance over POOL_PATH (see the
    module-level `pool` below), guarded by an instance-level lock so
    concurrent requests (there shouldn't be more than one active batch run
    at a time, but the backend is a shared process) never interleave a
    read-modify-write."""

    def __init__(self, path: Path = POOL_PATH) -> None:
        self.path = path
        self._lock = threading.Lock()

    def _load(self) -> List[PoolDevice]:
        if not self.path.exists():
            return []
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        return [PoolDevice(**d) for d in raw]

    def _save(self, devices: List[PoolDevice]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([asdict(d) for d in devices], indent=2), encoding="utf-8")

    def all(self) -> List[PoolDevice]:
        with self._lock:
            return self._load()

    def select_returning(self, count: int) -> List[PoolDevice]:
        """Part 3: devices with the MOST prior history first — highest
        total_times_run, ties broken by oldest first_seen. Returns fewer
        than `count` if the pool doesn't have enough (caller/main.py is
        responsible for auto-filling the shortfall with new devices —
        Part 4)."""
        with self._lock:
            devices = self._load()
        ranked = sorted(devices, key=lambda d: (-d.total_times_run, d.first_seen))
        return ranked[:count]

    def record_run(self, imsi: str) -> None:
        """Increments total_times_run for a device selected for this
        session — called once per returning device at selection time (not
        gated on that device's run actually succeeding: "times run" tracks
        how many sessions this identity was exercised in, which is what
        Part 3's ordering is meant to concentrate)."""
        with self._lock:
            devices = self._load()
            for d in devices:
                if d.imsi == imsi:
                    d.total_times_run += 1
                    break
            self._save(devices)

    def add_new(self, creds: LiveCredentials, timestamp: str) -> None:
        """Adds a freshly-generated device to the pool — first_seen = now,
        total_times_run = 1 (being added implies this session is its first
        use). If the pool is already at MAX_LIVE_DEVICES, evicts the
        least-valuable EXISTING entry first (fewest total_times_run, ties
        broken by oldest first_seen) — never evicts the device being added
        in the same call."""
        with self._lock:
            devices = self._load()
            if len(devices) >= MAX_LIVE_DEVICES:
                devices.sort(key=lambda d: (d.total_times_run, d.first_seen))
                devices = devices[1:]
            devices.append(PoolDevice(
                imsi=creds.imsi, suci=creds.suci, key_hex=creds.key_hex, opc_hex=creds.opc_hex,
                first_seen=timestamp, total_times_run=1,
            ))
            self._save(devices)

    def remove(self, imsi: str) -> bool:
        """Manual pruning (Part 5, optional) — returns False if imsi wasn't
        in the pool. Removing a device from the pool does NOT touch its
        experience history (that lives in the separate experience store)
        or delete its already-provisioned Open5GS subscriber/UE config —
        it only stops the pool from offering it as "returning" in future
        runs."""
        with self._lock:
            devices = self._load()
            remaining = [d for d in devices if d.imsi != imsi]
            if len(remaining) == len(devices):
                return False
            self._save(remaining)
            return True

    def existing_msins(self) -> set:
        """Every MSIN currently in the pool — passed alongside whatever
        MSINs are already used within THIS run so generate_live_credentials
        never collides with a pool device even across sessions."""
        return {d.imsi[-10:] for d in self.all()}


# One shared, process-local instance for the whole FastAPI app (mirrors
# results_store.py's `store` convention).
pool = DevicePool()
