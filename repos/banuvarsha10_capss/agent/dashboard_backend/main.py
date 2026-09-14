"""dashboard_backend/main.py

FastAPI app for the CAPSS Dashboard. Run from the `agent/` directory (same
convention as demo_for_mentor.py's relative "data/privacy_schemes.json"
path):

    cd agent
    uvicorn dashboard_backend.main:app --reload

This file, and everything it imports from dashboard_backend/, is entirely
new. It only imports and calls existing, unmodified code from capss/,
systems/, privacy/, and tests/integration/subscriber_fixtures.py.

Attack Testing is Live Mode ONLY (Normal/simulated mode was removed) —
every run here provisions real subscribers and registers them against the
real Open5GS/UERANSIM stack. See pipeline_service.run_live_device()'s
docstring for the full per-device flow.
"""

from __future__ import annotations

import json
import os
import queue
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from capss.knowledge_base.scheme_kb import SchemeKnowledgeBase
from capss.experience_memory.memory import ExperienceMemory
from capss.schemas.context import RegistrationContext

from dashboard_backend.identity_gen import generate_fresh_identities, mask_identity, UEIdentity
from dashboard_backend.systems_privacy_view import SystemsPrivacyView
from dashboard_backend.pipeline_service import run_live_device, run_manual_and_assess, run_scale_device
from dashboard_backend import pending_selections
from dashboard_backend import run_control
from dashboard_backend.device_pool import pool as device_pool
from dashboard_backend.results_store import store
from dashboard_backend.schemas import (
    AttackTestRunRequest, SelectScenarioRequest, ManualScenarioRequest,
    ScalingRunRequest,
)
from dashboard_backend.live_mode import LiveCredentials, MAX_LIVE_DEVICES, generate_live_credentials

SCHEMES_PATH = "data/privacy_schemes.json"
EXPERIENCE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "dashboard_experience_store.json"
)
# Scaling panel task: a dedicated, SEPARATE experience store — never the
# real, persistent EXPERIENCE_PATH above. Reset (real ExperienceMemory.
# clear(), same mechanism /api/experience/clear already uses) at the START
# of every scaling run, so 100-500 devices' worth of experience data never
# accumulates unbounded across runs, and Attack Testing/Manual Scenario
# Builder's real experience history is never touched by a scale test.
SCALING_EXPERIENCE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "dashboard_scaling_experience_store.json"
)
# Task-specified: reduced from the real default of 3 (assess_adaptation()'s
# own default, used everywhere else), SPECIFICALLY for scaling-panel runs —
# at 500 devices, 3 replays would mean far more real registrations than this
# panel's purpose (throughput measurement) needs; stability is already
# proven separately, elsewhere, with the real default.
SCALING_REPLAY_COUNT = 1

# A human has to look at the baseline result and pick a scenario — generous
# on purpose (Part E "choose per device" mode).
SELECTION_TIMEOUT_SECONDS = 600

app = FastAPI(title="CAPSS Dashboard API")

app.add_middleware(
    CORSMiddleware,
    # This is a local-only dev tool with no cookies/credentials involved,
    # so a wildcard origin is safe here — and necessary in practice, since
    # under WSL2 the frontend may end up reachable via "localhost",
    # "127.0.0.1", or the WSL VM's own dynamic IP depending on the host's
    # networking setup, and hardcoding one origin broke real setups.
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {"status": "ok"}


def _summarize(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    verdict_counts: Dict[str, int] = {}
    overhead_deltas = []
    cold_start_rag_count = 0
    real_stability_confirmed_count = 0
    real_stability_eligible_count = 0

    for d in devices:
        if d.get("cold_start"):
            cold_start_rag_count += 1

        real_stability = d.get("real_stability")
        if real_stability is not None:
            real_stability_eligible_count += 1
            if real_stability.get("confirmed"):
                real_stability_confirmed_count += 1

        comparison = d.get("comparison_result")
        if comparison is None:
            verdict_counts["NO_COMPARISON"] = verdict_counts.get("NO_COMPARISON", 0) + 1
            continue

        verdict = comparison.overall_verdict
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        overhead = comparison.measured_overhead
        if overhead is not None:
            overhead_deltas.append(overhead.time_diff_pct)

    avg_overhead_delta = (
        round(sum(overhead_deltas) / len(overhead_deltas), 2) if overhead_deltas else None
    )

    return {
        "verdict_counts": verdict_counts,
        "cold_start_rag_count": cold_start_rag_count,
        "avg_overhead_delta": avg_overhead_delta,
        "total_devices": len(devices),
        "real_stability_confirmed_count": real_stability_confirmed_count,
        "real_stability_eligible_count": real_stability_eligible_count,
    }


# ---------------------------------------------------------------------------
# Streaming — real per-device, per-stage progress as it actually happens
# (not a fake replay animation). Devices run SEQUENTIALLY in ONE background
# thread — a queue bridges that thread's real-time stage callbacks to this
# generator's yields, since a Python generator can't yield from inside a
# nested blocking call otherwise. This is what makes Live Mode's genuinely
# slow real waits (dbctl, nr-ue registration, up to 5 registrations per
# device — more for multi-launch scenarios, see live_mode.py) show up live
# instead of only after the whole batch finishes.
# ---------------------------------------------------------------------------

def _ndjson(event: Dict[str, Any]) -> str:
    return json.dumps(jsonable_encoder(event)) + "\n"


def _crashed_device_placeholder(reason: str, device_origin: Optional[str] = None) -> Dict[str, Any]:
    """Shaped like a normal device result but marked failed — used when
    run_one_device() raises something NOT already converted to a clean
    failure by the caller (live_mode.py's own LiveStepError handling, for
    example). Confirmed directly earlier in this project: without this, an
    unexpected exception killed the worker thread mid-device with no
    device_done event ever sent for it — the frontend's story card just
    sits on the last stage forever with no way to tell the run actually
    ended. Every device MUST get a terminal event.

    device_origin is threaded through where the caller knows it (Attack
    Testing's resolved device list — device-pool task) so even a crash
    still labels whether the pool's bookkeeping for this device (already
    updated at selection time, before it started running) refers to a
    returning/new device; left None for callers with no such concept
    (Manual Scenario Builder)."""
    return {
        "ue_id": None, "suci": None, "masked_identity": "unknown device",
        "attack_scenario": None, "steps": [], "cold_start": None,
        "baseline_preview": None, "baseline_execution": None,
        "comparison_result": None, "recommendation": None, "no_comparison_reason": None,
        "decision_trace": None, "hybrid_combination": None, "hybrid_benefit_score": None,
        "hybrid_reason": None, "explanation": None,
        "scheme_a_execution": None, "scheme_b_execution": None, "real_stability": None,
        "device_origin": device_origin, "cancelled": False, "llm_explanation": None,
        "live_success": False, "failure_reason": f"Unexpected error: {reason}",
        "initial_registration_ms": None, "post_attack_computation_ms": None,
    }


def _never_started_placeholder(device_origin: Optional[str] = None) -> Dict[str, Any]:
    """A device this batch never even attempted, because a stop-attack
    request (Part 2) arrived before its turn — distinct from both a real
    failure and a crash: nothing was tried, nothing went wrong."""
    return {
        "ue_id": None, "suci": None, "masked_identity": "not started (cancelled)",
        "attack_scenario": None, "steps": [], "cold_start": None,
        "baseline_preview": None, "baseline_execution": None,
        "comparison_result": None, "recommendation": None, "no_comparison_reason": None,
        "decision_trace": None, "hybrid_combination": None, "hybrid_benefit_score": None,
        "hybrid_reason": None, "explanation": None,
        "scheme_a_execution": None, "scheme_b_execution": None, "real_stability": None,
        "device_origin": device_origin, "cancelled": True, "llm_explanation": None,
        "live_success": False, "failure_reason": "Cancelled by user",
        "initial_registration_ms": None, "post_attack_computation_ms": None,
    }


def _stream_devices(
    total: int,
    run_one_device,
    result_holder: Dict[str, Any],
    get_placeholder: Optional[Callable[[int, str], Dict[str, Any]]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
    get_never_started_placeholder: Optional[Callable[[int], Dict[str, Any]]] = None,
) -> Iterator[str]:
    q: "queue.Queue" = queue.Queue()
    DONE = object()

    def worker():
        devices: List[Dict[str, Any]] = []
        durations: List[float] = []
        try:
            for index in range(total):
                # Stop-attack safe point (Part 2): between devices, never
                # mid-device. If cancelled, this and every remaining device
                # are marked cancelled without ever being attempted — the
                # CURRENT in-flight device (if any) already stopped itself
                # cleanly via its own internal should_cancel checks before
                # returning, so by the time we're back at this loop there
                # is nothing in flight to interrupt.
                if should_cancel and should_cancel():
                    for remaining_index in range(index, total):
                        q.put({"type": "device_start", "index": remaining_index, "total": total})
                        result = (
                            get_never_started_placeholder(remaining_index) if get_never_started_placeholder is not None
                            else _never_started_placeholder()
                        )
                        devices.append(result)
                        q.put({"type": "device_done", "index": remaining_index, "total": total, "device": result})
                    break

                q.put({"type": "device_start", "index": index, "total": total})
                device_start = time.monotonic()

                def on_stage(stage, data, _index=index):
                    q.put({"type": "stage", "index": _index, "total": total, "stage": stage, **data})

                try:
                    result = run_one_device(index, on_stage)
                except Exception as exc:  # noqa: BLE001 — see docstring above: every
                    # device must reach a terminal state, whatever went wrong.
                    result = (
                        get_placeholder(index, str(exc)) if get_placeholder is not None
                        else _crashed_device_placeholder(str(exc))
                    )
                devices.append(result)

                durations.append(time.monotonic() - device_start)
                remaining = total - (index + 1)
                avg = sum(durations) / len(durations)
                q.put({
                    "type": "device_done", "index": index, "total": total, "device": result,
                    # Rolling average of ACTUAL completed-device durations so far,
                    # projected across whatever's left — real devices can pick
                    # very different attack scenarios (Part E per-device mode)
                    # with very different real launch counts, so this is a
                    # genuine estimate, not a fixed per-device constant.
                    "estimated_seconds_remaining": round(avg * remaining, 1) if remaining > 0 else 0,
                })
        finally:
            q.put((DONE, devices))

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    while True:
        item = q.get()
        if isinstance(item, tuple) and item[0] is DONE:
            result_holder["devices"] = item[1]
            break
        yield _ndjson(item)
    t.join(timeout=5)


def _per_device_scenario_resolver(run_id: str, index: int):
    """Part E 'choose per device': returns a zero-arg callable that BLOCKS
    (genuinely — via queue.Queue.get) until POST /api/attack-test/
    select-scenario resolves this device's pending selection, or raises
    TimeoutError after SELECTION_TIMEOUT_SECONDS. pipeline_service.py's
    run_live_device() treats either outcome as a normal per-device failure
    (Part F step 13) — it never crashes the batch."""
    def resolve() -> str:
        q = pending_selections.register(run_id, index)
        try:
            return q.get(timeout=SELECTION_TIMEOUT_SECONDS)
        except queue.Empty as exc:
            raise TimeoutError(f"No attack scenario selected within {SELECTION_TIMEOUT_SECONDS}s") from exc
        finally:
            pending_selections.unregister(run_id, index)
    return resolve


def _resolve_devices(body: AttackTestRunRequest) -> List[Tuple[LiveCredentials, str]]:
    """Part 2-4 (device-pool task): resolves this run's exact device list
    — (creds, device_origin) pairs, in run order — BEFORE any device
    starts, so the pool's bookkeeping (record_run/add_new) is always
    consistent with what was decided for this session, even if a device's
    own real registration flow fails later (Part F step 13 keeps failures
    per-device; the pool decision that already happened doesn't unwind).

    invalid_subscriber (only reachable via attack_mode == "same_for_all"
    — Part E already excludes it from the per-device picker) bypasses the
    pool entirely: every device is freshly, ad hoc generated and labeled
    "new_requested", never touching device_pool.py — see that module's
    docstring for why a never-provisioned identity can't meaningfully
    "return" as a known subscriber.

    Otherwise: returning_count = devices_this_run - new_devices_count.
    Pool devices with the MOST prior history are pulled first (Part 3). If
    the pool has fewer than returning_count devices, the shortfall is
    auto-generated and labeled "new_autofilled" — distinct from the
    new_devices_count devices explicitly requested via Control 2, labeled
    "new_requested" (Part 4 — these must never display identically).
    """
    if body.attack_mode == "same_for_all" and body.attack_scenario == "invalid_subscriber":
        existing: set = set()
        return [(generate_live_credentials(existing), "new_requested") for _ in range(body.devices_this_run)]

    returning_count = body.devices_this_run - body.new_devices_count
    returning_pool_devices = device_pool.select_returning(returning_count)
    shortfall = returning_count - len(returning_pool_devices)

    existing_msins = device_pool.existing_msins()
    now = datetime.now(timezone.utc).isoformat()
    resolved: List[Tuple[LiveCredentials, str]] = []

    for pd in returning_pool_devices:
        device_pool.record_run(pd.imsi)
        resolved.append((
            LiveCredentials(imsi=pd.imsi, suci=pd.suci, key_hex=pd.key_hex, opc_hex=pd.opc_hex), "returning",
        ))

    for _ in range(body.new_devices_count):
        creds = generate_live_credentials(existing_msins)
        device_pool.add_new(creds, now)
        resolved.append((creds, "new_requested"))

    for _ in range(shortfall):
        creds = generate_live_credentials(existing_msins)
        device_pool.add_new(creds, now)
        resolved.append((creds, "new_autofilled"))

    return resolved


@app.post("/api/attack-test/run-stream")
def run_attack_test_stream(body: AttackTestRunRequest) -> StreamingResponse:
    return StreamingResponse(_stream_attack_test(body), media_type="application/x-ndjson")


def _stream_attack_test(body: AttackTestRunRequest) -> Iterator[str]:
    resolved_devices = _resolve_devices(body)  # Part 2-4, resolved BEFORE the stream starts
    device_count = len(resolved_devices)
    view = SystemsPrivacyView()
    run_id = store.new_run_id()
    run_control.register(run_id)  # Part 2 (stop-attack) — must exist before run_started is sent

    # Emitted FIRST, before any device starts, so the frontend has run_id
    # in hand before it could possibly need to POST a per-device selection
    # OR a stop request.
    yield _ndjson({
        "type": "run_started", "run_id": run_id, "total": device_count, "attack_mode": body.attack_mode,
    })

    def should_cancel() -> bool:
        return run_control.is_cancelled(run_id)

    def run_one_device(index: int, on_stage) -> Dict[str, Any]:
        creds, device_origin = resolved_devices[index]
        scenario = (
            body.attack_scenario if body.attack_mode == "same_for_all"
            else _per_device_scenario_resolver(run_id, index)
        )
        return run_live_device(
            view=view,
            schemes_path=SCHEMES_PATH,
            experience_path=EXPERIENCE_PATH,
            attack_scenario=scenario,
            creds=creds,
            device_origin=device_origin,
            on_stage=on_stage,
            should_cancel=should_cancel,
            # Baseline-forcing fix: real 0-indexed position in THIS run —
            # feeds baseline_for_position() (capss/scheme_execution/
            # assessment.py), never derived from device identity/history.
            batch_position=index,
        )

    def get_placeholder(index: int, reason: str) -> Dict[str, Any]:
        _, device_origin = resolved_devices[index]
        return _crashed_device_placeholder(reason, device_origin)

    def get_never_started_placeholder(index: int) -> Dict[str, Any]:
        _, device_origin = resolved_devices[index]
        return _never_started_placeholder(device_origin)

    try:
        result_holder: Dict[str, Any] = {}
        yield from _stream_devices(
            device_count, run_one_device, result_holder,
            get_placeholder=get_placeholder, should_cancel=should_cancel,
            get_never_started_placeholder=get_never_started_placeholder,
        )

        devices = result_holder["devices"]
        summary = _summarize(devices)
        # Cancelled devices are reported separately from genuine failures —
        # nothing about them actually failed (Part 2).
        summary["live_failures"] = sum(
            1 for d in devices if d.get("live_success") is False and not d.get("cancelled")
        )
        summary["cancelled_count"] = sum(1 for d in devices if d.get("cancelled"))
        store.save_run(run_id, devices, summary)
        yield _ndjson({"type": "batch_done", "run_id": run_id, "summary": summary})
    finally:
        run_control.unregister(run_id)


@app.post("/api/attack-test/{run_id}/stop")
def stop_attack_test(run_id: str) -> Dict[str, Any]:
    """Part 2 (stop-attack): requests a running batch stop at the next safe
    point. Does not forcibly kill anything itself — see run_control.py and
    pipeline_service.run_live_device()'s should_cancel checkpoints for why
    that's never necessary (every real nr-ue launch is already cleaned up
    in its own finally block regardless of outcome)."""
    ok = run_control.request_stop(run_id)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=f"No in-progress run with run_id={run_id!r} (already finished, or never existed).",
        )
    return {"status": "stopping"}


@app.post("/api/attack-test/select-scenario")
def select_scenario(body: SelectScenarioRequest) -> Dict[str, Any]:
    """Resolves ONE device's pending attack-scenario selection (Part E
    'choose per device' mode) — see pending_selections.py."""
    ok = pending_selections.resolve(body.run_id, body.device_index, body.attack_scenario)
    if not ok:
        raise HTTPException(
            status_code=404,
            detail=(
                "No pending selection for this run_id/device_index — it may already be "
                "resolved, timed out, or the run hasn't reached this device's baseline yet."
            ),
        )
    return {"status": "ok"}


@app.get("/api/device-pool")
def list_device_pool() -> Dict[str, Any]:
    """The persistent device pool (device-pool task, Part 5) — every
    device's real history summary, ranked the same way select_returning()
    would prefer them (most prior runs first)."""
    devices = sorted(device_pool.all(), key=lambda d: (-d.total_times_run, d.first_seen))
    return {
        "devices": [
            {
                "imsi": d.imsi, "masked_identity": mask_identity(d.imsi),
                "first_seen": d.first_seen, "total_times_run": d.total_times_run,
            }
            for d in devices
        ],
        "capacity": MAX_LIVE_DEVICES,
    }


@app.delete("/api/device-pool/{imsi}")
def delete_device_pool_entry(imsi: str) -> Dict[str, Any]:
    """Manual pruning (Part 5, optional). Only removes this device from
    the POOL — its accumulated experience history and its already-
    provisioned Open5GS subscriber/UE config are untouched, so it simply
    stops being offered as "returning" in future runs."""
    removed = device_pool.remove(imsi)
    if not removed:
        raise HTTPException(status_code=404, detail=f"{imsi!r} is not in the device pool")
    return {"status": "ok", "removed": imsi}


@app.get("/api/run/{run_id}")
def get_run(run_id: str) -> Dict[str, Any]:
    run = store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return run


@app.get("/api/assessment/{ue_id}")
def get_assessment(ue_id: str) -> Dict[str, Any]:
    device = store.get_latest_for_ue(ue_id)
    if device is None:
        raise HTTPException(status_code=404, detail="No result for this UE yet")
    return {
        "ue_id": ue_id,
        "comparison_result": device.get("comparison_result"),
        "no_comparison_reason": device.get("no_comparison_reason"),
    }


@app.get("/api/recommendation/{ue_id}")
def get_recommendation(ue_id: str) -> Dict[str, Any]:
    device = store.get_latest_for_ue(ue_id)
    if device is None:
        raise HTTPException(status_code=404, detail="No result for this UE yet")
    comparison = device.get("comparison_result")
    recommendation = device.get("recommendation")
    return {
        "ue_id": ue_id,
        "recommendation": recommendation,
        "scheme_a": comparison.scheme_a if comparison else None,
        "scheme_b": comparison.scheme_b if comparison else None,
    }


@app.get("/api/agent-trace/{ue_id}")
def get_agent_trace(ue_id: str) -> Dict[str, Any]:
    device = store.get_latest_for_ue(ue_id)
    if device is None:
        raise HTTPException(status_code=404, detail="No result for this UE yet")
    return {
        "ue_id": ue_id,
        "decision_trace": device.get("decision_trace"),
        "attack_scenario": device.get("attack_scenario"),
    }


# ---------------------------------------------------------------------------
# Tier 2 — Knowledge Base Viewer (read-only)
# ---------------------------------------------------------------------------

@app.get("/api/knowledge-base")
def list_knowledge_base() -> Dict[str, Any]:
    kb = SchemeKnowledgeBase(SCHEMES_PATH)
    return {
        "knowledge_version": kb.get_knowledge_version(),
        "schemes": kb.get_all_schemes(),
    }


@app.get("/api/knowledge-base/compare")
def compare_knowledge_base(a: str, b: str) -> Dict[str, Any]:
    kb = SchemeKnowledgeBase(SCHEMES_PATH)
    scheme_a = kb.get_by_short_name(a)
    scheme_b = kb.get_by_short_name(b)
    if scheme_a is None or scheme_b is None:
        raise HTTPException(status_code=404, detail=f"Unknown scheme short_name: {a if scheme_a is None else b}")
    return {"scheme_a": scheme_a, "scheme_b": scheme_b}


# ---------------------------------------------------------------------------
# Scaling / Throughput panel — 100-500 real devices, full real pipeline,
# Check 2 at replay_count=1. See ScalingRunRequest / run_scale_device()
# docstrings for the full design and why. Distinct from the separate
# until-failure stress test (dashboard_backend/scripts/stress_test.py),
# which shares run_scale_device() but has no user-facing UI and searches
# for a real failure point rather than measuring throughput at a safe,
# user-chosen size.
# ---------------------------------------------------------------------------

def _minimal_crashed_scale_device(reason: str) -> Dict[str, Any]:
    """Matches run_scale_device()'s own minimal dict shape (never the full
    DeviceResult shape _crashed_device_placeholder produces) — an
    unexpected exception is Part F step 13-style per-device failure
    isolation, same as any other real per-device failure at this scale."""
    return {
        "ue_id": None, "masked_identity": "unknown device", "success": False,
        "stage": "crashed", "failure_reason": f"Unexpected error: {reason}",
        "scheme_a": None, "scheme_b": None, "overall_verdict": None, "elapsed_s": 0.0,
    }


@app.post("/api/scaling-run/run-stream")
def run_scaling_stream(body: ScalingRunRequest) -> StreamingResponse:
    return StreamingResponse(_stream_scaling_run(body), media_type="application/x-ndjson")


def _stream_scaling_run(body: ScalingRunRequest) -> Iterator[str]:
    # Experience-store policy (see SCALING_EXPERIENCE_PATH's own comment):
    # real ExperienceMemory.clear() at the START of every run, so this
    # dedicated scratch store never grows unbounded across MULTIPLE scaling
    # runs, and starts every run from a genuinely clean, comparable state.
    ExperienceMemory(SCALING_EXPERIENCE_PATH).clear()

    device_count = body.device_count
    view = SystemsPrivacyView()
    existing_msins: set = set()
    started_at = time.monotonic()

    yield _ndjson({
        "type": "run_started", "total": device_count, "attack_scenario": body.attack_scenario,
        "replay_count": SCALING_REPLAY_COUNT,
    })

    def run_one_device(index: int, _on_stage) -> Dict[str, Any]:
        creds = generate_live_credentials(existing_msins)
        # batch_position=index: real 0-indexed position in THIS run — same
        # alternation input the baseline-forcing fix and "vs. static
        # baseline" feature both use, never derived from device identity.
        return run_scale_device(
            view, SCHEMES_PATH, SCALING_EXPERIENCE_PATH, body.attack_scenario, creds,
            batch_position=index, replay_count=SCALING_REPLAY_COUNT,
        )

    def get_placeholder(_index: int, reason: str) -> Dict[str, Any]:
        return _minimal_crashed_scale_device(reason)

    result_holder: Dict[str, Any] = {}
    yield from _stream_devices(device_count, run_one_device, result_holder, get_placeholder=get_placeholder)

    devices = result_holder.get("devices", [])
    total_elapsed_s = time.monotonic() - started_at
    n_success = sum(1 for d in devices if d.get("success"))
    n_failed = len(devices) - n_success
    avg_seconds_per_device = (total_elapsed_s / len(devices)) if devices else 0.0

    yield _ndjson({
        "type": "scaling_done",
        "total_devices": len(devices),
        "succeeded": n_success,
        "failed": n_failed,
        "total_elapsed_s": round(total_elapsed_s, 2),
        "avg_seconds_per_device": round(avg_seconds_per_device, 3),
        "replay_count_used": SCALING_REPLAY_COUNT,
    })


# ---------------------------------------------------------------------------
# Tier 2 — Experience Memory + Timeline
# ---------------------------------------------------------------------------

@app.delete("/api/experience/clear")
def clear_experience_store() -> Dict[str, Any]:
    """Part 3 (clear-experience-store): wipes ALL accumulated per-UE
    experience history (and, by extension, the EAS/RAG signal it feeds —
    see capss/reasoning/metrics.py) back to empty. Destructive; the
    frontend gates this behind an explicit confirmation dialog — this
    endpoint itself does not ask again.

    Uses ExperienceMemory's own clear() (capss/experience_memory/memory.py,
    unmodified) rather than deleting or hand-writing the file, so the
    resulting empty file is in the exact same real, valid shape the module
    itself would produce.

    Does NOT touch dashboard_backend/device_pool.json — clearing experience
    history and clearing the device identity pool are two independently
    controllable things (device-pool task). A device's IMSI/SUCI/K/OPC and
    its total_times_run bookkeeping are pool state, not experience state;
    they remain exactly as they were, so the SAME real subscribers stay
    reusable, they just start again with no accumulated history.
    """
    memory = ExperienceMemory(EXPERIENCE_PATH)
    ue_count_before = len(memory.get_all_ues())
    memory.clear()
    return {"status": "ok", "cleared_ue_count": ue_count_before}


@app.get("/api/experience/stats")
def experience_stats() -> Dict[str, Any]:
    return ExperienceMemory(EXPERIENCE_PATH).get_stats()


@app.get("/api/experience/ues")
def experience_ues() -> Dict[str, Any]:
    return {"ue_ids": ExperienceMemory(EXPERIENCE_PATH).get_all_ues()}


@app.get("/api/experience/{ue_id}/timeline")
def experience_timeline(ue_id: str) -> Dict[str, Any]:
    memory = ExperienceMemory(EXPERIENCE_PATH)
    experiences = memory.retrieve(ue_id)
    if not experiences:
        raise HTTPException(status_code=404, detail="No experience history for this UE")
    adaptation_history = memory.get_adaptation_history(ue_id)
    # Oldest-first for a left-to-right timeline chart; retrieve() is newest-first.
    confidence_trend = [
        {"timestamp": e.timestamp, "confidence": e.confidence, "selected_scheme": e.selected_scheme}
        for e in reversed(experiences)
    ]
    return {
        "ue_id": ue_id,
        "adaptation_history": adaptation_history,
        "confidence_trend": confidence_trend,
    }


# ---------------------------------------------------------------------------
# Tier 2 — Manual Scenario Builder
# ---------------------------------------------------------------------------

def _build_manual_contexts(body: ManualScenarioRequest):
    """Builds (identity, pre_context, attack_context) for one manual run.
    Reuses body.reuse_identity when given, so the SAME UE can undergo
    repeated manual scenarios with different slider values — otherwise a
    fresh identity is generated, matching Attack Testing's default."""
    from datetime import datetime, timedelta

    if body.reuse_identity is not None:
        identity = UEIdentity(
            ue_id=body.reuse_identity.ue_id,
            suci=body.reuse_identity.suci,
            msin=body.reuse_identity.ue_id[-10:],
        )
    else:
        identity = generate_fresh_identities(1)[0]

    base_time = datetime(2026, 1, 1, 12, 0, 0)

    pre_context = RegistrationContext(
        ue_id=identity.ue_id,
        suci=identity.suci,
        registration_type=body.registration_type,
        slice_type=body.slice_type,
        dnn=body.dnn,
        timestamp=base_time,
        request_classification="ALLOW",
        attack_type=None,
        attack_severity="NORMAL",
        detection_confidence=0.0,
        threat_score=0.0,
        privacy_score=1.0,
        privacy_risk_level="LOW",
        metadata_leakage=0.0,
        correlation_score=0.0,
    )
    attack_context = RegistrationContext(
        ue_id=identity.ue_id,
        suci=identity.suci,
        registration_type=body.registration_type,
        slice_type=body.slice_type,
        dnn=body.dnn,
        timestamp=base_time + timedelta(seconds=5),
        request_classification=body.request_classification,
        attack_type=body.attack_type,
        attack_severity=body.attack_severity,
        detection_confidence=body.detection_confidence,
        threat_score=body.threat_score,
        privacy_score=body.privacy_score,
        privacy_risk_level=body.privacy_risk_level,
        metadata_leakage=body.metadata_leakage,
        correlation_score=body.correlation_score,
    )
    return identity, pre_context, attack_context


@app.post("/api/manual-scenario/run")
def run_manual_scenario(body: ManualScenarioRequest) -> Dict[str, Any]:
    identity, pre_context, attack_context = _build_manual_contexts(body)
    device = run_manual_and_assess(pre_context, attack_context, SCHEMES_PATH, EXPERIENCE_PATH, mode="manual")

    run_id = store.new_run_id()
    summary = _summarize([device])
    store.save_run(run_id, [device], summary)
    return {"run_id": run_id, "device": device, "identity": {"ue_id": identity.ue_id, "suci": identity.suci}}


@app.post("/api/manual-scenario/run-stream")
def run_manual_scenario_stream(body: ManualScenarioRequest) -> StreamingResponse:
    """Same real-time stage streaming as Attack Testing (see
    /api/attack-test/run-stream), for exactly one device."""
    identity, pre_context, attack_context = _build_manual_contexts(body)

    def run_one_device(index: int, on_stage) -> Dict[str, Any]:
        return run_manual_and_assess(
            pre_context, attack_context, SCHEMES_PATH, EXPERIENCE_PATH, mode="manual", on_stage=on_stage,
        )

    def generator() -> Iterator[str]:
        result_holder: Dict[str, Any] = {}
        yield from _stream_devices(1, run_one_device, result_holder)
        devices = result_holder["devices"]
        summary = _summarize(devices)
        run_id = store.new_run_id()
        store.save_run(run_id, devices, summary)
        yield _ndjson({
            "type": "batch_done",
            "run_id": run_id,
            "summary": summary,
            "identities": [{"ue_id": identity.ue_id, "suci": identity.suci}],
        })

    return StreamingResponse(generator(), media_type="application/x-ndjson")
