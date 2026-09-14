"""Tests for the streaming Attack Testing endpoint: real per-device,
per-stage NDJSON progress for the live-only flow (Part C-H). Real hardware
is mocked at the live_mode.py boundary via live_fixtures.mock_live_hardware
— everything above that boundary (Systems/Privacy/Agent/assessment) runs
for real, exactly as it would in production."""

import json

import pytest
from fastapi.testclient import TestClient

import dashboard_backend.main as main_module
from dashboard_backend.tests.live_fixtures import mock_live_hardware


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "EXPERIENCE_PATH", str(tmp_path / "stream_experience.json"))
    from dashboard_backend.results_store import ResultsStore
    monkeypatch.setattr(main_module, "store", ResultsStore())
    # Isolated from the real, shared device_pool.json (device-pool task) —
    # without this, every API-level test would read/write the project's
    # actual persistent pool file instead of test-local state.
    from dashboard_backend.device_pool import DevicePool
    monkeypatch.setattr(main_module, "device_pool", DevicePool(tmp_path / "test_device_pool.json"))
    return TestClient(main_module.app)


def _read_events(client, body):
    with client.stream("POST", "/api/attack-test/run-stream", json=body) as resp:
        assert resp.status_code == 200
        return [json.loads(line) for line in resp.iter_lines() if line]


def test_stream_emits_run_started_first_with_a_usable_run_id(client):
    with mock_live_hardware("imsi-999709999991001", "suci-s1"):
        events = _read_events(
            client, {"attack_scenario": "duplicate_registration", "attack_mode": "same_for_all", "devices_this_run": 1},
        )
    assert events[0]["type"] == "run_started"
    assert events[0]["run_id"]
    assert events[0]["total"] == 1
    assert events[0]["attack_mode"] == "same_for_all"


def test_stream_emits_the_full_real_stage_sequence_for_one_device(client):
    with mock_live_hardware("imsi-999709999991002", "suci-s2"):
        events = _read_events(
            client, {"attack_scenario": "duplicate_registration", "attack_mode": "same_for_all", "devices_this_run": 1},
        )
    # live_fixtures.mock_live_hardware mocks whole live_mode.py functions
    # (provision_subscriber / run_baseline_registration / ...), so their
    # OWN internal stage emits (credentials_generated, adding_subscriber,
    # launching_ue, ...) don't fire here — those are covered directly by
    # test_live_mode.py's tests, which mock only launch_nr_ue_once and so
    # exercise the real emit() calls inside those functions. This test
    # checks the stages pipeline_service.run_live_device() itself emits.
    stage_names = [e["stage"] for e in events if e["type"] == "stage" and e.get("index") == 0]
    for expected in [
        "registering_context", "registered", "baseline_previewed", "baseline_executed",
        "attack_registered", "consulting_agent", "assessment_done", "ranking_done",
        "schemes_executed", "stability_replay_done", "real_stability_done",
    ]:
        assert expected in stage_names, f"missing stage {expected!r} in {stage_names}"
    # same_for_all mode never blocks — no selection stage.
    assert "awaiting_attack_selection" not in stage_names

    device_done = next(e for e in events if e["type"] == "device_done" and e["index"] == 0)
    assert device_done["device"]["comparison_result"] is not None
    assert device_done["device"]["baseline_execution"] is not None
    assert device_done["device"]["real_stability"] is not None
    assert "estimated_seconds_remaining" in device_done

    assert events[-1]["type"] == "batch_done"


def test_stream_covers_invalid_subscriber_stage_sequence(client):
    with mock_live_hardware("imsi-999709999991003", "suci-s3"):
        events = _read_events(
            client, {"attack_scenario": "invalid_subscriber", "attack_mode": "same_for_all", "devices_this_run": 1},
        )
    stage_names = [e["stage"] for e in events if e["type"] == "stage"]
    assert "agent_done" in stage_names
    assert "consulting_agent" in stage_names
    assert "baseline_previewed" not in stage_names

    device_done = next(e for e in events if e["type"] == "device_done")
    assert device_done["device"]["comparison_result"] is None
    assert device_done["device"]["recommendation"] is not None


def test_stream_multi_device_batch_isolates_one_failure(client):
    """duplicate/replay/flooding all launch multiple times per device —
    here one of two devices' provisioning fails; the batch must still
    finish and report both a success and an isolated failure."""
    call_count = {"n": 0}
    from unittest.mock import patch
    from dashboard_backend import live_mode
    from dashboard_backend.tests.live_fixtures import FakeAmfLog

    creds_ok = live_mode.LiveCredentials(imsi="imsi-999709999991005", suci="suci-ok", key_hex="A" * 32, opc_hex="B" * 32)
    creds_bad = live_mode.LiveCredentials(imsi="imsi-999709999991006", suci="suci-bad", key_hex="A" * 32, opc_hex="B" * 32)
    log = FakeAmfLog(creds_ok.imsi, creds_ok.suci)

    def fake_provision(attack_scenario, creds_arg, is_returning, on_stage=None):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return live_mode.ProvisionOutcome(creds=creds_ok, config_path="cfg.yaml", success=True, failure_reason=None)
        return live_mode.ProvisionOutcome(creds=creds_bad, config_path=None, success=False, failure_reason="mongo down")

    def fake_baseline(config_path, creds_, on_stage=None):
        log.add_launch()
        return live_mode.RegistrationEventOutcome(success=True, failure_reason=None, launch_count=1)

    def fake_attack(config_path, creds_, attack_scenario, is_returning=False, on_stage=None):
        for _ in range(2):
            log.add_launch()
        return live_mode.RegistrationEventOutcome(success=True, failure_reason=None, launch_count=2)

    def fake_replay(config_path, creds_, attack_scenario, replay_number, is_returning=False, on_stage=None):
        for _ in range(2):
            log.add_launch()
        return live_mode.RegistrationEventOutcome(success=True, failure_reason=None, launch_count=2)

    with patch.object(live_mode, "provision_subscriber", side_effect=fake_provision), \
         patch.object(live_mode, "run_baseline_registration", side_effect=fake_baseline), \
         patch.object(live_mode, "run_attack_registration", side_effect=fake_attack), \
         patch.object(live_mode, "run_stability_replay_registration", side_effect=fake_replay), \
         patch.object(live_mode, "parse_amf_log_for_device", side_effect=log.snapshot):
        events = _read_events(
            client, {"attack_scenario": "duplicate_registration", "attack_mode": "same_for_all", "devices_this_run": 2},
        )

    device_done = [e["device"] for e in events if e["type"] == "device_done"]
    assert len(device_done) == 2
    assert device_done[0]["live_success"] is True
    assert device_done[1]["live_success"] is False
    assert "mongo down" in device_done[1]["failure_reason"]

    batch_done = events[-1]
    assert batch_done["summary"]["live_failures"] == 1


def test_stream_per_device_mode_times_out_cleanly_when_nobody_selects(client, monkeypatch):
    """Part E 'choose per device': if nothing ever POSTs a selection, the
    device must fail cleanly with a timeout reason — not hang the stream
    forever. Uses a short override so the test doesn't wait the real 600s."""
    monkeypatch.setattr(main_module, "SELECTION_TIMEOUT_SECONDS", 1)

    with mock_live_hardware("imsi-999709999991007", "suci-s7"):
        events = _read_events(client, {"attack_mode": "per_device", "devices_this_run": 1})

    stage_names = [e["stage"] for e in events if e["type"] == "stage"]
    assert "awaiting_attack_selection" in stage_names

    device_done = next(e for e in events if e["type"] == "device_done")
    assert device_done["device"]["live_success"] is False
    assert "No attack scenario was selected" in device_done["device"]["failure_reason"]
    assert events[-1]["type"] == "batch_done"


def test_select_scenario_404_when_nothing_pending(client):
    resp = client.post(
        "/api/attack-test/select-scenario",
        json={"run_id": "does-not-exist", "device_index": 0, "attack_scenario": "flooding"},
    )
    assert resp.status_code == 404


def test_attack_scenario_required_for_same_for_all_mode_422(client):
    resp = client.post(
        "/api/attack-test/run-stream",
        json={"attack_mode": "same_for_all", "devices_this_run": 1},
    )
    assert resp.status_code == 422


def test_attack_scenario_forbidden_for_per_device_mode_422(client):
    resp = client.post(
        "/api/attack-test/run-stream",
        json={"attack_mode": "per_device", "attack_scenario": "replay", "devices_this_run": 1},
    )
    assert resp.status_code == 422


def test_invalid_subscriber_rejected_as_a_per_device_selection_422(client):
    """invalid_subscriber structurally cannot be chosen mid-flow (Part E) —
    the picker's own schema excludes it, so a POST offering it is invalid,
    not silently accepted."""
    resp = client.post(
        "/api/attack-test/select-scenario",
        json={"run_id": "whatever", "device_index": 0, "attack_scenario": "invalid_subscriber"},
    )
    assert resp.status_code == 422


def test_devices_this_run_above_cap_rejected_422(client):
    resp = client.post(
        "/api/attack-test/run-stream",
        json={"attack_scenario": "replay", "attack_mode": "same_for_all", "devices_this_run": 21},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Stop-attack task (Part 2)
# ---------------------------------------------------------------------------

def test_stop_endpoint_404_for_unknown_run_id(client):
    resp = client.post("/api/attack-test/does-not-exist/stop")
    assert resp.status_code == 404


def test_stream_marks_remaining_devices_cancelled_not_failed(client, monkeypatch):
    """A 3-device batch where cancellation is requested (simulated via
    run_control.is_cancelled directly, exactly what the real stop endpoint
    would flip) right after device 0 completes: device 0's own real result
    must be untouched, and devices 1-2 must come back labeled cancelled,
    never failed, without run_one_device ever being invoked for them."""
    from dashboard_backend import run_control

    # run_live_device() itself checks should_cancel() at several internal
    # checkpoints (after baseline, after attack, before each of 3 replays)
    # ON TOP OF _stream_devices' own once-per-device check — so device 0's
    # own full successful run alone calls this several times. The
    # threshold must be past ALL of device 0's own internal checks, so
    # cancellation only takes effect at device 1's turn.
    call_count = {"n": 0}

    def fake_is_cancelled(run_id):
        call_count["n"] += 1
        return call_count["n"] > 10

    monkeypatch.setattr(run_control, "is_cancelled", fake_is_cancelled)

    with mock_live_hardware("imsi-999709999991020", "suci-stop1"):
        events = _read_events(
            client, {"attack_scenario": "duplicate_registration", "attack_mode": "same_for_all", "devices_this_run": 3},
        )

    device_done = [e["device"] for e in events if e["type"] == "device_done"]
    assert len(device_done) == 3
    assert device_done[0]["live_success"] is True
    assert device_done[0].get("cancelled") in (False, None)
    assert device_done[1]["cancelled"] is True
    assert device_done[1]["failure_reason"] == "Cancelled by user"
    assert device_done[2]["cancelled"] is True

    batch_done = events[-1]
    assert batch_done["summary"]["cancelled_count"] == 2
    # Cancelled devices must never be counted as failures.
    assert batch_done["summary"]["live_failures"] == 0


def test_stop_endpoint_actually_stops_a_real_in_progress_run(client):
    """End-to-end: register a run via run_control the same way
    _stream_attack_test does, confirm POST .../stop flips it, confirm
    run_control reports it cancelled."""
    from dashboard_backend import run_control

    run_control.register("test-stop-run-1")
    try:
        resp = client.post("/api/attack-test/test-stop-run-1/stop")
        assert resp.status_code == 200
        assert resp.json()["status"] == "stopping"
        assert run_control.is_cancelled("test-stop-run-1") is True
    finally:
        run_control.unregister("test-stop-run-1")


# ---------------------------------------------------------------------------
# Clear-experience-store task (Part 3)
# ---------------------------------------------------------------------------

def test_clear_experience_store_empties_it_and_leaves_device_pool_untouched(client, tmp_path, monkeypatch):
    import json
    from capss.experience_memory.memory import ExperienceMemory
    from dashboard_backend.device_pool import DevicePool
    from dashboard_backend.live_mode import generate_live_credentials

    exp_path = tmp_path / "clear_test_experience.json"
    monkeypatch.setattr(main_module, "EXPERIENCE_PATH", str(exp_path))

    pool_path = tmp_path / "clear_test_pool.json"
    pool = DevicePool(pool_path)
    pool.add_new(generate_live_credentials(set()), "2026-01-01T00:00:00+00:00")
    monkeypatch.setattr(main_module, "device_pool", pool)

    # Seed some real experience data via the real ExperienceMemory API.
    with mock_live_hardware("imsi-999709999991030", "suci-clear1"):
        _read_events(
            client, {"attack_scenario": "duplicate_registration", "attack_mode": "same_for_all", "devices_this_run": 1},
        )
    assert ExperienceMemory(str(exp_path)).get_stats()["total_experiences"] > 0
    pool_before = json.loads(pool_path.read_text())

    resp = client.delete("/api/experience/clear")
    assert resp.status_code == 200
    assert resp.json()["cleared_ue_count"] >= 1

    assert ExperienceMemory(str(exp_path)).get_stats()["total_experiences"] == 0
    pool_after = json.loads(pool_path.read_text())
    assert pool_after == pool_before  # device pool completely untouched


def test_stream_devices_never_hangs_when_a_device_crashes_unexpectedly():
    """Regression guard: an unexpected exception from run_one_device()
    (e.g. the real "python" subprocess PermissionError found during live
    testing) used to kill the worker thread mid-device with no terminal
    event ever sent for it — the frontend's story card would sit on the
    last stage forever with no way to know the run had actually ended.
    Every device must reach a terminal event, and the generator must
    always finish."""

    def flaky_run_one_device(index, on_stage):
        on_stage("registering", {"ue_id": f"imsi-{index}"})
        if index == 1:
            raise RuntimeError("simulated unexpected crash")
        return {"ue_id": f"imsi-{index}", "ok": True}

    result_holder = {}
    events = list(main_module._stream_devices(3, flaky_run_one_device, result_holder))
    parsed = [json.loads(e) for e in events]

    device_done_events = [e for e in parsed if e["type"] == "device_done"]
    assert len(device_done_events) == 3, "every device must reach a terminal event, including the crashed one"

    crashed = device_done_events[1]["device"]
    assert crashed["live_success"] is False
    assert "simulated unexpected crash" in crashed["failure_reason"]

    assert len(result_holder["devices"]) == 3
