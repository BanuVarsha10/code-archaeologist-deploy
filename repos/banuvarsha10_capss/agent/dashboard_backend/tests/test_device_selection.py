"""Tests for main.py's _resolve_devices() — Part 2-4 (device-pool task):
returning/new-device selection logic. Part 3's return-ORDER preference is
covered directly against DevicePool in test_device_pool.py; this file
covers device-count accounting, auto-fill labeling (Part 4), the
new_devices_count == 0 no-generation guarantee, and invalid_subscriber's
pool bypass."""

import pytest

import dashboard_backend.main as main_module
from dashboard_backend.device_pool import DevicePool
from dashboard_backend.live_mode import generate_live_credentials
from dashboard_backend.schemas import AttackTestRunRequest


@pytest.fixture()
def isolated_pool(tmp_path, monkeypatch):
    pool = DevicePool(tmp_path / "pool.json")
    monkeypatch.setattr(main_module, "device_pool", pool)
    return pool


def _body(**kwargs) -> AttackTestRunRequest:
    defaults = dict(attack_mode="same_for_all", attack_scenario="replay", devices_this_run=1, new_devices_count=0)
    defaults.update(kwargs)
    return AttackTestRunRequest(**defaults)


def test_autofill_labels_every_device_new_autofilled_when_pool_is_empty(isolated_pool):
    resolved = main_module._resolve_devices(_body(devices_this_run=5, new_devices_count=0))

    assert len(resolved) == 5
    assert all(origin == "new_autofilled" for _, origin in resolved)
    # Every auto-filled device must actually have been added to the pool.
    assert len(isolated_pool.all()) == 5


def test_new_devices_count_zero_with_populated_pool_never_generates(isolated_pool):
    for _ in range(3):
        isolated_pool.add_new(generate_live_credentials(set()), "2026-01-01T00:00:00+00:00")

    resolved = main_module._resolve_devices(_body(devices_this_run=3, new_devices_count=0))

    assert len(resolved) == 3
    assert all(origin == "returning" for _, origin in resolved)
    assert len(isolated_pool.all()) == 3  # unchanged -- nothing new added


def test_partial_autofill_when_pool_has_some_but_not_enough(isolated_pool):
    isolated_pool.add_new(generate_live_credentials(set()), "2026-01-01T00:00:00+00:00")
    isolated_pool.add_new(generate_live_credentials(set()), "2026-01-02T00:00:00+00:00")

    resolved = main_module._resolve_devices(_body(devices_this_run=5, new_devices_count=0))

    origins = [origin for _, origin in resolved]
    assert origins.count("returning") == 2
    assert origins.count("new_autofilled") == 3
    assert len(resolved) == 5


def test_requested_new_devices_are_labeled_new_requested_not_autofilled(isolated_pool):
    resolved = main_module._resolve_devices(_body(devices_this_run=2, new_devices_count=2))

    origins = [origin for _, origin in resolved]
    assert origins == ["new_requested", "new_requested"]  # returning_count == 0


def test_new_requested_and_autofilled_never_collapse_into_the_same_label(isolated_pool):
    """Part 4's core requirement: a device the user explicitly asked to add
    (Control 2) must stay distinguishable from one the backend silently
    generated because the pool came up short."""
    isolated_pool.add_new(generate_live_credentials(set()), "2026-01-01T00:00:00+00:00")

    resolved = main_module._resolve_devices(_body(devices_this_run=4, new_devices_count=1))
    # returning_count = 4 - 1 = 3; pool has 1 -> shortfall of 2 autofilled.
    origins = [origin for _, origin in resolved]
    assert origins.count("returning") == 1
    assert origins.count("new_requested") == 1
    assert origins.count("new_autofilled") == 2


def test_invalid_subscriber_bypasses_the_pool_entirely(isolated_pool):
    isolated_pool.add_new(generate_live_credentials(set()), "2026-01-01T00:00:00+00:00")

    resolved = main_module._resolve_devices(
        _body(attack_scenario="invalid_subscriber", devices_this_run=3, new_devices_count=0)
    )

    assert len(resolved) == 3
    assert all(origin == "new_requested" for _, origin in resolved)
    # The pool must be completely untouched.
    assert len(isolated_pool.all()) == 1


def test_returning_devices_have_their_total_times_run_incremented(isolated_pool):
    creds = generate_live_credentials(set())
    isolated_pool.add_new(creds, "2026-01-01T00:00:00+00:00")
    assert isolated_pool.all()[0].total_times_run == 1

    main_module._resolve_devices(_body(devices_this_run=1, new_devices_count=0))

    assert isolated_pool.all()[0].total_times_run == 2


def test_resolved_credentials_are_mutually_distinct(isolated_pool):
    """No accidental collisions between a returning device's stored
    credentials and a freshly-generated device's random ones."""
    isolated_pool.add_new(generate_live_credentials(set()), "2026-01-01T00:00:00+00:00")

    resolved = main_module._resolve_devices(_body(devices_this_run=4, new_devices_count=2))
    imsis = [creds.imsi for creds, _ in resolved]
    assert len(imsis) == len(set(imsis))
