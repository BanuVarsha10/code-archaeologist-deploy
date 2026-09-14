"""Tests for dashboard_backend/device_pool.py's persistence layer (device-
pool task, Parts 1, 3, 6): cross-session persistence, Part 3's return-order
preference, and the 20-device-cap eviction rule stated in add_new()'s
docstring — fewest total_times_run evicted first, ties broken by oldest
first_seen."""

from dashboard_backend.device_pool import DevicePool
from dashboard_backend.live_mode import LiveCredentials, MAX_LIVE_DEVICES


def _creds(n: int) -> LiveCredentials:
    msin = str(n).zfill(10)
    return LiveCredentials(
        imsi=f"imsi-99970{msin}", suci=f"suci-0-999-70-0000-0-0-{msin}", key_hex="A" * 32, opc_hex="B" * 32,
    )


def test_pool_persists_across_two_separate_sessions(tmp_path):
    """A device added by one DevicePool instance (session 1) must be
    visible to a SECOND, independently-constructed DevicePool instance
    pointed at the same file (session 2) — this is what makes reuse work
    across actual dashboard restarts, not just within one process."""
    path = tmp_path / "pool.json"

    session1 = DevicePool(path)
    session1.add_new(_creds(1), "2026-01-01T00:00:00+00:00")

    session2 = DevicePool(path)
    devices = session2.all()
    assert len(devices) == 1
    assert devices[0].imsi == _creds(1).imsi
    assert devices[0].total_times_run == 1

    session2.record_run(devices[0].imsi)

    session3 = DevicePool(path)
    assert session3.all()[0].total_times_run == 2


def test_select_returning_prefers_most_prior_history_first():
    """Part 3: devices with more total_times_run come first, regardless of
    insertion order."""
    pool = DevicePool(path=__import__("pathlib").Path("/dev/null"))  # never saved in this test
    # Build state directly to control total_times_run precisely.
    from dashboard_backend.device_pool import PoolDevice
    devices = [
        PoolDevice(imsi=_creds(1).imsi, suci=_creds(1).suci, key_hex="A" * 32, opc_hex="B" * 32,
                   first_seen="2026-01-01T00:00:00+00:00", total_times_run=1),
        PoolDevice(imsi=_creds(2).imsi, suci=_creds(2).suci, key_hex="A" * 32, opc_hex="B" * 32,
                   first_seen="2026-01-02T00:00:00+00:00", total_times_run=5),
        PoolDevice(imsi=_creds(3).imsi, suci=_creds(3).suci, key_hex="A" * 32, opc_hex="B" * 32,
                   first_seen="2026-01-03T00:00:00+00:00", total_times_run=3),
    ]
    pool._save = lambda _d: None  # never actually write /dev/null
    pool._load = lambda: devices

    top_two = pool.select_returning(2)
    assert [d.imsi for d in top_two] == [_creds(2).imsi, _creds(3).imsi]


def test_select_returning_tie_broken_by_oldest_first_seen():
    from dashboard_backend.device_pool import PoolDevice
    pool = DevicePool(path=__import__("pathlib").Path("/dev/null"))
    devices = [
        PoolDevice(imsi=_creds(1).imsi, suci=_creds(1).suci, key_hex="A" * 32, opc_hex="B" * 32,
                   first_seen="2026-01-05T00:00:00+00:00", total_times_run=2),
        PoolDevice(imsi=_creds(2).imsi, suci=_creds(2).suci, key_hex="A" * 32, opc_hex="B" * 32,
                   first_seen="2026-01-01T00:00:00+00:00", total_times_run=2),
    ]
    pool._save = lambda _d: None
    pool._load = lambda: devices

    top = pool.select_returning(1)
    assert top[0].imsi == _creds(2).imsi  # older first_seen wins the tie


def test_select_returning_returns_fewer_than_requested_when_pool_is_short(tmp_path):
    pool = DevicePool(tmp_path / "pool.json")
    pool.add_new(_creds(1), "2026-01-01T00:00:00+00:00")

    result = pool.select_returning(5)
    assert len(result) == 1


def test_add_new_evicts_fewest_total_times_run_first_at_cap(tmp_path):
    """The stated eviction rule (device-pool task, Part 6): when adding a
    device would exceed MAX_LIVE_DEVICES, the entry with the FEWEST
    total_times_run is evicted first — never the device just being added."""
    pool = DevicePool(tmp_path / "pool.json")
    from dashboard_backend.device_pool import PoolDevice

    # Fill to the cap directly, with device 0 deliberately least-used.
    full = [
        PoolDevice(imsi=_creds(i).imsi, suci=_creds(i).suci, key_hex="A" * 32, opc_hex="B" * 32,
                   first_seen=f"2026-01-{i + 1:02d}T00:00:00+00:00", total_times_run=(1 if i == 0 else 10))
        for i in range(MAX_LIVE_DEVICES)
    ]
    pool._save(full)

    pool.add_new(_creds(999), "2026-06-01T00:00:00+00:00")

    imsis = {d.imsi for d in pool.all()}
    assert len(imsis) == MAX_LIVE_DEVICES  # still capped
    assert _creds(0).imsi not in imsis  # the least-used entry was evicted
    assert _creds(999).imsi in imsis     # the new device was NOT the one evicted


def test_add_new_eviction_tie_broken_by_oldest_first_seen(tmp_path):
    pool = DevicePool(tmp_path / "pool.json")
    from dashboard_backend.device_pool import PoolDevice

    full = [
        PoolDevice(imsi=_creds(i).imsi, suci=_creds(i).suci, key_hex="A" * 32, opc_hex="B" * 32,
                   # devices 0 and 1 tie on total_times_run=1; device 0 is older.
                   first_seen=("2026-01-01T00:00:00+00:00" if i == 0 else f"2026-02-{i + 1:02d}T00:00:00+00:00"),
                   total_times_run=(1 if i in (0, 1) else 10))
        for i in range(MAX_LIVE_DEVICES)
    ]
    pool._save(full)

    pool.add_new(_creds(999), "2026-06-01T00:00:00+00:00")

    imsis = {d.imsi for d in pool.all()}
    assert _creds(0).imsi not in imsis  # older of the tied pair evicted
    assert _creds(1).imsi in imsis


def test_remove_returns_false_for_unknown_imsi(tmp_path):
    pool = DevicePool(tmp_path / "pool.json")
    assert pool.remove("imsi-does-not-exist") is False


def test_remove_removes_only_the_named_device(tmp_path):
    pool = DevicePool(tmp_path / "pool.json")
    pool.add_new(_creds(1), "2026-01-01T00:00:00+00:00")
    pool.add_new(_creds(2), "2026-01-02T00:00:00+00:00")

    assert pool.remove(_creds(1).imsi) is True
    remaining = {d.imsi for d in pool.all()}
    assert remaining == {_creds(2).imsi}
