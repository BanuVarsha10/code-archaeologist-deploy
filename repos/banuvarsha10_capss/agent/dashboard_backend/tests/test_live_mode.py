"""Tests for dashboard_backend/live_mode.py's ORCHESTRATION LOGIC — failure
isolation, sequencing, credential freshness, config-file safety. These use
mocked subprocess/file calls throughout: there is no real gNB/MongoDB/
UERANSIM reachable from this environment, so real hardware execution is
NOT covered here — see live_mode.py's module docstring.
"""

import subprocess
from unittest.mock import patch, MagicMock

import pytest

from dashboard_backend import live_mode


def test_generate_live_credentials_are_fresh_and_well_formed():
    existing = set()
    creds1 = live_mode.generate_live_credentials(existing)
    creds2 = live_mode.generate_live_credentials(existing)

    assert creds1.imsi != creds2.imsi
    assert creds1.imsi.startswith("imsi-99970")
    assert len(creds1.key_hex) == 32
    assert len(creds1.opc_hex) == 32
    assert all(c in "0123456789ABCDEF" for c in creds1.key_hex)


def test_dbctl_add_subscriber_raises_on_nonzero_exit():
    creds = live_mode.LiveCredentials(imsi="imsi-999700000000001", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    fake_result = MagicMock(returncode=1, stdout="", stderr="mongo connection refused")

    with patch("pathlib.Path.exists", return_value=True), \
         patch.object(live_mode, "get_dbctl_slice", return_value=("1", "000001")), \
         patch("subprocess.run", return_value=fake_result):
        with pytest.raises(live_mode.LiveStepError, match="mongo connection refused"):
            live_mode.dbctl_add_subscriber(creds)


def test_dbctl_add_subscriber_raises_when_binary_missing():
    creds = live_mode.LiveCredentials(imsi="imsi-999700000000001", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch("pathlib.Path.exists", return_value=False):
        with pytest.raises(live_mode.LiveStepError, match="not found"):
            live_mode.dbctl_add_subscriber(creds)


def test_dbctl_add_subscriber_raises_on_timeout():
    creds = live_mode.LiveCredentials(imsi="imsi-999700000000001", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch("pathlib.Path.exists", return_value=True), \
         patch.object(live_mode, "get_dbctl_slice", return_value=("1", "000001")), \
         patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="open5gs-dbctl", timeout=15)):
        with pytest.raises(live_mode.LiveStepError, match="timed out"):
            live_mode.dbctl_add_subscriber(creds)


def test_get_dbctl_slice_reads_from_the_real_template_not_hardcoded(tmp_path):
    """Regression guard (this project's Part B, Issue 2): the sst/sd values
    must be read LIVE from UE_CONFIG_TEMPLATE, not a hardcoded constant that
    could silently drift out of sync with a real gNB/AMF config change —
    this exact failure mode ("Cannot find Requested NSSAI") was already hit
    once in this project from a config mismatch."""
    template = tmp_path / "open5gs-ue.yaml"
    template.write_text(
        "configured-nssai:\n  - sst: 7\n    sd: abcdef\n",
        encoding="utf-8",
    )
    with patch.object(live_mode, "UE_CONFIG_TEMPLATE", template):
        sst, sd = live_mode.get_dbctl_slice()
    assert (sst, sd) == ("7", "abcdef")


def test_generate_ue_config_substitutes_identity_and_never_overwrites(tmp_path):
    template = tmp_path / "open5gs-ue.yaml"
    template.write_text(
        "supi: 'imsi-999700000000001'\nkey: 'OLDKEY'\nop: 'OLDOP'\nmcc: '999'\n",
        encoding="utf-8",
    )
    generated_dir = tmp_path / "generated"
    creds = live_mode.LiveCredentials(
        imsi="imsi-999709999999999", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32,
    )

    with patch.object(live_mode, "UE_CONFIG_TEMPLATE", template), \
         patch.object(live_mode, "UE_CONFIG_GENERATED_DIR", generated_dir):
        path = live_mode.generate_ue_config(creds)
        text = path.read_text(encoding="utf-8")
        assert "imsi-999709999999999" in text
        assert "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" in text
        assert "mcc: '999'" in text  # untouched fields preserved

        # Second call for the SAME identity must refuse to overwrite.
        with pytest.raises(live_mode.LiveStepError, match="overwrite"):
            live_mode.generate_ue_config(creds)


def test_max_live_devices_is_twenty():
    """Part D: raised from 5 to 20 now that Live Mode is the dashboard's
    ONLY mode — the device slider is the primary control, not a secondary
    toggle hidden behind Normal Mode's old 20-device default."""
    assert live_mode.MAX_LIVE_DEVICES == 20


# ---------------------------------------------------------------------------
# provision_subscriber (Part F steps 1-3, now origin-aware — device-pool task)
# ---------------------------------------------------------------------------

_CREDS = live_mode.LiveCredentials(imsi="imsi-999700000000042", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)


def test_provision_subscriber_isolates_dbctl_failure():
    with patch.object(live_mode, "dbctl_add_subscriber", side_effect=live_mode.LiveStepError("mongo down")):
        outcome = live_mode.provision_subscriber("duplicate_registration", _CREDS, is_returning=False)

    assert outcome.success is False
    assert "mongo down" in outcome.failure_reason
    assert outcome.config_path is None


def test_provision_subscriber_skips_dbctl_for_invalid_subscriber():
    """invalid_subscriber deliberately never provisions a real subscriber —
    dbctl_add_subscriber must not even be called."""
    with patch.object(live_mode, "dbctl_add_subscriber") as mock_dbctl, \
         patch.object(live_mode, "generate_ue_config", return_value="fake_config.yaml"):
        outcome = live_mode.provision_subscriber("invalid_subscriber", _CREDS, is_returning=False)

    mock_dbctl.assert_not_called()
    assert outcome.success is True
    assert outcome.config_path == "fake_config.yaml"


def test_provision_subscriber_isolates_config_generation_failure():
    with patch.object(live_mode, "dbctl_add_subscriber", return_value=None), \
         patch.object(live_mode, "generate_ue_config", side_effect=live_mode.LiveStepError("Refusing to overwrite")):
        outcome = live_mode.provision_subscriber("replay", _CREDS, is_returning=False)

    assert outcome.success is False
    assert "Refusing to overwrite" in outcome.failure_reason


def test_provision_subscriber_returning_device_skips_dbctl_add():
    """Device-pool task: a RETURNING device is already provisioned in
    Open5GS's MongoDB from a prior session — dbctl add must not run again."""
    with patch.object(live_mode, "dbctl_add_subscriber") as mock_dbctl, \
         patch.object(live_mode, "config_path_for") as mock_path:
        mock_path.return_value.exists.return_value = True
        outcome = live_mode.provision_subscriber("duplicate_registration", _CREDS, is_returning=True)

    mock_dbctl.assert_not_called()
    assert outcome.success is True


def test_provision_subscriber_returning_device_reuses_existing_config():
    """A returning device's UE config from a prior session, if still
    present on disk, is reused as-is — generate_ue_config() must NOT be
    called (it would raise, since it refuses to overwrite anyway)."""
    with patch.object(live_mode, "config_path_for") as mock_path, \
         patch.object(live_mode, "generate_ue_config") as mock_generate:
        mock_path.return_value.exists.return_value = True
        outcome = live_mode.provision_subscriber("duplicate_registration", _CREDS, is_returning=True)

    mock_generate.assert_not_called()
    assert outcome.success is True
    assert outcome.config_path == mock_path.return_value


def test_provision_subscriber_returning_device_regenerates_missing_config():
    """Defensive fallback: if a returning device's config file from a prior
    session is missing (e.g. a fresh environment), it's regenerated
    deterministically from the SAME stored creds rather than failing."""
    with patch.object(live_mode, "config_path_for") as mock_path, \
         patch.object(live_mode, "generate_ue_config", return_value="regenerated.yaml") as mock_generate:
        mock_path.return_value.exists.return_value = False
        outcome = live_mode.provision_subscriber("duplicate_registration", _CREDS, is_returning=True)

    mock_generate.assert_called_once_with(_CREDS)
    assert outcome.success is True
    assert outcome.config_path == "regenerated.yaml"


# ---------------------------------------------------------------------------
# Registration event primitives (Part F steps 4, 8, 10)
# ---------------------------------------------------------------------------

def test_run_baseline_registration_launches_exactly_once():
    creds = live_mode.LiveCredentials(imsi="imsi-x", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "launch_nr_ue_once") as mock_launch:
        outcome = live_mode.run_baseline_registration("cfg.yaml", creds)

    assert outcome.success is True
    assert outcome.launch_count == 1
    mock_launch.assert_called_once()


def test_run_baseline_registration_isolates_timeout():
    creds = live_mode.LiveCredentials(imsi="imsi-x", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "launch_nr_ue_once", side_effect=live_mode.LiveStepError("timeout")):
        outcome = live_mode.run_baseline_registration("cfg.yaml", creds)

    assert outcome.success is False
    assert "timeout" in outcome.failure_reason


def test_run_attack_registration_flooding_launches_six_times():
    creds = live_mode.LiveCredentials(imsi="imsi-x", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "launch_nr_ue_once") as mock_launch:
        outcome = live_mode.run_attack_registration("cfg.yaml", creds, "flooding")

    assert outcome.success is True
    assert outcome.launch_count == 6
    assert mock_launch.call_count == 6


def test_run_attack_registration_duplicate_launches_twice_with_sleep():
    creds = live_mode.LiveCredentials(imsi="imsi-x", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "launch_nr_ue_once") as mock_launch, \
         patch("time.sleep") as mock_sleep:
        outcome = live_mode.run_attack_registration("cfg.yaml", creds, "duplicate_registration")

    assert outcome.launch_count == 2
    assert mock_launch.call_count == 2
    mock_sleep.assert_called_once_with(3.0)


def test_run_attack_registration_invalid_subscriber_launches_once():
    creds = live_mode.LiveCredentials(imsi="imsi-x", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "launch_nr_ue_once") as mock_launch:
        outcome = live_mode.run_attack_registration("cfg.yaml", creds, "invalid_subscriber")

    assert outcome.launch_count == 1
    mock_launch.assert_called_once()


def test_run_stability_replay_registration_repeats_the_same_pattern_as_attack():
    """Part F step 10: a stability replay for a multi-launch scenario is
    the SAME multi-launch burst, not a single bare launch — a lone extra
    launch would not reliably reproduce Systems' original classification."""
    creds = live_mode.LiveCredentials(imsi="imsi-x", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "launch_nr_ue_once") as mock_launch:
        outcome = live_mode.run_stability_replay_registration("cfg.yaml", creds, "flooding", 1)

    assert outcome.launch_count == 6
    assert mock_launch.call_count == 6


def test_provision_subscriber_emits_real_stage_events():
    creds = live_mode.LiveCredentials(imsi="imsi-999700000000099", suci="suci-y", key_hex="A" * 32, opc_hex="B" * 32)
    events = []
    with patch.object(live_mode, "dbctl_add_subscriber", return_value=None), \
         patch.object(live_mode, "generate_ue_config", return_value="fake_config.yaml"):
        live_mode.provision_subscriber(
            "duplicate_registration", creds, is_returning=False, on_stage=lambda stage, data: events.append(stage),
        )
    assert events == ["credentials_ready", "adding_subscriber", "subscriber_added", "generating_config", "config_ready"]


def test_provision_subscriber_returning_device_emits_reuse_stage_events():
    creds = live_mode.LiveCredentials(imsi="imsi-999700000000100", suci="suci-z", key_hex="A" * 32, opc_hex="B" * 32)
    events = []
    with patch.object(live_mode, "config_path_for") as mock_path:
        mock_path.return_value.exists.return_value = True
        live_mode.provision_subscriber(
            "duplicate_registration", creds, is_returning=True, on_stage=lambda stage, data: events.append(stage),
        )
    assert events == ["credentials_ready", "reusing_subscriber", "config_reused"]


def test_run_baseline_registration_emits_real_stage_events():
    creds = live_mode.LiveCredentials(imsi="imsi-x", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    events = []
    with patch.object(live_mode, "launch_nr_ue_once"):
        live_mode.run_baseline_registration("cfg.yaml", creds, on_stage=lambda stage, data: events.append(stage))
    assert events == ["launching_ue", "ue_registered"]


def test_run_stability_replay_registration_isolates_failure():
    creds = live_mode.LiveCredentials(imsi="imsi-x", suci="suci-x", key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "launch_nr_ue_once", side_effect=live_mode.LiveStepError("registration not observed")):
        outcome = live_mode.run_stability_replay_registration("cfg.yaml", creds, "replay", 2)

    assert outcome.success is False
    assert "registration not observed" in outcome.failure_reason


# ---------------------------------------------------------------------------
# _wait_for_registration_in_log / _registration_completed_for (regression
# guard: confirmed directly against a real run that matching on bare
# IMSI/SUCI presence — the previous behavior — killed nr-ue mid-
# registration, before authentication/security-mode/accept finished,
# causing real "Holding NG context already exists" / "GUTI has already
# been allocated" / "Cannot find AMF-UE Context" collisions when the next
# launch started immediately after. Must now require the same
# "Registration complete" marker logging/parse_amf_logs.py treats as
# authoritative, scoped to THIS device's most recent attempt.)
# ---------------------------------------------------------------------------

IMSI = "imsi-999709999991234"
SUCI = "suci-0-999-70-0000-0-0-9999991234"


def test_registration_completed_for_requires_the_completion_marker():
    early_log = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        "08/06 13:45:49.102: [gmm] INFO: Authentication Request\n"
    )
    assert live_mode._registration_completed_for(early_log, IMSI, SUCI) is False


def test_registration_completed_for_true_once_the_marker_appears():
    completed_log = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        "08/06 13:45:49.150: [gmm] INFO: Authentication successful\n"
        "08/06 13:45:49.200: [gmm] INFO: Registration complete\n"
    )
    assert live_mode._registration_completed_for(completed_log, IMSI, SUCI) is True


def test_registration_completed_for_does_not_leak_across_devices():
    """The exact bug this fix targets: a DIFFERENT device's InitialUEMessage
    (and its own eventual "Registration complete") must never count as
    completion for the device we're actually waiting on."""
    other_device_log = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        "08/06 13:45:49.150: [gmm] INFO: Authentication successful\n"
        "08/06 13:45:49.300: [amf] INFO: InitialUEMessage\n"  # a DIFFERENT device's attempt starts
        "08/06 13:45:49.301: [amf] INFO: [suci-other-device] known UE by SUCI\n"
        "08/06 13:45:49.400: [gmm] INFO: Registration complete\n"  # belongs to the OTHER device
    )
    assert live_mode._registration_completed_for(other_device_log, IMSI, SUCI) is False


def test_registration_completed_for_ignores_a_stale_earlier_attempt():
    """Stability replays reuse the SAME creds across many launches — an
    earlier launch's "Registration complete" must not satisfy a LATER
    launch's wait; only the identity's MOST RECENT block matters."""
    stale_then_fresh = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        "08/06 13:45:49.200: [gmm] INFO: Registration complete\n"  # first (earlier) launch, already consumed
        "08/06 13:46:10.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:46:10.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"  # second launch begins
        "08/06 13:46:10.150: [gmm] INFO: Authentication successful\n"
        # no "Registration complete" yet for THIS (second) attempt
    )
    assert live_mode._registration_completed_for(stale_then_fresh, IMSI, SUCI) is False


def test_registration_completed_for_survives_later_unrelated_activity_in_the_same_block():
    """Regression guard for the REAL bug found in production: Open5GS logs
    later, unrelated PDU-session housekeeping lines
    (nsmf-pdusession/.../modify) that also mention the IMSI, AFTER
    "Registration complete" already happened — confirmed directly: a real
    registration completed successfully but was reported as a false
    timeout because an earlier version of this scoping searched from the
    identity's LAST mention in the whole log (which landed on the later,
    irrelevant housekeeping line), not from the InitialUEMessage block
    boundary. No new InitialUEMessage appears here, so this later activity
    is still part of the SAME block and must not hide the completion."""
    real_shape_log = (
        "08/06 17:14:56.903: [amf] INFO: InitialUEMessage\n"
        f"08/06 17:14:56.903: [amf] INFO: [{SUCI}] Unknown UE by SUCI\n"
        "08/06 17:14:56.909: [gmm] WARNING: Authentication failure(Synch failure[count=0])\n"
        f"08/06 17:14:57.148: [gmm] INFO: [{IMSI}] Registration complete\n"
        f"08/06 17:14:57.170: [amf] INFO: [{IMSI}:1:11][0:0:NULL] /nsmf-pdusession/v1/sm-contexts/modify\n"
        f"08/06 17:15:17.463: [amf] INFO: [{IMSI}:1:13][0:0:NULL] /nsmf-pdusession/v1/sm-contexts/modify\n"
    )
    assert live_mode._registration_completed_for(real_shape_log, IMSI, SUCI) is True


def test_registration_completed_for_still_excludes_other_devices_after_the_fix():
    """The fix above must not regress the original leak-across-devices
    guard: a LATER device's own InitialUEMessage still starts a genuinely
    new block that must not be attributed to us."""
    other_device_after = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        "08/06 13:45:49.150: [gmm] INFO: Authentication successful\n"
        "08/06 13:45:49.300: [amf] INFO: InitialUEMessage\n"  # a DIFFERENT device's attempt starts
        "08/06 13:45:49.301: [amf] INFO: [suci-other-device] known UE by SUCI\n"
        "08/06 13:45:49.400: [gmm] INFO: Registration complete\n"  # belongs to the OTHER device
    )
    assert live_mode._registration_completed_for(other_device_after, IMSI, SUCI) is False


def test_last_cause_for_extracts_the_real_rejection_reason():
    rejected_log = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        "08/06 13:45:49.200: [gmm] WARNING: Registration reject [Cause(Requested NSSAI not supported)]\n"
    )
    assert live_mode._last_cause_for(rejected_log, IMSI, SUCI) == "Requested NSSAI not supported"


def test_last_cause_for_none_when_no_cause_present():
    log = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
    )
    assert live_mode._last_cause_for(log, IMSI, SUCI) is None


def test_wait_for_registration_in_log_ignores_stale_completion_before_known_before(tmp_path):
    """Regression guard for the REAL bug found in production: for a multi-
    launch attack pattern (e.g. duplicate_registration's 2 launches), the
    FIRST launch's own registration never actually completed on the
    network (real evidence: "Holding NG Context" -> "Release SM context",
    no "Registration complete") — but the wait STILL reported success,
    because its very first poll caught the log before this launch had
    written anything of its own, fell back to _last_block_for's normal
    "most recent block containing this identity" search, and found the
    STALE "Registration complete" from this SAME device's EARLIER
    (baseline) launch instead. `known_before` must make that impossible:
    only content written AFTER this launch started can ever count."""
    log_path = tmp_path / "amf.log"
    stale_baseline = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        f"08/06 13:45:49.200: [gmm] INFO: [{IMSI}] Registration complete\n"
    )
    log_path.write_text(stale_baseline, encoding="utf-8")
    known_before = len(stale_baseline)  # captured "before this launch started"

    # The new launch has started (a new InitialUEMessage/SUCI line exists)
    # but genuinely never reaches "Registration complete" — exactly the
    # real network behavior observed (collided with the still-live prior
    # context, released without completing).
    incomplete_new_attempt = (
        "08/06 13:45:49.803: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.803: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        "08/06 13:45:49.803: [amf] WARNING: Holding NG Context\n"
        f"08/06 13:45:49.810: [amf] INFO: [{IMSI}:1] Release SM context [204]\n"
    )
    log_path.write_text(stale_baseline + incomplete_new_attempt, encoding="utf-8")

    creds = live_mode.LiveCredentials(imsi=IMSI, suci=SUCI, key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "AMF_LOG_PATH", log_path), \
         patch.object(live_mode.time, "sleep"):
        completed, cause = live_mode._wait_for_registration_in_log(creds, timeout=1, known_before=known_before)

    assert completed is False, (
        "matched the STALE prior-launch completion instead of correctly waiting for "
        "THIS launch's own (never-arriving) Registration complete"
    )


def test_wait_for_registration_in_log_still_detects_a_genuine_new_completion(tmp_path):
    """Sanity check alongside the guard above: a real NEW completion after
    known_before must still be detected — the fix must not make every
    subsequent launch un-detectable."""
    log_path = tmp_path / "amf.log"
    stale_baseline = (
        "08/06 13:45:49.100: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:49.101: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        f"08/06 13:45:49.200: [gmm] INFO: [{IMSI}] Registration complete\n"
    )
    known_before = len(stale_baseline)
    genuine_new_completion = (
        "08/06 13:45:53.267: [amf] INFO: InitialUEMessage\n"
        f"08/06 13:45:53.267: [amf] INFO: [{SUCI}] known UE by SUCI\n"
        f"08/06 13:45:53.498: [gmm] INFO: [{IMSI}] Registration complete\n"
    )
    log_path.write_text(stale_baseline + genuine_new_completion, encoding="utf-8")

    creds = live_mode.LiveCredentials(imsi=IMSI, suci=SUCI, key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "AMF_LOG_PATH", log_path), \
         patch.object(live_mode.time, "sleep"):
        completed, cause = live_mode._wait_for_registration_in_log(creds, timeout=5, known_before=known_before)

    assert completed is True


def test_launch_nr_ue_once_captures_known_before_before_spawning_nr_ue(tmp_path):
    """launch_nr_ue_once must read the log's current length BEFORE
    spawning nr-ue, not after — capturing it too late would reopen the
    exact race this fix closes."""
    log_path = tmp_path / "amf.log"
    log_path.write_text("existing content\n", encoding="utf-8")
    creds = live_mode.LiveCredentials(imsi=IMSI, suci=SUCI, key_hex="A" * 32, opc_hex="B" * 32)

    captured = {}

    def fake_wait(creds_, timeout, known_before=0):
        captured["known_before"] = known_before
        return True, None

    with patch.object(live_mode, "AMF_LOG_PATH", log_path), \
         patch.object(live_mode, "NR_UE_BIN") as mock_bin, \
         patch("subprocess.Popen"), \
         patch.object(live_mode, "_wait_for_registration_in_log", side_effect=fake_wait), \
         patch.object(live_mode, "_terminate_nr_ue"):
        mock_bin.exists.return_value = True
        live_mode.launch_nr_ue_once(str(log_path), creds, timeout=1)

    assert captured["known_before"] == len("existing content\n")


def test_wait_for_registration_in_log_returns_true_once_complete(tmp_path):
    log_path = tmp_path / "amf.log"
    log_path.write_text(
        f"InitialUEMessage\n[{SUCI}] known UE by SUCI\nRegistration complete\n", encoding="utf-8",
    )
    creds = live_mode.LiveCredentials(imsi=IMSI, suci=SUCI, key_hex="A" * 32, opc_hex="B" * 32)

    with patch.object(live_mode, "AMF_LOG_PATH", log_path), \
         patch.object(live_mode.time, "sleep"):
        completed, cause = live_mode._wait_for_registration_in_log(creds, timeout=5)

    assert completed is True
    assert cause is None


def test_wait_for_registration_in_log_times_out_with_real_cause(tmp_path):
    log_path = tmp_path / "amf.log"
    log_path.write_text(
        f"InitialUEMessage\n[{SUCI}] known UE by SUCI\n"
        "Registration reject [Cause(Requested NSSAI not supported)]\n",
        encoding="utf-8",
    )
    creds = live_mode.LiveCredentials(imsi=IMSI, suci=SUCI, key_hex="A" * 32, opc_hex="B" * 32)

    # timeout=1 with a no-op sleep: guarantees the loop body runs (reading
    # the log) at least once before the deadline naturally elapses,
    # without the test actually waiting.
    with patch.object(live_mode, "AMF_LOG_PATH", log_path), \
         patch.object(live_mode.time, "sleep"):
        completed, cause = live_mode._wait_for_registration_in_log(creds, timeout=1)

    assert completed is False
    assert cause == "Requested NSSAI not supported"


def test_launch_nr_ue_once_includes_real_cause_in_timeout_error():
    creds = live_mode.LiveCredentials(imsi=IMSI, suci=SUCI, key_hex="A" * 32, opc_hex="B" * 32)
    with patch.object(live_mode, "NR_UE_BIN") as mock_bin, \
         patch("subprocess.Popen"), \
         patch.object(live_mode, "_wait_for_registration_in_log", return_value=(False, "Requested NSSAI not supported")), \
         patch.object(live_mode, "_terminate_nr_ue"):
        mock_bin.exists.return_value = True
        with pytest.raises(live_mode.LiveStepError, match="Requested NSSAI not supported"):
            live_mode.launch_nr_ue_once("cfg.yaml", creds, timeout=1)
