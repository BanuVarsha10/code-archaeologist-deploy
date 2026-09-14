"""dashboard_backend/live_mode.py

Live Mode — the dashboard's ONLY mode (Normal/synthetic mode was removed;
every run below is real). Real Open5GS/UERANSIM orchestration per real
device, exposed as small granular primitives that pipeline_service.py's
run_live_device() composes into the 13-step real per-device flow:
    1. Generate a fresh IMSI + real random K/OPC.
    2. Add the subscriber to the real Open5GS MongoDB via open5gs-dbctl.
    3. Generate a matching UE YAML config to a NEW file (never overwrite).
       (1-3: provision_subscriber())
    4. BASELINE: launch nr-ue once, normal (non-attack) timing.
       (run_baseline_registration())
    8. ATTACK: launch nr-ue per the scenario's real attack-timing pattern
       (single launch, or the multi-launch bursts flooding/duplicate_
       registration/replay/mixed need to actually trigger Systems'
       detectors). (run_attack_registration())
   10. STABILITY: 3 more REAL repetitions of that same attack-timing
       pattern. (run_stability_replay_registration())
    *. Parse the real AMF log via logging/parse_amf_logs.py (reused
       exactly as-is, as a subprocess — see that file's own docstring for
       why it can't be safely imported) to get a device's real
       RegistrationRequest(s) — called cumulatively; callers slice off
       the newly-added entries after each registration event.

Devices are processed strictly SEQUENTIALLY (never concurrently). One
device's failure at ANY step (dbctl add fails, nr-ue times out, log
parsing finds nothing) is caught and marked as a failure for that device
only — it does not abort the batch (Part F step 13).

STATUS: tested against a real gNB/AMF/MongoDB/UERANSIM stack on
2026-08-04, against the PRE-restructuring single-pass flow. Bugs found and
fixed during that testing: AMF_LOG_PATH's default pointed at a file that
never existed on a real install (fixed to the real
/var/log/open5gs/amf.log); dbctl_add_subscriber() used plain "add" which
leaves the subscriber's slice/APN unset, causing a real "Cannot find
Requested NSSAI" rejection (fixed to add_ue_with_slice, then to read the
slice live via get_dbctl_slice() instead of a hardcoded duplicate);
parse_amf_log_for_device() shelled out to a bare "python", which resolved
to a non-executable Windows interop stub in a WSL PATH (fixed to
sys.executable, plus a defensive OSError catch so a broken interpreter
path fails that one device cleanly instead of crashing the batch). The
granular primitives below (provision_subscriber /
run_baseline_registration / run_attack_registration /
run_stability_replay_registration) are a restructuring of that
already-tested single-pass flow's exact same launch logic — NOT
independently re-verified against real hardware yet. Multi-launch timing
for replay's 2s window remains a known open risk. A stability check for a
multi-launch scenario (e.g. flooding) means 3 MORE full 6-launch bursts,
not 3 single launches — see run_stability_replay_registration()'s
docstring for why, and treat per-device time estimates accordingly.
"""

from __future__ import annotations

import dataclasses
import os
import re
import secrets
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from systems.pre_amf.models import RegistrationRequest
from systems.pre_amf.registration_loader import RegistrationLoader

from dashboard_backend.identity_gen import UEIdentity

# ---------------------------------------------------------------------------
# Hard cap (named constant per the spec — never exceeded). Raised from 5 to
# 20 (Part D): the old value existed only because Live Mode used to be a
# secondary, hidden toggle behind Normal Mode's default 20-device population
# — now that Live Mode is the ONLY mode, the device slider is the primary
# control and should offer the same range Normal Mode always did.
# ---------------------------------------------------------------------------
MAX_LIVE_DEVICES = 20

# ---------------------------------------------------------------------------
# Paths — mirror the exact conventions already used in this project.
# ---------------------------------------------------------------------------
AGENT_ROOT = Path(__file__).resolve().parent.parent  # .../5g-project/agent
UERANSIM_ROOT = Path.home() / "5g-project" / "UERANSIM"
NR_UE_BIN = UERANSIM_ROOT / "build" / "nr-ue"
UE_CONFIG_TEMPLATE = UERANSIM_ROOT / "config" / "open5gs-ue.yaml"
UE_CONFIG_GENERATED_DIR = UERANSIM_ROOT / "config" / "generated"

# ASSUMPTION (untested — adjust if your Open5GS source lives elsewhere):
# a source checkout was found at ~/open5gs-src during this project's setup;
# open5gs-dbctl lives at misc/db/open5gs-dbctl in a standard Open5GS tree.
OPEN5GS_DBCTL = Path.home() / "open5gs-src" / "misc" / "db" / "open5gs-dbctl"

# CONFIRMED (2026-08-04, against this project's real Open5GS install):
# logging/parse_amf_logs.py's own default ("logging/raw_logs/amf.log")
# does not exist anywhere — that path is for a manually-copied log
# snapshot, not where the real open5gs-amfd daemon actually writes.
# Real path per /etc/open5gs/amf.yaml's logger.file.path, world-readable
# (no sudo needed to read it). CAPSS_LOG_FILE still overrides if set.
AMF_LOG_PATH = Path(os.environ.get("CAPSS_LOG_FILE", "/var/log/open5gs/amf.log"))
REGISTRATION_DATASET_CSV = AGENT_ROOT / "datasets" / "registration_dataset.csv"

# Fixed only — the APN name isn't part of the sst/sd mismatch failure mode
# this project already hit (see get_dbctl_slice() below), and every UE
# config in this project uses "internet".
DBCTL_APN = "internet"


def get_dbctl_slice() -> tuple[str, str]:
    """Returns (sst, sd) read LIVE from UE_CONFIG_TEMPLATE's own
    configured-nssai block — NOT a hardcoded duplicate.

    UE_CONFIG_TEMPLATE (UERANSIM/config/open5gs-ue.yaml) is the one file
    that must ALREADY agree with the real gNB (config/open5gs-gnb.yaml)
    and real AMF (/etc/open5gs/amf.yaml) for ANY registration — real or
    synthetic — to succeed at all; it is not a new source of truth, it is
    the existing one this whole project already depends on. A previously
    hardcoded sst/sd constant here could silently drift out of sync with
    it after a gNB/AMF config change (this exact failure mode —
    "Cannot find Requested NSSAI" — was already hit and fixed once in this
    project by making gNB/AMF/UE configs agree). Reading it live from the
    same file generate_ue_config() already copies per device means dbctl
    provisioning and the UE's own request can never disagree.
    """
    if not UE_CONFIG_TEMPLATE.exists():
        raise LiveStepError(f"UE config template not found at {UE_CONFIG_TEMPLATE}")
    text = UE_CONFIG_TEMPLATE.read_text(encoding="utf-8")
    match = re.search(
        r"configured-nssai:\s*\n\s*-\s*sst:\s*(\d+)\s*\n\s*sd:\s*(\S+)",
        text,
    )
    if not match:
        raise LiveStepError(
            f"Could not find a configured-nssai: sst/sd entry in {UE_CONFIG_TEMPLATE} — "
            f"cannot provision a subscriber without knowing which slice to use."
        )
    return match.group(1), match.group(2)

# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------
DBCTL_TIMEOUT_SECONDS = 15
REGISTRATION_TIMEOUT_SECONDS = 20
LOG_PARSE_TIMEOUT_SECONDS = 30
LOG_POLL_INTERVAL_SECONDS = 1


class LiveStepError(Exception):
    """Raised by any Live Mode step; message is the failure reason shown to the UI."""


@dataclass
class LiveCredentials:
    imsi: str
    suci: str
    key_hex: str
    opc_hex: str


def generate_live_credentials(existing_msins: set) -> LiveCredentials:
    """Fresh IMSI (project's PLMN 999-70 convention) + real random 16-byte
    K/OPC, matching the exact hex-string format UERANSIM's config expects
    (see UERANSIM/config/open5gs-ue.yaml: 32 uppercase hex chars each)."""
    while True:
        msin = str(secrets.randbelow(9_000_000_000) + 1_000_000_000).zfill(10)
        if msin not in existing_msins:
            existing_msins.add(msin)
            break
    imsi = f"imsi-99970{msin}"
    suci = f"suci-0-999-70-0000-0-0-{msin}"
    key_hex = secrets.token_hex(16).upper()
    opc_hex = secrets.token_hex(16).upper()
    return LiveCredentials(imsi=imsi, suci=suci, key_hex=key_hex, opc_hex=opc_hex)


def _current_log_length() -> int:
    """The real AMF log's current length in characters. This is the exact
    same offset-capture snippet _wait_for_registration_in_log()'s
    known_before has always relied on (see launch_nr_ue_once()) — pulled
    out into its own function so there is exactly one definition, reused
    by both that per-launch polling offset AND
    _capture_device_log_offset() below (per-device parse-scoping offset)
    — the same real mechanism serving two different real purposes, never
    duplicated as two slightly-different implementations."""
    if not AMF_LOG_PATH.exists():
        return 0
    try:
        return len(AMF_LOG_PATH.read_text(encoding="utf-8", errors="ignore"))
    except OSError:
        return 0


# parse_amf_log_for_device()'s unbounded-whole-log-reprocessing fix: for
# each UE, the real AMF log's length immediately BEFORE that device's
# CURRENT run's first real registration step began — captured in
# provision_subscriber() (the one call every scenario type, including
# invalid_subscriber, always makes exactly once per device per run,
# before any real registration happens). parse_amf_log_for_device() reads
# this back to scope its own scan to "since this device's own activity
# began this run" instead of the entire cumulative session log.
#
# Keyed by IMSI and OVERWRITTEN (not "set once") on every
# provision_subscriber() call so a RETURNING device reused later in the
# same long-running backend process gets a fresh, small window for its
# NEW run — never an ever-growing one back to the first time that device
# was ever seen. Module-level, process-lifetime state; memory cost is one
# small int per UE ever provisioned this process's lifetime — negligible
# (this fixes a per-call TIME cost that grew with session length, not a
# memory concern).
_device_log_offset: Dict[str, int] = {}


def _capture_device_log_offset(creds: LiveCredentials) -> None:
    _device_log_offset[creds.imsi] = _current_log_length()


def dbctl_add_subscriber(creds: LiveCredentials) -> None:
    """Adds the subscriber to the real Open5GS MongoDB via open5gs-dbctl,
    WITH the same slice/APN the UE config template requests (add_ue_with_slice)
    — plain "add" leaves the subscriber without slice/APN info, which the
    real AMF then rejects with "Cannot find Requested NSSAI" (confirmed
    directly). Raises LiveStepError on any failure — caller marks this
    device failed and moves on (never aborts the batch)."""
    if not OPEN5GS_DBCTL.exists():
        raise LiveStepError(f"open5gs-dbctl not found at {OPEN5GS_DBCTL}")
    sst, sd = get_dbctl_slice()
    try:
        result = subprocess.run(
            [
                str(OPEN5GS_DBCTL), "add_ue_with_slice",
                creds.imsi.replace("imsi-", ""), creds.key_hex, creds.opc_hex,
                DBCTL_APN, sst, sd,
            ],
            capture_output=True,
            text=True,
            timeout=DBCTL_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise LiveStepError(f"open5gs-dbctl add_ue_with_slice timed out after {DBCTL_TIMEOUT_SECONDS}s") from exc
    except OSError as exc:
        raise LiveStepError(f"open5gs-dbctl add_ue_with_slice failed to launch: {exc}") from exc

    if result.returncode != 0:
        raise LiveStepError(
            f"open5gs-dbctl add_ue_with_slice exited {result.returncode}: "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def config_path_for(creds: LiveCredentials) -> Path:
    """The deterministic path generate_ue_config() writes to for these
    credentials — split out so provision_subscriber() can check whether a
    RETURNING device's config from a prior session is still present
    WITHOUT generating anything (device-pool task)."""
    msin = creds.imsi[-10:]
    return UE_CONFIG_GENERATED_DIR / f"dashboard_live_{msin}.yaml"


def generate_ue_config(creds: LiveCredentials) -> Path:
    """Writes a NEW UE YAML config (never overwrites an existing one),
    copying every field from UERANSIM/config/open5gs-ue.yaml unchanged
    except supi/key/op, which are substituted for this device."""
    if not UE_CONFIG_TEMPLATE.exists():
        raise LiveStepError(f"UE config template not found at {UE_CONFIG_TEMPLATE}")

    template_text = UE_CONFIG_TEMPLATE.read_text(encoding="utf-8")
    generated = re.sub(r"^supi:.*$", f"supi: '{creds.imsi}'", template_text, count=1, flags=re.MULTILINE)
    generated = re.sub(r"^key:.*$", f"key: '{creds.key_hex}'", generated, count=1, flags=re.MULTILINE)
    generated = re.sub(r"^op:.*$", f"op: '{creds.opc_hex}'", generated, count=1, flags=re.MULTILINE)

    UE_CONFIG_GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    config_path = config_path_for(creds)
    if config_path.exists():
        raise LiveStepError(f"Refusing to overwrite existing config: {config_path}")
    config_path.write_text(generated, encoding="utf-8")
    return config_path


_CAUSE_RE = re.compile(r"[Cc]ause[\[\(]([^\]\)]+)[\]\)]")


def _find_blocks(log_text: str) -> List[tuple[int, int]]:
    """(start, end) char-offset pairs for each InitialUEMessage-delimited
    block, mirroring logging/parse_amf_logs.py's own state machine exactly
    — each InitialUEMessage starts a new registration attempt's block; the
    block runs until the next InitialUEMessage (or EOF)."""
    starts = [m.start() for m in re.finditer("InitialUEMessage", log_text)]
    blocks = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(log_text)
        blocks.append((start, end))
    return blocks


def _last_block_for(log_text: str, imsi: str, suci: str) -> Optional[str]:
    """The text of the MOST RECENT InitialUEMessage-delimited block that
    mentions this device's identity — i.e. this device's own most recent
    registration attempt.

    Regression guard: an EARLIER version of this scoping used "the last
    place this identity appears anywhere in the log" — wrong, confirmed
    directly against a real run: Open5GS logs later, unrelated PDU-session
    housekeeping lines (nsmf-pdusession/.../modify) that ALSO mention the
    IMSI, AFTER "Registration complete" already happened. That later,
    irrelevant mention pushed the scoped window past the real completion
    line, reporting a false timeout for a registration that had actually
    succeeded. Scoping by InitialUEMessage block (parse_amf_logs.py's own
    boundary marker) instead of "last mention" fixes this: any log
    activity for this device that happens without a NEW InitialUEMessage
    in between still correctly belongs to the same, already-found block.
    """
    for start, end in reversed(_find_blocks(log_text)):
        block_text = log_text[start:end]
        if imsi in block_text or suci in block_text:
            return block_text
    return None


def _registration_completed_for(log_text: str, imsi: str, suci: str) -> bool:
    """True only if "Registration complete" — the same literal marker
    logging/parse_amf_logs.py treats as the authoritative success signal —
    appears in the log block belonging to THIS device's most recent
    registration attempt (see _last_block_for)."""
    block = _last_block_for(log_text, imsi, suci)
    return block is not None and "Registration complete" in block


def _last_cause_for(log_text: str, imsi: str, suci: str) -> Optional[str]:
    """Best-effort real rejection cause for a timed-out registration —
    scoped the same way as _registration_completed_for() — so a failure
    reason says WHY (e.g. a real NSSAI/slice mismatch) instead of just
    "timed out", which is what made earlier real rejections hard to
    diagnose from the dashboard alone."""
    block = _last_block_for(log_text, imsi, suci)
    if block is None:
        return None
    match = None
    for match in _CAUSE_RE.finditer(block):
        pass  # last match in the block, if any
    return match.group(1) if match else None


def _wait_for_registration_in_log(
    creds: LiveCredentials, timeout: int, known_before: int = 0,
) -> tuple[bool, Optional[str]]:
    """Polls the real AMF log for evidence THIS device's registration
    actually COMPLETED — not just that an attempt started.

    Matching on bare IMSI/SUCI presence anywhere in the log (the previous
    behavior) was wrong: that substring appears within milliseconds of
    InitialUEMessage, long before authentication/security-mode/accept
    finish — so nr-ue was being killed mid-registration on every launch.
    Confirmed directly against a real run: the AMF log showed "Holding NG
    context already exists" / "GUTI has already been allocated" /
    "Cannot find AMF-UE Context" collisions from back-to-back launches for
    the same identity, because each launch's nr-ue was torn down before
    the network-side context from the PREVIOUS launch had actually
    finished — and later "Unknown timer[AMF_TIMER_MOBILE_REACHABLE]"
    errors from the resulting inconsistent AMF-side state. This was always
    present in the single-launch case too, but Part F's flow (5+ real
    registrations per device) made it fail far more often.

    Returns (completed, last_cause) — last_cause is a best-effort real
    rejection reason (e.g. an NSSAI/slice mismatch) if the wait times out,
    for a more actionable failure message than a bare "timed out".

    `known_before` — REGRESSION GUARD, confirmed directly against a real
    multi-launch run: without this, a NEW launch's very first poll can
    catch the log BEFORE this attempt has written anything of its own yet
    (a real race — Open5GS hasn't flushed the new InitialUEMessage line),
    at which point _last_block_for() falls back to the STALE "Registration
    complete" from this SAME device's PREVIOUS launch (e.g. baseline) and
    falsely reports success. Confirmed this is the actual root cause of
    two dashboard bugs, not just a theoretical risk: for
    duplicate_registration's 2-launch attack pattern, the FIRST launch was
    being falsely marked complete this way and terminated before its real
    registration ever finished (network-side: "Holding NG Context" ->
    "Release SM context", never "Registration complete") — while the
    SECOND launch (the one whose context actually becomes `attack_context`,
    since callers take the LAST new request) always completed for real
    with full DNN/S_NSSAI data. That made privacy_score compute to a
    constant 0.0 on every attack step regardless of scenario (maximum
    metadata exposure every time), which downstream skewed scheme
    selection toward whichever scheme scores best under that one constant
    condition. Passing `known_before` (the log's exact length at the
    moment THIS launch started, captured by launch_nr_ue_once before even
    spawning nr-ue) and slicing to `text[known_before:]` makes it
    impossible to match a block that existed before this launch began —
    the only way to find "Registration complete" is for THIS attempt to
    have genuinely produced it.
    """
    deadline = time.monotonic() + timeout
    needle_imsi = creds.imsi
    needle_suci = creds.suci
    text = ""
    while time.monotonic() < deadline:
        if AMF_LOG_PATH.exists():
            try:
                text = AMF_LOG_PATH.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            new_text = text[known_before:]
            if _registration_completed_for(new_text, needle_imsi, needle_suci):
                return True, None
        time.sleep(LOG_POLL_INTERVAL_SECONDS)
    return False, _last_cause_for(text[known_before:], needle_imsi, needle_suci)


def launch_nr_ue_once(config_path: Path, creds: LiveCredentials, timeout: int = REGISTRATION_TIMEOUT_SECONDS) -> None:
    """Launches nr-ue against config_path, waits (up to `timeout`) for
    evidence of registration in the real AMF log, then terminates this
    device's nr-ue process specifically (pkill -f <config_path>, matching
    this project's own cleanup convention in start_multiple_ues.py, but
    scoped to only this device instead of killing every nr-ue)."""
    if not NR_UE_BIN.exists():
        raise LiveStepError(f"nr-ue binary not found at {NR_UE_BIN}")

    # Captured BEFORE spawning nr-ue — see _wait_for_registration_in_log's
    # `known_before` docstring for why this must happen here, not inside
    # the wait loop.
    known_before = _current_log_length()

    try:
        process = subprocess.Popen(["sudo", "-n", str(NR_UE_BIN), "-c", str(config_path)])
    except OSError as exc:
        raise LiveStepError(f"Failed to launch nr-ue: {exc}") from exc

    try:
        registered, cause = _wait_for_registration_in_log(creds, timeout, known_before)
    finally:
        _terminate_nr_ue(process, config_path)

    if not registered:
        reason = f"nr-ue registration not observed within {timeout}s (timeout)"
        if cause:
            reason += f" — real AMF cause: {cause}"
        raise LiveStepError(reason)


def _terminate_nr_ue(process: subprocess.Popen, config_path: Path) -> None:
    try:
        subprocess.run(["sudo", "pkill", "-f", str(config_path)], timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        process.terminate()
        process.wait(timeout=5)
    except Exception:
        try:
            process.kill()
        except Exception:
            pass


# Duplicated from logging/parse_amf_logs.py's own imsi_re, deliberately —
# that file is teammate-owned and must never be edited (see
# _corrected_requests_by_block below), so this mirrors its exact pattern
# rather than importing it.
_IMSI_RE = re.compile(r"(imsi-\d+)", re.IGNORECASE)


def _first_imsi_in_block(block_text: str) -> Optional[str]:
    """The FIRST IMSI mention in an InitialUEMessage-delimited block —
    i.e. the identity closest to the block's own start, which is the
    identity that attempt actually belongs to."""
    match = _IMSI_RE.search(block_text)
    return match.group(1) if match else None


def _corrected_requests_by_block(
    all_requests: List[RegistrationRequest], log_text: str,
) -> List[RegistrationRequest]:
    """Output-correction layer over logging/parse_amf_logs.py's parsed
    rows — NEVER modifies that file (teammate-owned, see its docstring),
    only re-validates what it already produced.

    Root cause (confirmed via reproduction — see the diagnosis): that
    parser extracts each block's UE_ID via last-IMSI-mention-wins, with no
    check that every line in a block belongs to the same device. If the
    PREVIOUS device's AMF-side cleanup logging (still mentioning ITS OWN
    IMSI) straggles past the next InitialUEMessage marker — more likely
    for consecutive RETURNING devices, since they skip dbctl_add_subscriber
    ()/generate_ue_config() and so launch with less natural buffer time —
    that stray mention silently overwrites the new block's UE_ID with the
    PREVIOUS device's identity.

    This reuses the same InitialUEMessage block boundaries _find_blocks()
    already relies on (the function the live-poll path already trusts),
    and independently re-derives each block's identity from the FIRST
    IMSI mention in that block (closest to InitialUEMessage) instead of
    trusting the subprocess's last-match-wins value. Blocks correspond to
    CSV rows 1:1 IN ORDER (both are produced by scanning the same log file
    top-to-bottom, split on the same literal "InitialUEMessage" marker),
    so position-zipping them is safe PROVIDED the log hasn't shrunk since
    the subprocess read it (ruled out structurally: Open5GS logrotate on
    this system is daily-only, not size-based, and devices are processed
    strictly sequentially — never concurrently — so nothing else appends
    to this log between the subprocess call and this re-read).

    Falls back to the subprocess's original value whenever correction
    isn't safe or isn't warranted: block/row count mismatch (log
    unexpectedly shorter than expected — skip correction entirely rather
    than risk misaligning), or a block with no IMSI at all (the parser's
    own SUCI-only fallback case for an unresolved subscriber — nothing to
    correct against). This is strictly a correction, never a fabrication:
    it can only replace a wrong IMSI with a real one actually present
    earlier in the SAME block, never invent an identity the log doesn't
    contain."""
    blocks = _find_blocks(log_text)
    if len(blocks) < len(all_requests):
        return all_requests

    corrected = []
    for request, (start, end) in zip(all_requests, blocks):
        real_ue_id = _first_imsi_in_block(log_text[start:end])
        if real_ue_id is None or real_ue_id == request.ue_id:
            corrected.append(request)
        else:
            corrected.append(dataclasses.replace(request, ue_id=real_ue_id))
    return corrected


def parse_amf_log_for_device(creds: LiveCredentials) -> List[RegistrationRequest]:
    """Reuses logging/parse_amf_logs.py exactly as-is (subprocess — it is
    not safely importable, see that file's docstring), then loads its CSV
    output via the existing RegistrationLoader and filters to just this
    device's rows (by IMSI, falling back to SUCI for the unresolved-
    subscriber case the parser itself documents).

    Before filtering, the loaded rows pass through
    _corrected_requests_by_block() — an output-only validation/correction
    layer (see its docstring) that fixes a confirmed cross-device
    misattribution bug in the subprocess's own UE_ID extraction, without
    changing the subprocess call or the file it invokes in any way.

    SCOPING FIX (worsening-with-scale fix): confirmed by direct
    measurement, this function's cost used to grow with the ENTIRE
    session's cumulative log size (~0.08s at 4k lines -> ~0.39s at 40.6k
    lines for the subprocess pass alone), because both the subprocess and
    this function's own re-read processed the whole real, ever-growing
    AMF_LOG_PATH on every call, for every device, at every stage. That
    growing per-call cost widened the real-world window between the two
    reads, giving a PREVIOUS device's straggling async AMF cleanup
    logging more opportunity to land in between and trigger the exact
    cross-device misattribution _corrected_requests_by_block() exists to
    catch.

    Both reads are now bounded to the real log's content SINCE
    _device_log_offset[creds.imsi] — captured in provision_subscriber(),
    before this device's CURRENT run began (same real offset-capture
    mechanism as _wait_for_registration_in_log()'s known_before; see
    _current_log_length()). This bounds the per-call cost to roughly
    "how far THIS device has gotten in its own real registration
    sequence" (a small, ~constant number of real launches), independent
    of how many OTHER devices ran earlier in the same session.

    logging/parse_amf_logs.py itself is NEVER modified or told about this
    scoping — it always reads whatever file CAPSS_LOG_FILE points to,
    start to finish, as if it were the whole log. This function instead
    writes the SCOPED TAIL to a temporary file and points the subprocess
    at THAT, so its own linear full-file pass only ever processes this
    device's own small window. The exact same in-memory tail is then
    reused for _corrected_requests_by_block() — one real disk read now
    feeds both steps identically, which also removes the read-time race
    between "what the subprocess saw" and "what this function's own
    separate re-read saw" that existed before this fix (previously two
    independent disk reads of a growing file; now one read, sliced once,
    reused twice — they can no longer disagree even in principle).

    The misattribution-CORRECTION logic itself (re-deriving a block's
    UE_ID from the first IMSI mention within it) is untouched — this fix
    is purely about bounding what gets scanned before that logic runs."""
    offset = _device_log_offset.get(creds.imsi, 0)

    log_text = ""
    if AMF_LOG_PATH.exists():
        try:
            log_text = AMF_LOG_PATH.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            log_text = ""
    # offset need not land exactly on an "InitialUEMessage" boundary — any
    # leading partial-block content before the first such marker in the
    # slice is never assigned to any block by either parser (both start
    # with "no block open" and skip content before the first marker), so
    # a mid-block cut is safe, not just a block-aligned one.
    scoped_log_text = log_text[offset:] if offset else log_text

    tmp_log_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", prefix="capss_amf_slice_",
            delete=False, encoding="utf-8",
        ) as tmp:
            tmp.write(scoped_log_text)
            tmp_log_path = tmp.name

        subprocess.run(
            # sys.executable, not the bare string "python": in a WSL
            # session whose PATH includes Windows entries (interop), a
            # bare "python" can resolve to a Windows AppExecutionAlias
            # stub file that isn't actually executable via a direct
            # exec() call — confirmed directly (PermissionError: [Errno
            # 13] Permission denied: 'python'), not a hypothetical. Using
            # the exact interpreter already running this backend process
            # sidesteps PATH resolution entirely.
            [sys.executable, "logging/parse_amf_logs.py"],
            cwd=str(AGENT_ROOT),
            # Points at the SCOPED TEMP FILE (this device's own tail),
            # never the real, ever-growing AMF_LOG_PATH directly — see
            # this function's own docstring for why.
            env={**os.environ, "CAPSS_LOG_FILE": tmp_log_path},
            capture_output=True,
            text=True,
            timeout=LOG_PARSE_TIMEOUT_SECONDS,
            check=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise LiveStepError(f"AMF log parsing timed out after {LOG_PARSE_TIMEOUT_SECONDS}s") from exc
    except subprocess.CalledProcessError as exc:
        raise LiveStepError(f"AMF log parsing failed: {exc.stderr.strip() if exc.stderr else exc}") from exc
    except OSError as exc:
        # Defense in depth: sys.executable should never hit this, but ANY
        # failure to even launch the subprocess must still become a clean
        # per-device failure — not an uncaught crash that kills the whole
        # batch's worker thread and leaves the stream looking stuck with
        # no terminal event for this device (confirmed directly: this is
        # exactly what happened with the "python" bug above before this
        # except clause existed).
        raise LiveStepError(f"Could not launch AMF log parser: {exc}") from exc
    finally:
        if tmp_log_path is not None:
            try:
                os.unlink(tmp_log_path)
            except OSError:
                pass

    if not REGISTRATION_DATASET_CSV.exists():
        raise LiveStepError(f"Expected parsed dataset not found at {REGISTRATION_DATASET_CSV}")

    all_requests = RegistrationLoader(str(REGISTRATION_DATASET_CSV)).load()

    if scoped_log_text:
        all_requests = _corrected_requests_by_block(all_requests, scoped_log_text)

    matching = [
        r for r in all_requests if r.ue_id in (creds.imsi, creds.suci)
    ]
    if not matching:
        raise LiveStepError("No matching registration found in the parsed AMF log for this device")
    return matching


@dataclass
class ProvisionOutcome:
    creds: LiveCredentials
    config_path: Optional[Path]
    success: bool
    failure_reason: Optional[str]


@dataclass
class RegistrationEventOutcome:
    success: bool
    failure_reason: Optional[str]
    launch_count: int


def provision_subscriber(
    attack_scenario: str,
    creds: LiveCredentials,
    is_returning: bool,
    on_stage=None,  # Optional[Callable[[str, dict], None]]
) -> ProvisionOutcome:
    """Part F steps 1-3, now origin-aware (device-pool task).

    `creds` is resolved by the CALLER before this runs (device_pool.py's
    selection for a returning device, or generate_live_credentials() for a
    new one) — this function no longer generates credentials itself.

    For a RETURNING device: dbctl add is skipped entirely (already
    provisioned in Open5GS's MongoDB during a prior session — re-adding it
    would be redundant at best, a real dbctl error at worst), and the UE
    config from that prior session is reused if the file is still present
    on disk, or regenerated deterministically from these SAME stored creds
    if it isn't (e.g. a fresh environment) — safe, since generate_ue_config
    just substitutes supi/key/op from creds, which are unchanged.

    For a NEW device (requested or auto-filled): behaves exactly as
    before — real dbctl add (skipped only for invalid_subscriber, which
    never becomes a pool device — see device_pool.py's module docstring)
    plus fresh UE config generation.

    Never raises — failures are captured on the returned outcome so the
    caller can continue to the next device."""
    def emit(stage, **data):
        if on_stage is not None:
            on_stage(stage, data)

    # parse_amf_log_for_device() scoping fix: capture this device's log
    # offset before ANYTHING else happens for it this run — the earliest
    # possible point, called unconditionally for every scenario type
    # (including invalid_subscriber, which skips the dbctl-add branch
    # below but still runs this). See _capture_device_log_offset()'s
    # docstring.
    _capture_device_log_offset(creds)

    emit("credentials_ready", imsi=creds.imsi, origin="returning" if is_returning else "new")

    try:
        if is_returning:
            emit("reusing_subscriber", imsi=creds.imsi, reason="returning pool device — already provisioned in a prior session")
        elif attack_scenario != "invalid_subscriber":
            emit("adding_subscriber", imsi=creds.imsi)
            dbctl_add_subscriber(creds)
            emit("subscriber_added", imsi=creds.imsi)
        else:
            emit("skipping_subscriber_add", imsi=creds.imsi, reason="invalid_subscriber scenario")

        existing_config = config_path_for(creds)
        if is_returning and existing_config.exists():
            config_path = existing_config
            emit("config_reused", imsi=creds.imsi, config_path=str(config_path))
        else:
            emit("generating_config", imsi=creds.imsi)
            config_path = generate_ue_config(creds)
            emit("config_ready", imsi=creds.imsi, config_path=str(config_path))
    except LiveStepError as exc:
        emit("step_failed", imsi=creds.imsi, reason=str(exc))
        return ProvisionOutcome(creds=creds, config_path=None, success=False, failure_reason=str(exc))

    return ProvisionOutcome(creds=creds, config_path=config_path, success=True, failure_reason=None)


# Mixed's returning-device padding (Bug 4 follow-up). Measured directly on
# a real returning device: with NO padding, baseline-to-first-attack-launch
# measured only 1.95s real (dangerously close to REPLAY_INTERVAL=2.0s --
# misclassified that launch as REPLAY instead of the intended neutral
# separator), and the intended 1.0s replay-timed delay measured 2.58s real
# (~1.58s of real subprocess/registration overhead on top of the sleep --
# crossed the 2.0s threshold, landing on DUPLICATE_REGISTRATION instead of
# REPLAY). 15.0s of explicit padding before the first attack launch pushes
# that gap to ~15+1.95=16.95s -- comfortably clear of DUPLICATE_INTERVAL's
# 10.0s ceiling with ~7s of margin, not just barely over it.
_MIXED_RETURNING_DEVICE_PAD_SECONDS = 15.0


def _launch_pattern_for(attack_scenario: str, is_returning: bool = False) -> List[float]:
    """Sleep-before-each-launch schedule for ATTACK-timing (Part F step 8),
    identical to what the pre-restructuring single-pass flow used: a rapid
    6-launch burst for flooding (rate detector needs 5+ within its window),
    a 2s-spaced pair for replay (its 2s REPLAY_INTERVAL), a 3s-spaced pair
    for duplicate_registration (10s DUPLICATE_INTERVAL, comfortably under
    it), a single launch for everything else (invalid_subscriber, and the
    baseline registration via run_baseline_registration below, which calls
    this with a scenario-independent [0.0] directly rather than through
    this function).

    "mixed" (fixed -- see the "mixed doesn't mix anything" finding in the
    Bug 2 diagnosis) used to be a literal alias for duplicate_registration's
    [0.0, 3.0] pattern, so it always classified as plain
    DUPLICATE_REGISTRATION -- GS winning those runs was correct given what
    actually got detected, but the scenario didn't do what its name
    promised. Now a genuine 3-launch chain: a duplicate-timed pair first
    ([0.0, 3.0], same proven 3s gap as duplicate_registration on its own),
    then one more launch at a replay-timed 1s gap from the SECOND launch
    (same proven 1s gap replay uses on its own -- not a novel timing value,
    just the two already-proven patterns chained back to back).

    That [0.0, 3.0, 1.0] pattern only holds up for a FRESHLY-provisioned
    device, confirmed directly against the real classifier before that fix
    shipped. It does NOT hold up for a RETURNING device (Bug 4 follow-up):
    measured directly on a real returning device, the baseline-to-first-
    attack-launch gap collapsed to 1.95s real (vs. whatever larger gap a
    fresh device's dbctl/config-gen work produces), misclassifying that
    first launch as REPLAY instead of a neutral separator, and real
    subprocess/registration overhead alone (~1.6s, independent of any
    intended sleep) pushed the intended 1.0s replay-timed gap to 2.58s --
    over REPLAY_INTERVAL(2.0s) -- so the sequence ended on
    DUPLICATE_REGISTRATION instead of REPLAY. `is_returning` selects a
    second, padded pattern for that case (see
    _MIXED_RETURNING_DEVICE_PAD_SECONDS): an explicit 15.0s pad before the
    first launch (pushing that gap safely past DUPLICATE_INTERVAL's 10.0s
    ceiling so it can't be misread as an attack at all), then the same
    proven [3.0, 0.0] shape as [0.0, 3.0, 1.0] but with the replay-timed
    launch's OWN intended delay dropped to 0.0 -- real overhead (~1.6s)
    alone lands it under 2.0s with real, if modest (~0.2-0.4s), margin;
    adding any further intended delay on top would only shrink that margin
    further, given overhead already consumes most of the 2.0s budget on its
    own.

    Confirmed directly against the real classifier: the fresh-device
    pattern's resulting sequence classifies DUPLICATE_REGISTRATION on the
    2nd launch, then REPLAY on the 3rd -- attack_context
    (pipeline_service._build_steps's LAST step) ends up REPLAY, with the
    earlier DUPLICATE_REGISTRATION step still visible in the device's full
    step history. This is 3 launches per attack/stability-replay event now
    (vs. 2 for plain replay/duplicate_registration) -- ETA display already
    derives from a running per-device average (main.py), not a hardcoded
    per-scenario count, so no separate estimate needed updating."""
    if attack_scenario == "flooding":
        return [0.0] * 6
    if attack_scenario == "replay":
        return [0.0, 1.0]
    if attack_scenario == "duplicate_registration":
        return [0.0, 3.0]
    if attack_scenario == "mixed":
        if is_returning:
            return [_MIXED_RETURNING_DEVICE_PAD_SECONDS, 3.0, 0.0]
        return [0.0, 3.0, 1.0]
    return [0.0]


def _run_registration_pattern(
    config_path: Path,
    creds: LiveCredentials,
    pattern: List[float],
    event_label: str,
    on_stage=None,
) -> RegistrationEventOutcome:
    def emit(stage, **data):
        if on_stage is not None:
            on_stage(stage, data)
    try:
        for i, delay in enumerate(pattern):
            if delay:
                time.sleep(delay)
            emit("launching_ue", imsi=creds.imsi, event=event_label, attempt=i + 1, of=len(pattern))
            launch_nr_ue_once(config_path, creds, timeout=REGISTRATION_TIMEOUT_SECONDS)
            emit("ue_registered", imsi=creds.imsi, event=event_label, attempt=i + 1, of=len(pattern))
    except LiveStepError as exc:
        emit("step_failed", imsi=creds.imsi, event=event_label, reason=str(exc))
        return RegistrationEventOutcome(success=False, failure_reason=str(exc), launch_count=0)
    return RegistrationEventOutcome(success=True, failure_reason=None, launch_count=len(pattern))


def run_baseline_registration(config_path: Path, creds: LiveCredentials, on_stage=None) -> RegistrationEventOutcome:
    """Part F step 4 — exactly ONE real nr-ue launch, normal (non-attack)
    timing. This is a genuinely clean registration, not the first launch of
    an attack-timing burst — that distinction is what makes this device's
    'pre' state real and honest rather than borrowed from mid-attack data."""
    return _run_registration_pattern(config_path, creds, [0.0], "baseline", on_stage)


def run_attack_registration(
    config_path: Path, creds: LiveCredentials, attack_scenario: str, is_returning: bool = False, on_stage=None,
) -> RegistrationEventOutcome:
    """Part F step 8 — the scenario's real attack-timing launch pattern,
    identical to what the pre-restructuring single-pass flow used for its
    only registration burst. `is_returning` only changes anything for
    "mixed" (Bug 4 follow-up) — see _launch_pattern_for's docstring."""
    return _run_registration_pattern(
        config_path, creds, _launch_pattern_for(attack_scenario, is_returning), "attack", on_stage,
    )


def run_stability_replay_registration(
    config_path: Path, creds: LiveCredentials, attack_scenario: str, replay_number: int,
    is_returning: bool = False, on_stage=None,
) -> RegistrationEventOutcome:
    """Part F step 10 — one of 3 REAL stability replays. Repeats the SAME
    real attack-timing pattern as run_attack_registration, NOT a single bare
    launch: for multi-launch scenarios (flooding/duplicate_registration/
    replay/mixed) Systems' rate/duplicate detectors classify based on
    repeated-event patterns for this UE, so a single lone extra launch would
    not reliably reproduce the same attack classification the original
    attack registration got. This means the real per-device launch count for
    a stability check is scenario-dependent, not a flat 3 — e.g. flooding's
    3 replays are 3 more 6-launch bursts (18 more real nr-ue processes), not
    3 single ones. Surfaced explicitly in pipeline_service.py's time
    estimate and real_stability field so this isn't silently hidden behind
    an inaccurate flat '5 real registrations per device' expectation.
    `is_returning` only changes anything for "mixed" (Bug 4 follow-up) —
    same flag/rationale as run_attack_registration's, passed through
    consistently since a stability replay never re-does provisioning
    either, regardless of this device's original origin for this run."""
    return _run_registration_pattern(
        config_path, creds, _launch_pattern_for(attack_scenario, is_returning),
        f"stability_replay_{replay_number}", on_stage,
    )
