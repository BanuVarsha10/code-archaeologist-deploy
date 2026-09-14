"""dashboard_backend/scripts/stress_test.py

Real-hardware scaling stress test for Live Mode — finds the actual current
batch-size capacity limit by running progressively larger batches of real
devices (real Open5GS/UERANSIM/MongoDB registrations, real nr-ue processes)
until a genuine stop condition triggers, while monitoring real system
resources between batches.

WHY THIS DOESN'T USE pipeline_service.run_live_device() DIRECTLY:
run_live_device() is the dashboard's real per-device flow, but its Step 10
(3 MORE hardcoded real nr-ue replay registrations, on top of the
baseline+attack registrations — a SEPARATE real-hardware layer, not
controlled by assess_adaptation()'s replay_count at all) and Step 11 (fresh
re-executions) and the LLM explainer call all measure something else
(real-hardware replay stability already proven elsewhere with the real
default of 3; UI display data; plain-language prose) and are orthogonal to
what THIS script exists to measure: how many devices' worth of real
registrations (provision + baseline + attack, the part every device
actually needs) the environment can sustain before something real breaks.

This script instead calls pipeline_service.run_scale_device() — the SAME
shared, reduced-fidelity-vs-Step-10/11 real pipeline function the Scaling
panel (Part 2 of the "baseline-forcing fix + scaling panel" task) also
uses, so both features' real per-device cost is identical and directly
comparable, and neither duplicates the real hardware-orchestration logic.
It explicitly passes replay_count to assess_adaptation() via that shared
function — this script is one of only two real callers anywhere in the
project allowed to pass anything other than the default 3 (the Scaling
panel is the other) — see assess_adaptation()'s docstring.

IMPORTANT HONESTY NOTE (read before interpreting results): because Step 10's
hardcoded 3 real replays are skipped here, this script's real per-device
hardware cost (2-6 real nr-ue launches, depending on attack_scenario) is
LOWER than a full run_live_device() device (5-9 real launches). A capacity
limit found here is a real, honest limit for THIS reduced-fidelity flow, but
is not automatically identical to Attack Testing's practical ceiling in the
dashboard UI, which does more real hardware work per device. See the STEP 3
comparison section of the accompanying report for how to reason about this.

SAFETY: sequential only (matches the project's own existing assumption that
devices are processed strictly sequentially, never concurrently — see
live_mode.py's _corrected_requests_by_block docstring), a real preflight
check before any device is launched, a real resource sample after EVERY
device (not just every batch) so a dangerous spike is caught fast, and
guaranteed nr-ue cleanup after every batch size regardless of outcome.

Usage (from agent/, i.e. `cd ~/5g-project/agent` — same cwd every other
dashboard_backend entry point already assumes):
    python3 -m dashboard_backend.scripts.stress_test
    python3 -m dashboard_backend.scripts.stress_test --start 5 --step 5 --max 100
    python3 -m dashboard_backend.scripts.stress_test --replay-count 3 --max 15  # Step 3 sanity comparison
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# --- Real, unmodified project imports (never reimplemented) ---------------
from dashboard_backend import live_mode
from dashboard_backend.pipeline_service import run_scale_device
from dashboard_backend.systems_privacy_view import SystemsPrivacyView

SCRIPT_DIR = Path(__file__).resolve().parent
RESULTS_ROOT = SCRIPT_DIR / "stress_test_results"

SCHEMES_PATH = "data/privacy_schemes.json"  # same relative default as main.py's SCHEMES_PATH

# Hard, real safety thresholds (task requirement — sensible, stated values).
MEMORY_DANGER_PCT = 90.0          # stop if system memory used% crosses this
DISK_FREE_DANGER_MB = 500         # stop if free disk on / drops below this
LOAD1_PER_CORE_DANGER = 8.0       # secondary CPU guard: load1/nproc this high is a real overload signal

NR_UE_MATCH = str(live_mode.NR_UE_BIN)  # exact string pgrep/pkill -f match, same convention live_mode.py itself uses


# ---------------------------------------------------------------------------
# Real system resource sampling — shelling out to real tools (psutil is not
# installed in this environment; the task explicitly allows either).
# ---------------------------------------------------------------------------

def _run(cmd: List[str], timeout: float = 10.0) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.stdout or result.stderr or "").strip()
    except Exception as exc:  # noqa: BLE001 — a monitoring command failing must never crash the test itself
        return f"<error running {cmd!r}: {exc}>"


@dataclass
class ResourceSample:
    timestamp: str
    mem_total_mb: Optional[float]
    mem_used_mb: Optional[float]
    mem_used_pct: Optional[float]
    load1: Optional[float]
    load1_per_core: Optional[float]
    nr_ue_process_count: int
    open_fds_system: Optional[int]
    disk_free_mb_root: Optional[float]
    mongo_reachable: bool
    mongo_current_connections: Optional[int]
    open5gs_amfd_active: bool
    stress_process_rss_mb: Optional[float]


def sample_resources() -> ResourceSample:
    ts = datetime.now(timezone.utc).isoformat()

    mem_total_mb = mem_used_mb = mem_used_pct = None
    free_out = _run(["free", "-m"])
    for line in free_out.splitlines():
        if line.startswith("Mem:"):
            parts = line.split()
            # Mem: total used free shared buff/cache available
            mem_total_mb = float(parts[1])
            mem_used_mb = float(parts[2])
            mem_used_pct = round(mem_used_mb / mem_total_mb * 100.0, 2) if mem_total_mb else None
            break

    load1 = load1_per_core = None
    try:
        loadavg_text = Path("/proc/loadavg").read_text().split()
        load1 = float(loadavg_text[0])
        nproc = int(_run(["nproc"]) or "1")
        load1_per_core = round(load1 / max(nproc, 1), 3)
    except Exception:  # noqa: BLE001 — monitoring-only, never fatal
        pass

    nr_ue_count_raw = _run(["pgrep", "-c", "-f", NR_UE_MATCH])
    try:
        nr_ue_process_count = int(nr_ue_count_raw)
    except ValueError:
        nr_ue_process_count = 0  # pgrep -c prints "0" on no match anyway; this covers stderr/empty cases

    open_fds_system = None
    try:
        fd_parts = Path("/proc/sys/fs/file-nr").read_text().split()
        open_fds_system = int(fd_parts[0])
    except Exception:  # noqa: BLE001
        pass

    disk_free_mb_root = None
    df_out = _run(["df", "--output=avail", "-BM", "/"])
    df_lines = [l for l in df_out.splitlines() if l.strip()]
    if len(df_lines) >= 2:
        try:
            disk_free_mb_root = float(df_lines[1].strip().rstrip("M"))
        except ValueError:
            pass

    mongo_reachable = False
    mongo_current_connections = None
    mongo_ping = _run(["mongosh", "--quiet", "--eval", "db.adminCommand('ping').ok"], timeout=8.0)
    if mongo_ping.strip() == "1":
        mongo_reachable = True
        conn_out = _run(
            ["mongosh", "--quiet", "--eval", "db.serverStatus().connections.current"], timeout=8.0,
        )
        try:
            mongo_current_connections = int(conn_out.strip())
        except ValueError:
            pass

    amfd_status = _run(["systemctl", "is-active", "open5gs-amfd"])
    open5gs_amfd_active = amfd_status.strip() == "active"

    stress_process_rss_mb = None
    try:
        status_text = Path("/proc/self/status").read_text()
        for line in status_text.splitlines():
            if line.startswith("VmRSS:"):
                stress_process_rss_mb = round(int(line.split()[1]) / 1024.0, 2)
                break
    except Exception:  # noqa: BLE001
        pass

    return ResourceSample(
        timestamp=ts,
        mem_total_mb=mem_total_mb, mem_used_mb=mem_used_mb, mem_used_pct=mem_used_pct,
        load1=load1, load1_per_core=load1_per_core,
        nr_ue_process_count=nr_ue_process_count,
        open_fds_system=open_fds_system,
        disk_free_mb_root=disk_free_mb_root,
        mongo_reachable=mongo_reachable, mongo_current_connections=mongo_current_connections,
        open5gs_amfd_active=open5gs_amfd_active,
        stress_process_rss_mb=stress_process_rss_mb,
    )


def check_stop_conditions(sample: ResourceSample) -> Optional[str]:
    """Returns a human-readable reason string the instant a REAL, defined
    stop condition is met, or None if it's safe to continue. Checked after
    EVERY device (not just every batch), per the safety-first hard
    constraint."""
    if sample.mem_used_pct is not None and sample.mem_used_pct >= MEMORY_DANGER_PCT:
        return f"System memory usage {sample.mem_used_pct}% crossed the {MEMORY_DANGER_PCT}% danger threshold"
    if sample.disk_free_mb_root is not None and sample.disk_free_mb_root < DISK_FREE_DANGER_MB:
        return f"Free disk space on / dropped to {sample.disk_free_mb_root}MB (below {DISK_FREE_DANGER_MB}MB threshold)"
    if sample.load1_per_core is not None and sample.load1_per_core >= LOAD1_PER_CORE_DANGER:
        return f"1-minute load average per core ({sample.load1_per_core}) crossed the {LOAD1_PER_CORE_DANGER} danger threshold"
    if not sample.mongo_reachable:
        return "MongoDB became unreachable (mongosh ping failed)"
    if not sample.open5gs_amfd_active:
        return "open5gs-amfd is no longer 'active' per systemctl"
    return None


# ---------------------------------------------------------------------------
# Cleanup — guaranteed after every batch size, whatever the outcome.
# ---------------------------------------------------------------------------

def cleanup_orphaned_nr_ue(log) -> bool:
    """Returns True if the environment is confirmed clean (0 nr-ue
    processes) afterward. Uses `sudo -n pkill`, matching live_mode.py's own
    non-interactive convention for terminating nr-ue — if sudo isn't
    available this will simply fail to kill anything real (nothing to do,
    since nothing real could have launched without sudo either)."""
    before_raw = _run(["pgrep", "-f", NR_UE_MATCH])
    before_pids = [p for p in before_raw.splitlines() if p.strip()]
    if not before_pids:
        log(f"cleanup: no orphaned nr-ue processes found (pgrep -f {NR_UE_MATCH})")
        return True

    log(f"cleanup: found {len(before_pids)} nr-ue process(es) still running (pids={before_pids}) — killing")
    _run(["sudo", "-n", "pkill", "-f", NR_UE_MATCH], timeout=10.0)
    time.sleep(1.5)
    after_raw = _run(["pgrep", "-f", NR_UE_MATCH])
    after_pids = [p for p in after_raw.splitlines() if p.strip()]
    if after_pids:
        log(f"cleanup: WARNING — {len(after_pids)} nr-ue process(es) still present after pkill: {after_pids}")
        return False
    log("cleanup: confirmed clean — 0 nr-ue processes remain")
    return True


# ---------------------------------------------------------------------------
# Preflight — real, cheap checks before any device is launched.
# ---------------------------------------------------------------------------

def preflight_checks(log) -> Optional[str]:
    """Returns a reason string if the environment isn't genuinely ready for
    real registrations (never guesses — every check here is a real command
    or real file check), or None if it's safe to proceed."""
    if not live_mode.NR_UE_BIN.exists():
        return f"nr-ue binary not found at {live_mode.NR_UE_BIN}"
    if not live_mode.UE_CONFIG_TEMPLATE.exists():
        return f"UE config template not found at {live_mode.UE_CONFIG_TEMPLATE}"

    sudo_check = subprocess.run(["sudo", "-n", "true"], capture_output=True, text=True, timeout=5.0)
    if sudo_check.returncode != 0:
        return (
            "sudo -n is not available (no cached credential) — every real nr-ue launch "
            f"requires it (see live_mode.launch_nr_ue_once). sudo -n stderr: "
            f"{sudo_check.stderr.strip() or '<none>'}. Run `sudo -v` interactively in a real "
            "terminal first (see run_dashboard_backend.sh's own comment on this), then re-run "
            "this script from that same session."
        )

    amfd_status = _run(["systemctl", "is-active", "open5gs-amfd"])
    if amfd_status.strip() != "active":
        return f"open5gs-amfd is not active (systemctl is-active reported {amfd_status!r})"

    mongo_ping = _run(["mongosh", "--quiet", "--eval", "db.adminCommand('ping').ok"], timeout=8.0)
    if mongo_ping.strip() != "1":
        return f"MongoDB is not reachable (mongosh ping did not return ok: {mongo_ping!r})"

    log("preflight: nr-ue binary present, UE config template present, sudo -n available, "
        "open5gs-amfd active, MongoDB reachable — safe to proceed")
    return None


# ---------------------------------------------------------------------------
# Logging — real file, flushed on every write, survives a mid-run crash.
# ---------------------------------------------------------------------------

class RunLogger:
    def __init__(self, run_dir: Path):
        run_dir.mkdir(parents=True, exist_ok=True)
        self.run_dir = run_dir
        self._log_fh = open(run_dir / "stress_test.log", "a", buffering=1, encoding="utf-8")
        self._samples_fh = open(run_dir / "resource_samples.csv", "a", buffering=1, encoding="utf-8")
        self._samples_fh.write(
            "timestamp,batch_size,device_index,mem_used_pct,load1_per_core,nr_ue_process_count,"
            "open_fds_system,disk_free_mb_root,mongo_reachable,mongo_current_connections,"
            "open5gs_amfd_active,stress_process_rss_mb\n"
        )

    def log(self, message: str) -> None:
        line = f"[{datetime.now(timezone.utc).isoformat()}] {message}"
        print(line, flush=True)
        self._log_fh.write(line + "\n")

    def sample(self, batch_size: int, device_index: Any, s: ResourceSample) -> None:
        self._samples_fh.write(
            f"{s.timestamp},{batch_size},{device_index},{s.mem_used_pct},{s.load1_per_core},"
            f"{s.nr_ue_process_count},{s.open_fds_system},{s.disk_free_mb_root},{s.mongo_reachable},"
            f"{s.mongo_current_connections},{s.open5gs_amfd_active},{s.stress_process_rss_mb}\n"
        )

    def write_report(self, report: Dict[str, Any]) -> None:
        (self.run_dir / "report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    def close(self) -> None:
        self._log_fh.close()
        self._samples_fh.close()


# ---------------------------------------------------------------------------
# Batch + main scaling loop
# ---------------------------------------------------------------------------

def run_batch(
    logger: RunLogger, size: int, attack_scenario: str, replay_count: int,
) -> Dict[str, Any]:
    """Runs ONE fresh batch of exactly `size` real devices, sequentially,
    from clean state (new SystemsPrivacyView + new, isolated experience
    store file — matching how the real dashboard's own batch endpoint
    isolates per-run state). Returns a summary dict; stops EARLY within the
    batch the instant a stop condition is met."""
    logger.log(f"=== batch size {size}: starting (attack_scenario={attack_scenario!r}, replay_count={replay_count}) ===")

    run_dir = logger.run_dir
    experience_path = str(run_dir / f"stress_experience_N{size}.json")
    view = SystemsPrivacyView()
    existing_msins: set = set()

    device_results: List[Dict[str, Any]] = []
    stop_reason: Optional[str] = None
    started_at = time.monotonic()

    for i in range(1, size + 1):
        creds = live_mode.generate_live_credentials(existing_msins)
        # batch_position=i-1: real 0-indexed position in THIS batch — same
        # alternation input the baseline-forcing fix and "vs. static
        # baseline" feature both use, never derived from device identity.
        result = run_scale_device(
            view, SCHEMES_PATH, experience_path, attack_scenario, creds,
            batch_position=i - 1, replay_count=replay_count,
        )
        device_results.append(result)

        if result["success"]:
            logger.log(
                f"  device {i}/{size} ({result['masked_identity']}): OK "
                f"({result['elapsed_s']:.1f}s, scheme {result['scheme_a']} -> {result['scheme_b']}, "
                f"verdict={result['overall_verdict']})"
            )
        else:
            logger.log(f"  device {i}/{size} ({result['masked_identity']}): FAILED at stage={result['stage']!r}: {result['failure_reason']}")

        sample = sample_resources()
        logger.sample(size, i, sample)

        # A per-device real-registration failure is ALREADY handled/expected
        # per-device failure isolation elsewhere in this project (Attack
        # Testing continues past one failed device). This stress test's stop
        # condition is specifically a NEW kind of failure signal: resource
        # danger thresholds, or MongoDB/Open5GS becoming unreachable —
        # checked via the resource sample, not the device's own success flag.
        stop_reason = check_stop_conditions(sample)
        if stop_reason:
            logger.log(f"  STOP CONDITION at device {i}/{size}: {stop_reason}")
            break

    elapsed = time.monotonic() - started_at
    n_success = sum(1 for r in device_results if r["success"])
    n_failed = len(device_results) - n_success

    # A batch where every attempted device failed to complete a real
    # registration (not just one) is itself a new-kind-of-failure signal —
    # distinct from a resource threshold, but just as real a stop condition.
    if stop_reason is None and device_results and n_success == 0:
        stop_reason = (
            f"All {len(device_results)} attempted device(s) in this batch failed a real registration step "
            f"(first failure: stage={device_results[0]['stage']!r}, reason={device_results[0]['failure_reason']!r})"
        )
        logger.log(f"  STOP CONDITION: {stop_reason}")

    logger.log(
        f"=== batch size {size}: {n_success} succeeded, {n_failed} failed/incomplete "
        f"out of {len(device_results)} attempted, {elapsed:.1f}s elapsed ==="
    )

    cleanup_ok = cleanup_orphaned_nr_ue(logger.log)

    return {
        "batch_size": size,
        "attempted": len(device_results),
        "succeeded": n_success,
        "failed": n_failed,
        "elapsed_s": round(elapsed, 1),
        "stop_reason": stop_reason,
        "cleanup_confirmed_clean": cleanup_ok,
        "final_resource_sample": asdict(sample_resources()),
        "device_failure_stages": [r["stage"] for r in device_results if not r["success"]],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--start", type=int, default=5, help="First batch size to test (default: 5)")
    parser.add_argument(
        "--step", type=int, default=5,
        help="Increment between batch sizes (default: +5 — fine enough to localize the failure point "
             "within a 5-device window without doubling's coarser jumps)",
    )
    parser.add_argument(
        "--max", type=int, default=100,
        help="Generous fixed upper bound — stop here if nothing has broken yet (default: 100)",
    )
    parser.add_argument("--attack-scenario", default="duplicate_registration", help="Attack scenario for every device (default: duplicate_registration)")
    parser.add_argument(
        "--replay-count", type=int, default=1,
        help="Check 2 replay count passed explicitly to assess_adaptation() (default: 1, the fast-mode "
             "override for this stress test). Pass 3 for the Step-3 default-replay-count sanity comparison.",
    )
    args = parser.parse_args()

    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RESULTS_ROOT / run_id
    logger = RunLogger(run_dir)

    logger.log(
        f"stress_test starting: start={args.start} step={args.step} max={args.max} "
        f"attack_scenario={args.attack_scenario!r} replay_count={args.replay_count}"
    )

    preflight_failure = preflight_checks(logger.log)
    if preflight_failure:
        logger.log(f"PREFLIGHT FAILED — aborting before launching any real device: {preflight_failure}")
        logger.write_report({
            "run_id": run_id, "aborted": True, "preflight_failure": preflight_failure,
            "batches": [],
        })
        logger.close()
        print(f"\nPreflight failed: {preflight_failure}\nSee {run_dir} for the full log.", file=sys.stderr)
        return 1

    batches: List[Dict[str, Any]] = []
    size = args.start
    overall_stop_reason: Optional[str] = None

    while size <= args.max:
        batch_report = run_batch(logger, size, args.attack_scenario, args.replay_count)
        batches.append(batch_report)
        logger.write_report({
            "run_id": run_id, "aborted": False, "preflight_failure": None,
            "args": vars(args), "batches": batches, "in_progress": True,
        })

        if batch_report["stop_reason"]:
            overall_stop_reason = batch_report["stop_reason"]
            logger.log(f"STOPPING scaling loop at batch size {size}: {overall_stop_reason}")
            break
        if not batch_report["cleanup_confirmed_clean"]:
            overall_stop_reason = f"Cleanup could not confirm a clean state after batch size {size} — stopping rather than continuing to scale up on top of orphaned processes."
            logger.log(overall_stop_reason)
            break

        size += args.step
    else:
        overall_stop_reason = f"Reached the fixed upper bound (max={args.max}) with no failure — stopping as designed."
        logger.log(overall_stop_reason)

    final_report = {
        "run_id": run_id, "aborted": False, "preflight_failure": None,
        "args": vars(args), "batches": batches, "in_progress": False,
        "overall_stop_reason": overall_stop_reason,
        "largest_fully_clean_batch_size": (
            batches[-2]["batch_size"] if len(batches) >= 2 and batches[-1]["stop_reason"] else
            (batches[-1]["batch_size"] if batches and not batches[-1]["stop_reason"] else None)
        ),
        "first_failure_batch_size": batches[-1]["batch_size"] if batches and batches[-1]["stop_reason"] else None,
    }
    logger.write_report(final_report)
    logger.log(f"stress_test finished. Report written to {run_dir / 'report.json'}")
    logger.close()

    print(f"\nDone. Full results in {run_dir}")
    print(f"Overall stop reason: {overall_stop_reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
