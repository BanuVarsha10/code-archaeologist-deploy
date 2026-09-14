import { useEffect, useState } from "react";
import type { AttackScenario } from "../api/types";
import { ATTACK_SCENARIOS } from "../api/types";
import type { UseScalingRunReturn } from "../hooks/useScalingRun";
import { Card } from "../components/Card";
import { SCHEME_FULL_NAMES } from "../components/SchemeLabel";

/**
 * Real scalability/throughput measurement — 100-500 real devices through
 * the FULL real pipeline (baseline forced ECIES/ML-KEM -> Systems ->
 * Privacy -> Agent -> real scheme execution -> real assess_adaptation()),
 * Check 2 at replay_count=1 for this panel only (see
 * dashboard_backend/pipeline_service.run_scale_device()). Deliberately
 * minimal per-device display at this scale — identity, status, and the
 * scheme actually selected only; see the other Tier-1 panels for full
 * per-device detail on a normal, small batch.
 */
/** Ticks once per real second while running, off the wall clock (Date.now()
 * vs. the run's real start time) — genuinely live, not just re-rendering
 * when a device_done event happens to arrive. Once the run finishes, the
 * caller should prefer the backend's own authoritative summary.total_elapsed_s
 * instead of this hook's last tick (this hook freezes at whatever it last
 * read, which is close but not the precise final value). */
function useLiveElapsedMs(startedAtMs: number | null, running: boolean): number {
  const [nowMs, setNowMs] = useState(() => Date.now());
  useEffect(() => {
    if (!running || startedAtMs === null) return;
    setNowMs(Date.now());
    const id = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [running, startedAtMs]);
  if (startedAtMs === null) return 0;
  return nowMs - startedAtMs;
}

function formatDuration(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}m ${seconds.toString().padStart(2, "0")}s`;
}

function StatusCell({ success }: { success: boolean }) {
  return success ? (
    <span style={{ color: "var(--status-good)", fontWeight: 700 }}>Success</span>
  ) : (
    <span style={{ color: "var(--status-critical)", fontWeight: 700 }}>Failed</span>
  );
}

export function ScalingPanel({ scalingRun }: { scalingRun: UseScalingRunReturn }) {
  const { running, error, devices, total, summary, startedAtMs, startRun } = scalingRun;
  const [deviceCount, setDeviceCount] = useState(100);
  const [attackScenario, setAttackScenario] = useState<AttackScenario>("duplicate_registration");

  const liveElapsedMs = useLiveElapsedMs(startedAtMs, running);
  const elapsedMs = !running && summary ? summary.total_elapsed_s * 1000 : liveElapsedMs;
  const doneCount = devices.filter(Boolean).length;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Scaling / Throughput</h1>
        <p className="page-subtitle">
          A real scalability measurement — runs the FULL real pipeline (real baseline forced to
          ECIES/ML-KEM, Systems, Privacy, Agent, real scheme execution, real assess_adaptation())
          for 100-500 real devices. Check 2's stability replay count is 1 for this panel only
          (default 3 everywhere else) — a throughput measurement, not a stability re-verification.
          Uses a dedicated scratch experience store, reset every run — never the real, persistent
          store Attack Testing uses.
        </p>
      </div>

      <Card style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", gap: 24, alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 280px", minWidth: 240 }}>
            <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 6 }}>
              Devices this run: <strong style={{ color: "var(--text-primary)" }}>{deviceCount}</strong>
            </label>
            <input
              type="range"
              min={100}
              max={500}
              step={10}
              value={deviceCount}
              onChange={(e) => setDeviceCount(Number(e.target.value))}
              disabled={running}
              style={{ width: "100%" }}
            />
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "var(--text-muted)" }}>
              <span>100</span>
              <span>500</span>
            </div>
          </div>
          <div>
            <label style={{ display: "block", fontSize: 12, color: "var(--text-muted)", marginBottom: 4 }}>
              Attack scenario
            </label>
            <select
              value={attackScenario}
              onChange={(e) => setAttackScenario(e.target.value as AttackScenario)}
              disabled={running}
              style={{ padding: "8px 10px", borderRadius: 8 }}
            >
              {ATTACK_SCENARIOS.filter((s) => s.value !== "invalid_subscriber").map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>
          <button
            className="btn btn-primary"
            onClick={() => startRun(deviceCount, attackScenario)}
            disabled={running}
          >
            {running ? <span className="spinner" /> : `Run (${deviceCount} real devices)`}
          </button>
        </div>
        {error && <p style={{ color: "var(--status-critical)", marginTop: 10, marginBottom: 0 }}>{error}</p>}
      </Card>

      {(running || startedAtMs !== null) && (
        <Card className="hero-banner" style={{ marginBottom: 20 }}>
          <div className="hero-label">{running ? "Running — live elapsed time" : "Last run — total elapsed time"}</div>
          <div className="hero-value mono">{formatDuration(elapsedMs)}</div>
          <div style={{ fontSize: 13, opacity: 0.75, marginTop: 4 }}>
            {running
              ? `${doneCount} / ${total} devices done`
              : summary && `${summary.succeeded} succeeded, ${summary.failed} failed of ${summary.total_devices}`}
          </div>
        </Card>
      )}

      {summary && !running && (
        <Card title="Final summary" style={{ marginBottom: 20 }}>
          <div className="card-grid">
            <div className="metric-row">
              <span className="metric-label">Total devices run</span>
              <span className="metric-value">{summary.total_devices}</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">Total real elapsed time</span>
              <span className="metric-value">{summary.total_elapsed_s.toFixed(1)}s</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">Average time per device</span>
              <span className="metric-value">{summary.avg_seconds_per_device.toFixed(2)}s</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">Succeeded / Failed</span>
              <span className="metric-value">
                {summary.succeeded} / {summary.failed}
              </span>
            </div>
            <div className="metric-row">
              <span className="metric-label">Check 2 replay count used</span>
              <span className="metric-value">{summary.replay_count_used}</span>
            </div>
          </div>
        </Card>
      )}

      <Card title={`Devices (${doneCount}${total ? ` / ${total}` : ""})`}>
        {devices.length === 0 ? (
          <span className="empty-state">Run a scaling test to see per-device results here.</span>
        ) : (
          <div style={{ overflowX: "auto", maxHeight: 520, overflowY: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Identity</th>
                  <th>Status</th>
                  <th>Scheme selected</th>
                </tr>
              </thead>
              <tbody>
                {devices.map(
                  (d, i) =>
                    d && (
                      <tr key={i}>
                        <td className="mono">{i + 1}</td>
                        <td className="mono">{d.masked_identity}</td>
                        <td>
                          <StatusCell success={d.success} />
                          {!d.success && (
                            <div style={{ fontSize: 11, color: "var(--text-muted)" }}>{d.failure_reason}</div>
                          )}
                        </td>
                        <td className="mono" title={d.scheme_b ? SCHEME_FULL_NAMES[d.scheme_b] ?? d.scheme_b : undefined}>
                          {d.scheme_b ?? "—"}
                        </td>
                      </tr>
                    ),
                )}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
