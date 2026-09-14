import type { UseAttackRunReturn } from "../hooks/useAttackRun";
import { Card } from "../components/Card";

/**
 * Deliberately minimal — real per-device computation timing only, nothing
 * this panel would duplicate from Attack Testing/Assessment/Explainability
 * (no scheme names, no verdicts, no per-mechanism breakdown). Exactly two
 * timed stages, both real time.perf_counter() measurements taken at their
 * call sites in dashboard_backend/pipeline_service.py — see
 * DeviceResult.initial_registration_ms / post_attack_computation_ms.
 */
function formatMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  return `${ms.toFixed(1)} ms`;
}

function StatusCell({ liveSuccess, cancelled }: { liveSuccess: boolean | undefined; cancelled: boolean | undefined }) {
  if (cancelled) {
    return <span style={{ color: "var(--status-warning)", fontWeight: 700 }}>Cancelled</span>;
  }
  if (liveSuccess === true) {
    return <span style={{ color: "var(--status-good)", fontWeight: 700 }}>Success</span>;
  }
  if (liveSuccess === false) {
    return <span style={{ color: "var(--status-critical)", fontWeight: 700 }}>Failed</span>;
  }
  return <span style={{ color: "var(--text-muted)" }}>Unknown</span>;
}

export function PerformancePanel({ attackRun }: { attackRun: UseAttackRunReturn }) {
  const rows = attackRun.deviceStates.filter((s) => s.device !== null);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Performance</h1>
        <p className="page-subtitle">
          Real per-device computation timing from the last Attack Testing run — Initial
          registration (Systems + Privacy classification + the Agent's baseline recommendation) and
          Post-attack computation (Systems + Privacy classification of the attack event through
          assess_adaptation()'s full run, to the final verdict). Two independent
          time.perf_counter() measurements per device — no scheme or verdict detail here; see the
          other panels for that.
        </p>
      </div>

      <Card>
        {rows.length === 0 ? (
          <span className="empty-state">Run an attack scenario first — this panel shows the last run's devices.</span>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Identity</th>
                  <th>Status</th>
                  <th>Initial Registration</th>
                  <th>Post-Attack Computation</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((s) => {
                  const d = s.device!;
                  return (
                    <tr key={d.ue_id}>
                      <td className="mono">{d.masked_identity}</td>
                      <td>
                        <StatusCell liveSuccess={d.live_success} cancelled={d.cancelled} />
                      </td>
                      <td>{formatMs(d.initial_registration_ms)}</td>
                      <td>{formatMs(d.post_attack_computation_ms)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
