import type { DeviceResult } from "../api/types";
import { Card } from "../components/Card";
import { SchemeBarChart } from "../components/SchemeBarChart";
import { SCHEME_FULL_NAMES } from "../components/SchemeLabel";

const DIMENSION_COLUMNS: { key: keyof import("../api/types").SchemeScore; label: string }[] = [
  { key: "privacy_match", label: "Privacy" },
  { key: "performance_match", label: "Performance" },
  { key: "deployment_match", label: "Deployment" },
  { key: "tracking_protection_match", label: "Tracking Protection" },
  { key: "quantum_match", label: "Quantum" },
  { key: "identity_protection_match", label: "Identity Protection" },
  { key: "experience_alignment", label: "Experience" },
];

export function ExplainabilityPanel({ device }: { device: DeviceResult | null }) {
  if (!device) {
    return (
      <div>
        <PageHeader />
        <div className="empty-state">Run an attack scenario first, then select a device.</div>
      </div>
    );
  }

  const scores = device.decision_trace?.candidate_scores ?? null;

  if (!scores) {
    return (
      <div>
        <PageHeader />
        <div className="empty-state">
          No scheme comparison available for this device (
          {device.no_comparison_reason ?? "scenario has no decision trace"}).
        </div>
      </div>
    );
  }

  const winnerId = [...scores].sort((a, b) => b.final_score - a.final_score)[0]?.scheme_id;
  const ranked = [...scores].sort((a, b) => b.final_score - a.final_score);
  const hybrid = device.hybrid_combination ?? device.recommendation?.hybrid_schemes ?? null;

  return (
    <div>
      <PageHeader />

      {hybrid && hybrid.length > 1 && (
        <Card className="rationale-block" style={{ marginBottom: 16 }}>
          <div className="block-kicker">Agent suggested a hybrid combination</div>
          <p style={{ margin: 0, fontSize: 13 }}>
            <span className="mono">{hybrid.map((h) => `${h} (${SCHEME_FULL_NAMES[h] ?? h})`).join(" + ")}</span>{" "}
            scored higher together than either scheme
            individually (benefit {device.hybrid_benefit_score?.toFixed(2) ?? "n/a"}). The table below still
            ranks individual schemes — the winner's row is the primary member of that combination.
          </p>
        </Card>
      )}

      <Card title="Final score by scheme">
        <SchemeBarChart scores={scores} />
      </Card>

      <div style={{ marginTop: 16 }}>
        <Card title="Per-dimension score breakdown">
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scheme</th>
                  <th>Final</th>
                  {DIMENSION_COLUMNS.map((c) => (
                    <th key={c.key}>{c.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ranked.map((s) => (
                  <tr key={s.scheme_id} className={s.scheme_id === winnerId ? "row-active" : ""}>
                    <td>
                      <strong>{s.short_name}</strong>
                      {s.scheme_id === winnerId && (
                        <span className="badge badge-mode-normal" style={{ marginLeft: 8 }}>
                          Winner
                        </span>
                      )}
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {SCHEME_FULL_NAMES[s.short_name] ?? s.short_name}
                      </div>
                      {s.rejection_reasons.length > 0 && (
                        <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2, maxWidth: 220 }}>
                          {s.rejection_reasons.join("; ")}
                        </div>
                      )}
                    </td>
                    <td>{s.final_score.toFixed(3)}</td>
                    {DIMENSION_COLUMNS.map((c) => (
                      <td key={c.key}>{Number(s[c.key] ?? 0).toFixed(2)}</td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </div>
  );
}

function PageHeader() {
  return (
    <div className="page-header">
      <h1 className="page-title">Explainability</h1>
      <p className="page-subtitle">
        All 7 schemes' scores for the selected registration, ranked side by side.
      </p>
    </div>
  );
}
