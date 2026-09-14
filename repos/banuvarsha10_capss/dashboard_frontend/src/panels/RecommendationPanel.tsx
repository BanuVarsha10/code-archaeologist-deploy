import type { DeviceResult } from "../api/types";
import { Card } from "../components/Card";
import { VerdictPill } from "../components/Badge";
import { schemeFullLabel } from "../components/SchemeLabel";

export function RecommendationPanel({ device }: { device: DeviceResult | null }) {
  if (!device) {
    return (
      <div>
        <PageHeader />
        <div className="empty-state">Run an attack scenario first, then select a device.</div>
      </div>
    );
  }

  // For scenarios with a comparison, the "after" recommendation lives on
  // comparison_result (scheme_b) with details in the analytical_rationale's
  // agent_reason/agent_metric_summary. For invalid_subscriber, it's the
  // direct `recommendation` (PrivacyPolicy).
  const comparison = device.comparison_result;
  const recommendation = device.recommendation;

  const selectedScheme = comparison?.scheme_b ?? recommendation?.selected_scheme ?? "—";
  const reason = comparison?.analytical_rationale?.agent_reason ?? recommendation?.reason ?? "—";
  const confidence =
    comparison?.analytical_rationale?.agent_metric_summary?.confidence ??
    recommendation?.confidence ??
    null;
  // Data-wiring fix (same class of bug as the Baseline card / adaptation_note
  // fixes): device.recommendation (PrivacyPolicy) is None for every real
  // device that has a comparison_result — only invalid_subscriber devices
  // (which never get a comparison_result at all) populate it — see
  // pipeline_service.py's run_live_device()/run_manual_and_assess() return
  // dicts. So recommendation?.validation_result was ALWAYS null/"Not
  // available" for every normal device, universally, not hybrid-specific.
  // comparison_result.overall_verdict is the real, current, already-4-check-
  // validated source Assessment panel already uses correctly — preferred
  // here whenever a comparison exists; recommendation.validation_result
  // stays as the (correct, still-needed) fallback for invalid_subscriber,
  // the one real scenario with no comparison_result at all.
  const isValid = recommendation?.validation_result?.is_valid ?? null;
  const hybrid = device.hybrid_combination ?? recommendation?.hybrid_schemes ?? null;
  const isHybrid = hybrid !== null && hybrid.length > 1;

  return (
    <div>
      <PageHeader />

      <div className="hero-banner">
        <div className="hero-label">{isHybrid ? "Selected hybrid combination" : "Selected scheme"}</div>
        <div className="hero-value">{isHybrid ? hybrid!.join(" + ") : selectedScheme}</div>
        <div style={{ fontSize: 13, opacity: 0.75, marginTop: 4 }}>
          {isHybrid ? hybrid!.map(schemeFullLabel).join(" + ") : schemeFullLabel(selectedScheme)}
        </div>
      </div>

      {isHybrid && (
        <Card className="rationale-block" style={{ marginBottom: 16 }}>
          <div className="block-kicker">Hybrid rationale</div>
          <p style={{ color: "var(--text-secondary)", fontSize: 13, margin: 0 }}>
            {device.hybrid_reason ?? "Combining these two schemes scored higher than either alone."}
          </p>
          {device.hybrid_benefit_score !== null && (
            <div className="metric-row">
              <span className="metric-label">Hybrid benefit score</span>
              <span className="metric-value">{device.hybrid_benefit_score?.toFixed(2)}</span>
            </div>
          )}
        </Card>
      )}

      <div className="card-grid">
        <Card title="Confidence">
          <div className="hero-banner" style={{ margin: 0, background: "var(--bg-panel-raised)", color: "var(--text-primary)" }}>
            <div className="hero-label" style={{ color: "var(--text-muted)" }}>
              Confidence score
            </div>
            <div className="hero-value" style={{ background: "none", color: "var(--accent-green-start)" }}>
              {confidence !== null ? confidence.toFixed(2) : "n/a"}
            </div>
          </div>
        </Card>

        <Card title="Validation status">
          {comparison ? (
            <>
              <VerdictPill verdict={comparison.overall_verdict} />
              <p style={{ color: "var(--text-secondary)", fontSize: 12, marginTop: 8, marginBottom: 0 }}>
                {comparison.verdict_reason}
              </p>
            </>
          ) : isValid === null ? (
            <span style={{ color: "var(--text-muted)" }}>Not available for this scenario.</span>
          ) : (
            <span className={`badge ${isValid ? "badge-mode-normal" : "badge-mode-live"}`}>
              {isValid ? "Valid" : "Invalid"}
            </span>
          )}
          {recommendation?.validation_result?.warnings?.map((w) => (
            <div key={w} style={{ color: "var(--status-warning)", fontSize: 12, marginTop: 6 }}>
              ⚠ {w}
            </div>
          ))}
        </Card>

        <Card title="Reason">
          <p style={{ color: "var(--text-secondary)", margin: 0 }}>{reason}</p>
        </Card>
      </div>
    </div>
  );
}

function PageHeader() {
  return (
    <div className="page-header">
      <h1 className="page-title">Recommendation</h1>
      <p className="page-subtitle">The Agent's final output for the selected registration.</p>
    </div>
  );
}
