import type { DeviceResult } from "../api/types";
import { Card } from "../components/Card";
import { SCHEME_FULL_NAMES, schemeFullLabel } from "../components/SchemeLabel";

const RAG_RULE_RE = /RULE_RAG_CROSS_UE_RETRIEVAL\(k=(\d+),\s*avg_sim=([\d.]+)\)/;

function humanizeRule(rule: string): string {
  return rule
    .replace(/^RULE_/, "")
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/^\w/, (c) => c.toUpperCase());
}

/**
 * The Agent's real reasoning evidence for the selected device — not a
 * fixed 10-step narrative, but the actual retrieval + scoring data
 * capss/reasoning/explainer.py computes: which past experiences (local
 * and cross-UE, via real vector-similarity retrieval with similarity
 * scores) informed the decision, why each losing scheme was rejected, and
 * which context rules fired. Everything here is real data already
 * produced by the existing, unmodified reasoning engine — this panel
 * only makes it visible.
 */
export function AIAgentPanel({ device }: { device: DeviceResult | null }) {
  if (!device) {
    return (
      <div>
        <PageHeader />
        <div className="empty-state">Run an attack scenario first, then select a device.</div>
      </div>
    );
  }

  const trace = device.decision_trace;
  const explanation = device.explanation;

  if (!trace || !explanation) {
    return (
      <div>
        <PageHeader />
        <Card title="No reasoning trace for this scenario">
          <p style={{ color: "var(--text-secondary)" }}>
            {device.no_comparison_reason ??
              "This device did not produce a comparable decision trace."}
          </p>
          {device.recommendation && (
            <div className="metric-row">
              <span className="metric-label">Selected scheme</span>
              <span className="metric-value">{schemeFullLabel(device.recommendation.selected_scheme)}</span>
            </div>
          )}
        </Card>
      </div>
    );
  }

  const ragMatch = explanation.rules_fired.map((r) => r.match(RAG_RULE_RE)).find(Boolean);
  const otherRules = explanation.rules_fired.filter((r) => !RAG_RULE_RE.test(r));
  const rejections = Object.entries(explanation.why_alternatives_rejected);

  return (
    <div>
      <PageHeader />

      <div className="hero-banner">
        <div className="hero-label">Winner</div>
        <div className="hero-value">{trace.winner}</div>
        <div style={{ fontSize: 13, opacity: 0.75 }}>
          {(trace.winner && SCHEME_FULL_NAMES[trace.winner]) ?? trace.winner}
        </div>
        <p style={{ marginTop: 8, fontSize: 13, opacity: 0.85 }}>{explanation.why_selected}</p>
      </div>

      <Card title="Retrieved evidence (real vector-similarity retrieval)">
        <div className="metric-row">
          <span className="metric-label">Local experiences for this UE</span>
          <span className="metric-value">{trace.experience_contribution.total_experiences}</span>
        </div>
        {ragMatch ? (
          <>
            <div className="metric-row">
              <span className="metric-label">Cross-UE matches retrieved</span>
              <span className="metric-value">{ragMatch[1]}</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">Average similarity</span>
              <span className="metric-value">{(parseFloat(ragMatch[2]) * 100).toFixed(0)}%</span>
            </div>
          </>
        ) : (
          <div className="metric-row">
            <span className="metric-label">Cross-UE retrieval</span>
            <span className="metric-value" style={{ color: "var(--text-muted)" }}>
              Not triggered (this UE already has 3+ of its own experiences)
            </span>
          </div>
        )}
        <p style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 8 }}>
          {explanation.experience_influence}
        </p>
      </Card>

      <div style={{ marginTop: 16 }}>
        <Card title={`Rejected alternatives (${rejections.length})`}>
          {rejections.length === 0 ? (
            <span className="empty-state">No other schemes were scored for comparison.</span>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Scheme</th>
                  <th>Why it lost</th>
                </tr>
              </thead>
              <tbody>
                {rejections.map(([scheme, reason]) => (
                  <tr key={scheme}>
                    <td className="mono">
                      {scheme}
                      <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {SCHEME_FULL_NAMES[scheme] ?? scheme}
                      </div>
                    </td>
                    <td style={{ color: "var(--text-secondary)" }}>{reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      <div className="card-grid" style={{ marginTop: 16 }}>
        <Card title="Context rules fired">
          {otherRules.length === 0 ? (
            <span className="empty-state">No specific rules flagged.</span>
          ) : (
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {otherRules.map((r) => (
                <span className="badge badge-neutral" key={r}>
                  {humanizeRule(r)}
                </span>
              ))}
            </div>
          )}
        </Card>

        <Card title="Ranking">
          <div className="metric-row">
            <span className="metric-label">Winner score</span>
            <span className="metric-value">{trace.winner_score?.toFixed(3)}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Runner-up</span>
            <span className="metric-value">
              {trace.runner_up
                ? `${trace.runner_up} (${SCHEME_FULL_NAMES[trace.runner_up] ?? trace.runner_up})`
                : "—"}{" "}
              ({trace.runner_up_score?.toFixed(3) ?? "—"})
            </span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Score gap</span>
            <span className="metric-value">{trace.score_gap?.toFixed(3) ?? "—"}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Knowledge coverage</span>
            <span className="metric-value">{(trace.knowledge_coverage * 100).toFixed(0)}%</span>
          </div>
        </Card>

        <Card title="Adaptation">
          <p style={{ fontSize: 13, color: "var(--text-secondary)", margin: 0 }}>{explanation.adaptation_note}</p>
        </Card>
      </div>

      <div style={{ marginTop: 16 }}>
        <Card title="Confidence & risk reasoning">
          <p style={{ fontSize: 13, color: "var(--text-secondary)" }}>{explanation.confidence_explanation}</p>
          <p style={{ fontSize: 13, color: "var(--text-secondary)", marginBottom: 0 }}>
            {explanation.risk_explanation}
          </p>
        </Card>
      </div>
    </div>
  );
}

function PageHeader() {
  return (
    <div className="page-header">
      <h1 className="page-title">AI Agent Reasoning</h1>
      <p className="page-subtitle">
        Real retrieval evidence and scoring behind the Agent's recommendation — not a scripted
        narrative.
      </p>
    </div>
  );
}
