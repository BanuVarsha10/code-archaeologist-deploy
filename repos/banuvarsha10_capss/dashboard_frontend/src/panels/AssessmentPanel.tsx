import type { DeviceResult } from "../api/types";
import { Card } from "../components/Card";
import { VerdictPill } from "../components/Badge";
import { SCHEME_FULL_NAMES, schemeFullLabel } from "../components/SchemeLabel";

export function AssessmentPanel({ device }: { device: DeviceResult | null }) {
  if (!device) {
    return (
      <div>
        <PageHeader />
        <div className="empty-state">Run an attack scenario first, then select a device.</div>
      </div>
    );
  }

  const cr = device.comparison_result;

  if (!cr) {
    return (
      <div>
        <PageHeader />
        <Card>
          <div className="card-title">No before/after comparison applies to this scenario</div>
          <p style={{ color: "var(--text-secondary)" }}>{device.no_comparison_reason}</p>
          {device.recommendation && (
            <div className="metric-row">
              <span className="metric-label">Real recommendation produced instead</span>
              <span className="metric-value">{schemeFullLabel(device.recommendation.selected_scheme)}</span>
            </div>
          )}
        </Card>
      </div>
    );
  }

  return (
    <div>
      <PageHeader />

      <div className="hero-banner">
        <div className="hero-label">Overall verdict</div>
        <div className="hero-value" style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <VerdictPill verdict={cr.overall_verdict} />
        </div>
        <p style={{ marginTop: 8, fontSize: 13, opacity: 0.85 }}>{cr.verdict_reason}</p>
      </div>

      <div className="card-grid" style={{ marginBottom: 16 }}>
        <Card title="Check 1 — Adaptation occurred">
          <div className="metric-row">
            <span className="metric-label">
              {cr.scheme_a} ({SCHEME_FULL_NAMES[cr.scheme_a] ?? cr.scheme_a}) → {cr.scheme_b} (
              {SCHEME_FULL_NAMES[cr.scheme_b] ?? cr.scheme_b})
            </span>
            <span className="metric-value">{cr.adaptation_occurred ? "Yes" : "No"}</span>
          </div>
        </Card>
        <Card title={`Check 2 — Simulated Stability (${cr.replay_count} replays, no hardware)`}>
          <div className="metric-row">
            <span className="metric-label">{cr.stability_detail}</span>
            <span className="metric-value">{cr.stability_confirmed ? "Confirmed" : "Not confirmed"}</span>
          </div>
          <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8, marginBottom: 0 }}>
            Internal reasoning only — {cr.replay_count} more agent-only calls on the identical
            attack context, no real hardware involved. See the Attack Testing story view for the
            separate Real Hardware Stability signal (live replay registrations), which can
            legitimately differ from this.
          </p>
        </Card>
      </div>

      {/* Check 3 (Measured Overhead) and Check 4 (Analytical Rationale) are
          kept as two visually distinct blocks — real numbers vs.
          literature-backed claim — never blended into one number/block. */}
      <div className="check4-grid">
        <Card className="overhead-block">
          <div className="block-kicker">Check 3 — Measured Overhead (empirical)</div>
          {cr.measured_overhead ? (
            <>
              <div className="metric-row">
                <span className="metric-label">Time: {schemeFullLabel(cr.measured_overhead.scheme_a)}</span>
                <span className="metric-value">{cr.measured_overhead.time_a_ms.toFixed(2)} ms</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Time: {schemeFullLabel(cr.measured_overhead.scheme_b)}</span>
                <span className="metric-value">{cr.measured_overhead.time_b_ms.toFixed(2)} ms</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Time diff (B vs A)</span>
                <span className="metric-value">{cr.measured_overhead.time_diff_pct}%</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Size diff (B vs A)</span>
                <span className="metric-value">{cr.measured_overhead.size_diff_pct}%</span>
              </div>
              <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
                {cr.measured_overhead.note}
              </p>
            </>
          ) : (
            <span className="empty-state">Not available.</span>
          )}
        </Card>

        <Card className="rationale-block">
          <div className="block-kicker">Check 4 — Analytical Rationale (knowledge base)</div>
          {cr.analytical_rationale ? (
            <>
              <div className="metric-row">
                <span className="metric-label">Attack type</span>
                <span className="metric-value">{cr.analytical_rationale.attack_type}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Affinity: {schemeFullLabel(cr.analytical_rationale.scheme_a)}</span>
                <span className="metric-value">{String(cr.analytical_rationale.affinity_a)}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Affinity: {schemeFullLabel(cr.analytical_rationale.scheme_b)}</span>
                <span className="metric-value">{String(cr.analytical_rationale.affinity_b)}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Analytically justified</span>
                <span className="metric-value">{cr.analytical_rationale.analytically_justified ? "Yes" : "No"}</span>
              </div>
              <p style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 8 }}>
                {cr.analytical_rationale.justification_note}
              </p>
              <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
                {cr.analytical_rationale.source_note}
              </p>
            </>
          ) : (
            <span className="empty-state">Not available.</span>
          )}
        </Card>
      </div>

      {/* Hybrid execution gap fix: Check 3 above is ALWAYS scheme_a vs
          scheme_b only (the primary scheme), never blended with this —
          shown as its own distinct, clearly-labeled block so "GS + DP"
          never gets confused with execution data that's actually only
          GS's. Only rendered when the Agent's real recommendation was a
          hybrid combination; absent entirely otherwise. */}
      {cr.hybrid_partner_scheme && (
        <Card className="hybrid-partner-block" style={{ marginTop: 16 }}>
          <div className="block-kicker">
            Hybrid Partner — real execution (separate from Check 3 above)
          </div>
          <p style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 0 }}>
            The Agent's full recommendation is a hybrid:{" "}
            <strong>
              {schemeFullLabel(cr.scheme_b)} + {schemeFullLabel(cr.hybrid_partner_scheme)}
            </strong>
            . Check 3 above measures {schemeFullLabel(cr.scheme_a)} vs {schemeFullLabel(cr.scheme_b)} only —
            the primary scheme, exactly as throughout this comparison. This block is{" "}
            {schemeFullLabel(cr.hybrid_partner_scheme)}'s own real, separate execution; its numbers are never
            combined into Check 3's figures.
          </p>
          {cr.hybrid_partner_execution ? (
            <>
              <div className="metric-row">
                <span className="metric-label">Output type</span>
                <span className="metric-value">{cr.hybrid_partner_execution.output_type}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Generation time</span>
                <span className="metric-value">{cr.hybrid_partner_execution.generation_time_ms.toFixed(2)} ms</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Output size</span>
                <span className="metric-value">{cr.hybrid_partner_execution.output_size_bytes} bytes</span>
              </div>
              {cr.hybrid_partner_execution.error && (
                <div className="metric-row">
                  <span className="metric-label" style={{ color: "var(--status-critical)" }}>Execution error</span>
                  <span className="metric-value">{cr.hybrid_partner_execution.error}</span>
                </div>
              )}
            </>
          ) : (
            <span className="empty-state">Hybrid partner execution not available.</span>
          )}
        </Card>
      )}

      {device.llm_explanation && (
        <Card className="ai-summary-block" style={{ marginTop: 16 }}>
          <div className="block-kicker">AI Summary (plain-language, generated after the decision above)</div>

          {/* Section A — Why the winner was selected. */}
          <div style={{ marginTop: 10 }}>
            <div
              style={{
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: "0.04em",
                textTransform: "uppercase",
                color: "var(--accent-green-start)",
              }}
            >
              Section A — Why {schemeFullLabel(cr.scheme_b)} was selected
            </div>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.6, marginTop: 6 }}>
              {device.llm_explanation.winner_explanation}
            </p>
          </div>

          {/* Section B — Why the others were not selected: each rejected
              scheme's real, >=3-sentence grounded explanation (or fewer,
              honestly framed, when real data doesn't support 3 distinct
              points — see llm_explainer.py's honest-uncertainty exception). */}
          {device.llm_explanation.rejected_schemes.length > 0 && (
            <div
              style={{
                marginTop: 16,
                paddingTop: 14,
                borderTop: "1px solid var(--border-subtle)",
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: "0.04em",
                  textTransform: "uppercase",
                  color: "var(--accent-purple)",
                }}
              >
                Section B — Why the others were not selected
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 8 }}>
                {device.llm_explanation.rejected_schemes.map((r) => (
                  <div key={r.scheme}>
                    <div style={{ fontSize: 12.5, fontWeight: 700, color: "var(--text-primary)" }}>
                      <span className="mono">{r.scheme}</span>{" "}
                      <span style={{ fontWeight: 400, color: "var(--text-muted)" }}>
                        ({SCHEME_FULL_NAMES[r.scheme] ?? r.scheme})
                      </span>
                    </div>
                    <p style={{ fontSize: 12.5, color: "var(--text-secondary)", lineHeight: 1.55, margin: "2px 0 0" }}>
                      {r.reason}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {device.llm_explanation.hybrid_partner_explanation && (
            <div
              style={{
                marginTop: 12,
                paddingTop: 10,
                borderTop: "1px solid var(--border-subtle)",
              }}
            >
              <div className="block-kicker" style={{ marginBottom: 4 }}>
                Why the hybrid partner ({schemeFullLabel(cr.hybrid_partner_scheme)}) was added
              </div>
              <p style={{ fontSize: 12.5, color: "var(--text-secondary)", lineHeight: 1.5, margin: 0 }}>
                {device.llm_explanation.hybrid_partner_explanation}
              </p>
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function PageHeader() {
  return (
    <div className="page-header">
      <h1 className="page-title">Assessment</h1>
      <p className="page-subtitle">
        The full 4-check adaptation assessment for the selected registration.
      </p>
    </div>
  );
}
