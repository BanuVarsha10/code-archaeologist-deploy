import { useEffect, useState } from "react";
import type { DeviceResult } from "../api/types";
import { Card } from "../components/Card";
import { Meter } from "../components/Meter";
import { Sparkline } from "../components/Sparkline";
import { SchemeBarChart } from "../components/SchemeBarChart";
import { VerdictPill } from "../components/Badge";
import { schemeFullLabel } from "../components/SchemeLabel";

interface Stage {
  key: string;
  label: string;
}

const STAGES: Stage[] = [
  { key: "subscriber", label: "Subscriber" },
  { key: "systems", label: "Pre-AMF (Systems)" },
  { key: "privacy", label: "Privacy" },
  { key: "agent", label: "Agent" },
  { key: "recommendation", label: "Recommendation" },
  { key: "execution", label: "Scheme Execution" },
  { key: "assessment", label: "Assessment" },
];

export function PipelineVisualizerPanel({ device }: { device: DeviceResult | null }) {
  const [activeIndex, setActiveIndex] = useState(-1);
  const [playing, setPlaying] = useState(false);
  // Bumped by the "Replay flow" button to force the effect below to re-run
  // even when device?.ue_id hasn't changed (re-watching the same device).
  const [replayNonce, setReplayNonce] = useState(0);

  // The animation timer is owned ENTIRELY by this effect, not by an
  // imperative function called from it. This is a deliberate rewrite, not
  // a tweak: the previous version managed the timer via a ref and called
  // an imperative play() function from the effect, with cleanup bolted on
  // separately (a manual clearTimeout at the top of play(), plus a
  // SEPARATE unmount-only effect) — nothing structurally guaranteed that
  // cleanup ran before every restart, only whatever was manually
  // remembered. Owning the interval inside the effect itself means React's
  // own cleanup contract (guaranteed to run before the effect re-fires for
  // ANY reason, and on unmount) clears it automatically every time,
  // eliminating the whole class of "orphaned timer" bugs rather than
  // patching around one specific trigger of it.
  useEffect(() => {
    if (!device) return;
    setPlaying(true);
    setActiveIndex(0);
    let i = 0;
    const interval = window.setInterval(() => {
      i += 1;
      if (i >= STAGES.length) {
        setPlaying(false);
        setActiveIndex(STAGES.length - 1);
        window.clearInterval(interval);
        return;
      }
      setActiveIndex(i);
    }, 550);
    return () => window.clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device?.ue_id, replayNonce]);

  function play() {
    setReplayNonce((n) => n + 1);
  }

  if (!device) {
    return (
      <div>
        <PageHeader />
        <div className="empty-state">Run an attack scenario first, then select a device.</div>
      </div>
    );
  }

  const latestStep = device.steps[device.steps.length - 1];
  const overhead = device.comparison_result?.measured_overhead;
  const scores = device.decision_trace?.candidate_scores ?? null;

  return (
    <div>
      <PageHeader />

      <button className="btn btn-primary" onClick={play} disabled={playing} style={{ marginBottom: 20 }}>
        {playing ? <span className="spinner" /> : "Replay flow"}
      </button>

      <div style={{ display: "flex", alignItems: "stretch", gap: 8, overflowX: "auto", paddingBottom: 8 }}>
        {STAGES.map((stage, i) => (
          <div key={stage.key} style={{ display: "flex", alignItems: "center" }}>
            <div
              className={`card ${i === activeIndex && playing ? "pulse-active" : ""}`}
              style={{
                minWidth: 150,
                borderColor: i <= activeIndex ? "var(--accent-green-start)" : "var(--border-subtle)",
                boxShadow: i === activeIndex && playing ? "0 0 16px 4px var(--accent-green-glow)" : "none",
                transition: "box-shadow 300ms ease, border-color 300ms ease",
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  textTransform: "uppercase",
                  letterSpacing: "0.04em",
                  color: "var(--text-muted)",
                  fontWeight: 700,
                }}
              >
                {stage.label}
              </div>
              <div
                style={{
                  marginTop: 6,
                  fontSize: 12,
                  color: i <= activeIndex ? "var(--text-primary)" : "var(--text-muted)",
                }}
              >
                {i <= activeIndex || activeIndex === -1 ? "Ready" : "…"}
              </div>
            </div>
            {i < STAGES.length - 1 && (
              <div
                style={{
                  width: 20,
                  height: 2,
                  background: i < activeIndex ? "var(--accent-green-start)" : "var(--border-strong)",
                  transition: "background 300ms ease",
                }}
              />
            )}
          </div>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16, marginTop: 20 }}>
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {activeIndex >= 0 && (
            <Card title="Subscriber">
              <div className="metric-row">
                <span className="metric-label">Identity</span>
                <span className="metric-value mono">{device.masked_identity}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Attack scenario</span>
                <span className="metric-value">{device.attack_scenario}</span>
              </div>
            </Card>
          )}

          {activeIndex >= 1 && latestStep && (
            <Card title="Pre-AMF (Systems)">
              <div className="metric-row">
                <span className="metric-label">Decision</span>
                <span className="metric-value">{latestStep.attack_report.decision}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Attack type</span>
                <span className="metric-value">{latestStep.attack_report.attack_type}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Severity</span>
                <span className="metric-value">{latestStep.attack_report.severity}</span>
              </div>
            </Card>
          )}

          {activeIndex >= 2 && latestStep && (
            <Card title="Privacy — metadata minimization">
              <div className="card-grid">
                <Meter
                  label="Metadata leakage score (unminimized fields)"
                  value={latestStep.privacy_result.metadata_leakage}
                  invertColor
                />
                <Meter label="Privacy score" value={latestStep.privacy_result.privacy_score} />
                {device.steps.length > 1 && (
                  <Sparkline
                    label="Leakage score across steps"
                    values={device.steps.map((s) => s.privacy_result.metadata_leakage)}
                  />
                )}
              </div>
              <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
                {([
                  ["gNB IP", latestStep.minimization.gnb_ip],
                  ["UE ID", latestStep.minimization.ue_id],
                  ["SUCI", latestStep.minimization.suci],
                  ["DNN", latestStep.minimization.dnn],
                  ["S-NSSAI", latestStep.minimization.snssai],
                  ["Timestamp", latestStep.minimization.timestamp],
                ] as const).map(([label, field]) => (
                  <div key={label} className="metric-row" style={{ fontFamily: "monospace", fontSize: 12 }}>
                    <span className="metric-label" style={{ fontFamily: "inherit" }}>{label}</span>
                    <span className="metric-value">
                      {field.original || "—"} <span style={{ color: "var(--text-muted)" }}>→</span>{" "}
                      {field.minimized || "—"}
                    </span>
                  </div>
                ))}
              </div>
              <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>
                Real field-level minimization (privacy/live_context.py's LiveMetadataMinimizer) — pseudonymized
                identifiers, masked gNB IP, generalized DNN/S-NSSAI, relative timestamp. The metadata leakage
                score above is computed from the ORIGINAL (unminimized) fields and is unaffected by this step.
              </p>
            </Card>
          )}

          {activeIndex >= 3 && device.decision_trace && (
            <Card title="Agent — retrieval + reasoning">
              <div className="metric-row">
                <span className="metric-label">Winner</span>
                <span className="metric-value">{schemeFullLabel(device.decision_trace.winner)}</span>
              </div>
              <div className="metric-row">
                <span className="metric-label">Local + cross-UE evidence</span>
                <span className="metric-value">
                  {device.decision_trace.experience_contribution.total_experiences} local
                  {device.explanation?.rules_fired.some((r) => r.includes("RAG")) && " + cross-UE matches"}
                </span>
              </div>
              {device.explanation && (
                <p style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 8 }}>
                  {device.explanation.experience_influence}
                </p>
              )}
            </Card>
          )}

          {activeIndex >= 4 && (
            <Card title="Recommendation">
              <div className="hero-banner" style={{ margin: 0 }}>
                <div className="hero-label">
                  {device.hybrid_combination ? "Hybrid combination" : "Selected scheme"}
                </div>
                <div className="hero-value">
                  {device.hybrid_combination?.join(" + ") ??
                    device.comparison_result?.scheme_b ??
                    device.recommendation?.selected_scheme ??
                    "—"}
                </div>
                <div style={{ fontSize: 13, opacity: 0.75, marginTop: 4 }}>
                  {device.hybrid_combination
                    ? device.hybrid_combination.map(schemeFullLabel).join(" + ")
                    : schemeFullLabel(device.comparison_result?.scheme_b ?? device.recommendation?.selected_scheme)}
                </div>
              </div>
            </Card>
          )}

          {activeIndex >= 5 && overhead && (
            <Card title="Scheme execution (real encryption run)">
              <div className="check4-grid">
                <div>
                  <div className="block-kicker">Before — {schemeFullLabel(overhead.scheme_a)}</div>
                  <div className="metric-row">
                    <span className="metric-label">Generation time</span>
                    <span className="metric-value">{overhead.time_a_ms.toFixed(2)} ms</span>
                  </div>
                  <div className="metric-row">
                    <span className="metric-label">Output size</span>
                    <span className="metric-value">{overhead.size_a_bytes} B</span>
                  </div>
                </div>
                <div>
                  <div className="block-kicker">After — {schemeFullLabel(overhead.scheme_b)}</div>
                  <div className="metric-row">
                    <span className="metric-label">Generation time</span>
                    <span className="metric-value">{overhead.time_b_ms.toFixed(2)} ms</span>
                  </div>
                  <div className="metric-row">
                    <span className="metric-label">Output size</span>
                    <span className="metric-value">{overhead.size_b_bytes} B</span>
                  </div>
                </div>
              </div>
              <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 8 }}>{overhead.note}</p>
            </Card>
          )}

          {activeIndex >= 6 && device.comparison_result && (
            <Card title="Assessment — did the switch actually help?" className="rationale-block">
              <VerdictPill verdict={device.comparison_result.overall_verdict} />
              <p style={{ marginTop: 8, color: "var(--text-secondary)", fontSize: 13 }}>
                {device.comparison_result.verdict_reason}
              </p>
              {device.comparison_result.analytical_rationale && (
                <div className="metric-row">
                  <span className="metric-label">Analytically justified (privacy/security)</span>
                  <span className="metric-value">
                    {String(device.comparison_result.analytical_rationale.analytically_justified)}
                  </span>
                </div>
              )}
              {overhead && (
                <div className="metric-row">
                  <span className="metric-label">Measured efficiency delta (time)</span>
                  <span className="metric-value">{overhead.time_diff_pct}%</span>
                </div>
              )}
            </Card>
          )}
        </div>

        <div>
          <Card title="All 7 schemes — final score">
            {scores ? (
              <SchemeBarChart scores={scores} />
            ) : (
              <span className="empty-state">No scheme comparison for this scenario.</span>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
}

function PageHeader() {
  return (
    <div className="page-header">
      <h1 className="page-title">Pipeline Visualizer</h1>
      <p className="page-subtitle">
        Subscriber → Pre-AMF → Privacy (metadata minimization) → Agent → Recommendation → Scheme
        Execution → Assessment, from real run data.
      </p>
    </div>
  );
}
