import type { DeviceResult, DeviceStep } from "../api/types";
import { Card } from "../components/Card";
import { Sparkline } from "../components/Sparkline";
import { Meter } from "../components/Meter";

export function SystemsPrivacyPanel({ device }: { device: DeviceResult | null }) {
  if (!device) {
    return (
      <div>
        <PageHeader />
        <div className="empty-state">Run an attack scenario first, then select a device.</div>
      </div>
    );
  }

  if (device.steps.length === 0) {
    return (
      <div>
        <PageHeader />
        <div className="empty-state">
          {device.failure_reason ?? "No Systems/Privacy step data recorded for this device."}
        </div>
      </div>
    );
  }

  const privacyTrend = device.steps.map((s) => s.privacy_result.privacy_score);
  // Investigation fix: was `1 - metadata_leakage` under an "exposure" label —
  // the same unintended-inversion bug class already fixed in Pipeline
  // Visualizer (which shows the RAW leakage/exposure value + Meter's
  // `invertColor`, never an inverted number — see Meter.tsx's own docstring
  // for why that's the correct pattern for "a raw leakage/exposure score").
  // An "exposure" label showing 0.15 when the real, unminimized-field
  // exposure is 0.85 is self-contradictory and was never justified by any
  // comment here, unlike every other deliberate framing choice in this
  // codebase. Now shows the real metadata_leakage value directly, matching
  // Pipeline Visualizer exactly.
  const exposureTrend = device.steps.map((s) => s.privacy_result.metadata_leakage);
  const correlationTrend = device.steps.map((s) => s.privacy_result.correlation_score);
  const latest = device.steps[device.steps.length - 1];

  return (
    <div>
      <PageHeader />

      {device.steps.length > 1 && (
        <Card title={`Privacy metrics across ${device.steps.length} registration steps`} className="card-grid">
          <Sparkline label="Privacy score" values={privacyTrend} />
          <Sparkline label="Metadata exposure (unminimized fields)" values={exposureTrend} />
          <Sparkline label="Correlation / tracking risk" values={correlationTrend} />
        </Card>
      )}

      <div style={{ marginTop: 16 }}>
        <Card title="Metadata exposure — latest state">
          <div className="card-grid">
            <Meter
              label="Metadata exposure score"
              value={latest.privacy_result.metadata_leakage}
              invertColor
              detail={`Raw metadata_leakage: ${latest.privacy_result.metadata_leakage.toFixed(2)} (lower is better) — computed from the ORIGINAL, unminimized fields`}
            />
            <Meter
              label="Privacy score"
              value={latest.privacy_result.privacy_score}
              detail={`Risk level: ${latest.privacy_result.privacy_risk_level}`}
            />
            <Meter
              label="Anti-correlation"
              value={1 - latest.privacy_result.correlation_score}
              detail={`Raw correlation_score: ${latest.privacy_result.correlation_score.toFixed(2)} (lower is better)`}
            />
          </div>
        </Card>
      </div>

      <div style={{ marginTop: 16 }}>
        <Card title="Real metadata minimization — latest state">
          <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
            {([
              ["gNB IP", latest.minimization.gnb_ip],
              ["UE ID", latest.minimization.ue_id],
              ["SUCI", latest.minimization.suci],
              ["DNN", latest.minimization.dnn],
              ["S-NSSAI", latest.minimization.snssai],
              ["Timestamp", latest.minimization.timestamp],
            ] as const).map(([label, field]) => (
              <div key={label} className="metric-row" style={{ fontFamily: "monospace", fontSize: 12 }}>
                <span className="metric-label" style={{ fontFamily: "inherit" }}>{label}</span>
                <span className="metric-value">
                  {field.original || "—"} <span style={{ color: "var(--text-muted)" }}>→</span> {field.minimized || "—"}
                </span>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <div style={{ marginTop: 16, display: "flex", flexDirection: "column", gap: 16 }}>
        {device.steps.map((step, i) => (
          <StepCard key={step.request_id} step={step} index={i} isLast={i === device.steps.length - 1} />
        ))}
      </div>
    </div>
  );
}

function StepCard({ step, index, isLast }: { step: DeviceStep; index: number; isLast: boolean }) {
  const vb = step.validation_breakdown;
  return (
    <Card title={`Step ${index + 1}${isLast ? " (final)" : ""} — ${step.request_id}`}>
      <div className="check4-grid">
        <div>
          <div className="block-kicker">Systems Module (Pre-AMF)</div>
          <div className="metric-row">
            <span className="metric-label">Decision</span>
            <span className="metric-value">{step.attack_report.decision}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Attack type</span>
            <span className="metric-value">{step.attack_report.attack_type}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Severity</span>
            <span className="metric-value">{step.attack_report.severity}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Risk score</span>
            <span className="metric-value">{step.attack_report.risk_score.toFixed(1)}</span>
          </div>

          <div style={{ marginTop: 10, display: "flex", flexWrap: "wrap", gap: 6 }}>
            <ValidatorBadge label="Header" passed={vb.header_result.passed} />
            <ValidatorBadge label="Parameter" passed={vb.parameter_result.passed} />
            <ValidatorBadge label="Subscriber" passed={vb.subscriber_result.passed} />
            <ValidatorBadge label="Duplicate/Replay" passed={!vb.duplicate_result.detected} />
            <ValidatorBadge label="Rate/Flood" passed={!vb.rate_result.detected} />
          </div>
        </div>

        <div>
          <div className="block-kicker">Privacy Module</div>
          <div className="metric-row">
            <span className="metric-label">Privacy score</span>
            <span className="metric-value">{step.privacy_result.privacy_score.toFixed(2)}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Risk level</span>
            <span className="metric-value">{step.privacy_result.privacy_risk_level}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Metadata exposure (unminimized)</span>
            <span className="metric-value">{((1 - step.privacy_result.metadata_leakage) * 100).toFixed(0)}%</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Correlation score</span>
            <span className="metric-value">{step.privacy_result.correlation_score.toFixed(2)}</span>
          </div>
        </div>
      </div>
    </Card>
  );
}

function ValidatorBadge({ label, passed }: { label: string; passed: boolean }) {
  return (
    <span className={`badge ${passed ? "badge-mode-normal" : "badge-mode-live"}`}>
      {label}: {passed ? "OK" : "Flagged"}
    </span>
  );
}

function PageHeader() {
  return (
    <div className="page-header">
      <h1 className="page-title">Systems + Privacy Modules</h1>
      <p className="page-subtitle">
        Per-step Pre-AMF validation results, privacy/metadata-exposure metrics, and real
        field-level metadata minimization for the selected device.
      </p>
    </div>
  );
}
