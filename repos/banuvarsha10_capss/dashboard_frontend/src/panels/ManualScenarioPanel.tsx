import { useState } from "react";
import type { DeviceResult, IdentityPair, ManualScenarioInput, StreamEvent } from "../api/types";
import { DEFAULT_MANUAL_SCENARIO } from "../api/types";
import { streamManualScenario, ApiError } from "../api/client";
import { Card } from "../components/Card";
import { VerdictPill } from "../components/Badge";
import { DeviceStoryCard } from "../components/DeviceStoryCard";
import type { DeviceStoryState } from "../components/DeviceStoryCard";
import { SCHEME_FULL_NAMES } from "../components/SchemeLabel";

const SLIDERS: { key: keyof ManualScenarioInput; label: string }[] = [
  { key: "threat_score", label: "Threat score" },
  { key: "privacy_score", label: "Privacy score" },
  { key: "metadata_leakage", label: "Metadata leakage" },
  { key: "correlation_score", label: "Correlation / tracking risk" },
  { key: "detection_confidence", label: "Attack detection confidence" },
];

function emptyState(): DeviceStoryState {
  return {
    index: 0,
    ueId: null,
    maskedIdentity: null,
    status: "processing",
    stages: [],
    comparison: null,
    decisionTrace: null,
    finalVerdict: null,
    verdictReason: null,
    failureReason: null,
    device: null,
  };
}

interface HistoryEntry {
  input: ManualScenarioInput;
  scheme: string;
  verdict: string;
}

export function ManualScenarioPanel({ onResult }: { onResult: (device: DeviceResult) => void }) {
  const [input, setInput] = useState<ManualScenarioInput>(DEFAULT_MANUAL_SCENARIO);
  const [pinnedIdentity, setPinnedIdentity] = useState<IdentityPair | null>(null);
  const [state, setState] = useState<DeviceStoryState>(emptyState());
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function setField<K extends keyof ManualScenarioInput>(key: K, value: ManualScenarioInput[K]) {
    setInput((prev) => ({ ...prev, [key]: value }));
  }

  function handleEvent(event: StreamEvent) {
    if (event.type === "stage") {
      setState((prev) => {
        const stages = [...prev.stages, { stage: event.stage!, data: event as Record<string, unknown> }];
        const comparison = event.stage === "assessment_done" && event.comparison ? event.comparison : prev.comparison;
        const decisionTrace =
          event.stage === "ranking_done" && event.decision_trace ? event.decision_trace : prev.decisionTrace;
        return { ...prev, stages, comparison, decisionTrace };
      });
    } else if (event.type === "device_done") {
      const device = event.device!;
      setState((prev) => ({
        ...prev,
        status: "done",
        ueId: device.ue_id,
        maskedIdentity: device.masked_identity,
        comparison: device.comparison_result,
        decisionTrace: device.decision_trace,
        finalVerdict: device.comparison_result?.overall_verdict ?? null,
        verdictReason: device.comparison_result?.verdict_reason ?? null,
        device,
      }));
      onResult(device);
      setHistory((prev) => [
        ...prev,
        {
          input,
          scheme: device.comparison_result?.scheme_b ?? device.recommendation?.selected_scheme ?? "—",
          verdict: device.comparison_result?.overall_verdict ?? "NO_COMPARISON",
        },
      ]);
    } else if (event.type === "batch_done") {
      if (event.identities && event.identities.length > 0) setPinnedIdentity(event.identities[0]);
    }
  }

  async function handleGenerate() {
    setLoading(true);
    setError(null);
    setState(emptyState());
    try {
      await streamManualScenario(input, pinnedIdentity, handleEvent);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to generate recommendation");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Manual Scenario Builder</h1>
        <p className="page-subtitle">
          Build a synthetic registration context directly and run it through the same real
          pipeline as Attack Testing.
        </p>
      </div>

      <Card>
        <div className="metric-row" style={{ marginBottom: 8 }}>
          <span className="metric-label">Device</span>
          <span className="metric-value">
            {pinnedIdentity ? (
              <>
                <span className="mono">{pinnedIdentity.ue_id}</span>
                <button
                  className="btn btn-secondary"
                  style={{ marginLeft: 12, padding: "4px 10px", fontSize: 11 }}
                  onClick={() => {
                    setPinnedIdentity(null);
                    setHistory([]);
                  }}
                  disabled={loading}
                >
                  New device
                </button>
              </>
            ) : (
              <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>
                A fresh device will be generated on first run, then reused for every scenario
                below so results are comparable.
              </span>
            )}
          </span>
        </div>

        <div className="card-grid">
          {SLIDERS.map((s) => (
            <div className="field-group" key={s.key}>
              <label className="field-label">
                {s.label}: {(input[s.key] as number).toFixed(2)}
              </label>
              <input
                type="range"
                min={0}
                max={1}
                step={0.01}
                value={input[s.key] as number}
                onChange={(e) => setField(s.key, parseFloat(e.target.value) as never)}
              />
            </div>
          ))}

          <div className="field-group">
            <label className="field-label">Registration type</label>
            <select
              className="select"
              value={input.registration_type}
              onChange={(e) => setField("registration_type", e.target.value as never)}
            >
              <option value="initial">Initial</option>
              <option value="mobility">Mobility</option>
              <option value="periodic">Periodic</option>
              <option value="emergency">Emergency</option>
            </select>
          </div>

          <div className="field-group">
            <label className="field-label">Request classification</label>
            <select
              className="select"
              value={input.request_classification}
              onChange={(e) => setField("request_classification", e.target.value as never)}
            >
              <option value="ALLOW">ALLOW</option>
              <option value="TAG">TAG</option>
              <option value="BLOCK">BLOCK</option>
            </select>
          </div>

          <div className="field-group">
            <label className="field-label">Attack type (optional)</label>
            <input
              className="field-input"
              value={input.attack_type ?? ""}
              onChange={(e) => setField("attack_type", (e.target.value || null) as never)}
              placeholder="e.g. flooding, replay"
            />
          </div>
        </div>

        <button className="btn btn-primary" style={{ marginTop: 16 }} onClick={handleGenerate} disabled={loading}>
          {loading ? <span className="spinner" /> : "Generate Recommendation"}
        </button>
      </Card>

      {error && (
        <div style={{ marginTop: 12 }}>
          <Card>
            <span style={{ color: "var(--status-critical)" }}>{error}</span>
          </Card>
        </div>
      )}

      {state.stages.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <DeviceStoryCard state={state} total={1} />
        </div>
      )}

      {history.length > 1 && (
        <div style={{ marginTop: 16 }}>
          <Card title={`This device's history (${history.length} runs)`}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Threat</th>
                  <th>Attack type</th>
                  <th>Scheme</th>
                  <th>Verdict</th>
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i}>
                    <td>{i + 1}</td>
                    <td>{h.input.threat_score.toFixed(2)}</td>
                    <td>{h.input.attack_type ?? "—"}</td>
                    <td className="mono" title={SCHEME_FULL_NAMES[h.scheme] ?? h.scheme}>
                      {h.scheme}
                    </td>
                    <td>
                      <VerdictPill verdict={h.verdict as never} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </div>
      )}
    </div>
  );
}
