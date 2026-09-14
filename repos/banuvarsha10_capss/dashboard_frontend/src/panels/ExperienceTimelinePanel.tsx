import { useEffect, useState } from "react";
import type { ExperienceStats, ExperienceTimeline } from "../api/types";
import { getExperienceStats, getExperienceUes, getExperienceTimeline, clearExperienceStore } from "../api/client";
import { Card } from "../components/Card";
import { ConfidenceTrendChart } from "../components/ConfidenceTrendChart";

export function ExperienceTimelinePanel({ selectedUeId }: { selectedUeId: string | null }) {
  const [stats, setStats] = useState<ExperienceStats | null>(null);
  const [ueIds, setUeIds] = useState<string[]>([]);
  const [activeUe, setActiveUe] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<ExperienceTimeline | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [clearing, setClearing] = useState(false);

  function loadOverview() {
    getExperienceStats().then(setStats).catch(() => {});
    getExperienceUes()
      .then((res) => {
        setUeIds(res.ue_ids);
        setActiveUe(selectedUeId && res.ue_ids.includes(selectedUeId) ? selectedUeId : res.ue_ids[0] ?? null);
      })
      .catch(() => {});
  }

  useEffect(() => {
    loadOverview();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Part 3 (clear-experience-store): destructive, so gated behind a real
  // confirmation naming exactly what's lost — never a single click. Does
  // NOT touch the device pool (device_pool.json) — that's a deliberately
  // separate, independently-controllable thing (device-pool task); the
  // backend endpoint enforces this, not just this dialog's wording.
  async function handleClear() {
    const confirmed = window.confirm(
      "This will permanently clear all accumulated experience history for all devices " +
        "(scheme-selection history, EAS/RAG signal). This cannot be undone.\n\n" +
        "The device pool (real subscriber identities) is NOT affected — those devices " +
        "remain reusable, just with no history.\n\nClear experience history now?",
    );
    if (!confirmed) return;
    setClearing(true);
    setError(null);
    try {
      await clearExperienceStore();
      setTimeline(null);
      setActiveUe(null);
      loadOverview();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to clear the experience store.");
    } finally {
      setClearing(false);
    }
  }

  useEffect(() => {
    if (!activeUe) return;
    setError(null);
    getExperienceTimeline(activeUe)
      .then(setTimeline)
      .catch((err) => setError(err.message ?? "Failed to load timeline"));
  }, [activeUe]);

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Experience Memory + Timeline</h1>
        <p className="page-subtitle">
          One UE's recommendation history over time — scheme changes and confidence trend.
        </p>
      </div>

      <div className="card-grid" style={{ marginBottom: 16 }}>
        <Card title="Overall experience store">
          <div className="metric-row">
            <span className="metric-label">Total experiences</span>
            <span className="metric-value">{stats?.total_experiences ?? "—"}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Distinct UEs</span>
            <span className="metric-value">{stats?.total_ues ?? "—"}</span>
          </div>
          <div className="metric-row">
            <span className="metric-label">Avg. per UE</span>
            <span className="metric-value">{stats?.avg_per_ue?.toFixed(2) ?? "—"}</span>
          </div>
          <button
            className="btn btn-secondary"
            onClick={handleClear}
            disabled={clearing || !stats?.total_experiences}
            style={{ marginTop: 12, width: "100%", color: "var(--status-critical)" }}
          >
            {clearing ? "Clearing…" : "Clear experience store"}
          </button>
        </Card>

        <Card title="Select UE">
          <select
            className="select"
            value={activeUe ?? ""}
            onChange={(e) => setActiveUe(e.target.value)}
            style={{ width: "100%" }}
          >
            {ueIds.length === 0 && <option value="">No UEs with experience yet</option>}
            {ueIds.map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </Card>
      </div>

      {error && <div className="empty-state">{error}</div>}

      {timeline && (
        <>
          <Card title="Confidence trend" className="card-raised">
            <ConfidenceTrendChart entries={timeline.confidence_trend} />
          </Card>

          <div style={{ marginTop: 16 }}>
            <Card title="Adaptation history">
              {timeline.adaptation_history.length === 0 ? (
                <span className="empty-state">No scheme changes recorded for this UE yet.</span>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>From</th>
                      <th>To</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {timeline.adaptation_history.map((h, i) => (
                      <tr key={i}>
                        <td className="mono">{h.timestamp}</td>
                        <td>{h.from}</td>
                        <td>{h.to}</td>
                        <td style={{ color: "var(--text-secondary)" }}>{h.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
