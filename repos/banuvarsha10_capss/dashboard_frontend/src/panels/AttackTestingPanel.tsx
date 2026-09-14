import { useEffect, useRef, useState } from "react";
import type { AttackMode, AttackScenario, DevicePoolEntry, DeviceResult } from "../api/types";
import { ATTACK_SCENARIOS, PER_DEVICE_ATTACK_SCENARIOS, MAX_LIVE_DEVICES } from "../api/types";
import { getDevicePool } from "../api/client";
import type { StartRunParams, UseAttackRunReturn } from "../hooks/useAttackRun";
import { Card } from "../components/Card";
import { ColdStartBadge, DeviceOriginBadge, VerdictPill } from "../components/Badge";
import { DeviceStoryCard } from "../components/DeviceStoryCard";
import { schemeFullLabel } from "../components/SchemeLabel";

function formatEta(seconds: number): string {
  if (seconds <= 0) return "almost done";
  if (seconds < 60) return `~${Math.round(seconds)}s remaining`;
  const minutes = Math.round(seconds / 60);
  return `~${minutes} min remaining`;
}

export function AttackTestingPanel({
  attackRun,
  onRun,
  selectedUeId,
  onSelectDevice,
}: {
  // Bug 1 fix: the run's entire live state + streaming subscription is
  // owned by App.tsx (via useAttackRun) so it survives this panel
  // unmounting on tab switches. This panel only reads it and dispatches
  // actions (onRun/attackRun.stop/attackRun.selectDeviceScenario) — it no
  // longer owns any run state of its own.
  attackRun: UseAttackRunReturn;
  onRun: (params: StartRunParams) => void;
  selectedUeId: string | null;
  onSelectDevice: (device: DeviceResult) => void;
}) {
  const [scenario, setScenario] = useState<AttackScenario>("duplicate_registration");
  const [attackMode, setAttackMode] = useState<AttackMode>("same_for_all");
  // Device-pool task: two separate controls replace the old single slider.
  const [devicesThisRun, setDevicesThisRun] = useState(1);
  const [newDevicesCount, setNewDevicesCount] = useState(0);

  const {
    running,
    stopping,
    error,
    deviceStates,
    total,
    viewIndex,
    setViewIndex,
    summary,
    etaSeconds,
    pendingSelection,
    selecting,
    stop: handleStop,
    selectDeviceScenario: handleSelect,
  } = attackRun;

  const [poolEntries, setPoolEntries] = useState<DevicePoolEntry[] | null>(null);
  const [poolCapacity, setPoolCapacity] = useState(MAX_LIVE_DEVICES);

  async function refreshPool() {
    try {
      const resp = await getDevicePool();
      setPoolEntries(resp.devices);
      setPoolCapacity(resp.capacity);
    } catch {
      // Non-critical — the run button doesn't depend on this succeeding.
    }
  }

  useEffect(() => {
    refreshPool();
  }, []);

  // The run just changed the pool (returning devices' run counts, any new
  // additions) — refresh once it finishes, whether or not this panel was
  // mounted continuously for the whole run (it may have just re-mounted
  // after the user navigated away and back). Guarded so a fresh mount
  // during an ALREADY-running run doesn't spuriously refresh immediately.
  const prevRunningRef = useRef(running);
  useEffect(() => {
    if (prevRunningRef.current && !running) refreshPool();
    prevRunningRef.current = running;
  }, [running]);

  // invalid_subscriber bypasses the device pool entirely (see
  // pipeline_service.py's module docstring) — Control 2 is meaningless
  // for it, so the UI hides it rather than implying it does something.
  const isInvalidSubscriberRun = attackMode === "same_for_all" && scenario === "invalid_subscriber";

  function handleRun() {
    onRun({
      attackMode,
      attackScenario: attackMode === "same_for_all" ? scenario : undefined,
      devicesThisRun,
      newDevicesCount,
    });
  }

  const activeIndex = viewIndex ?? (deviceStates.length > 0 ? deviceStates.length - 1 : null);
  const activeState = activeIndex !== null ? deviceStates[activeIndex] : null;

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Attack Testing</h1>
        <p className="page-subtitle">
          Runs against your real Open5GS/UERANSIM stack — real subscribers, real registrations. Each
          device: baseline → attack → Agent compares (suggests, executes both schemes, checks
          stability with 3 more real replays) → verdict. This is genuinely slow — up to 5+ real
          registrations per device.
        </p>
      </div>

      <Card className="card-grid" title="">
        <div className="field-group">
          <span className="field-label">Attack selection</span>
          <div className="toggle-row">
            <button
              type="button"
              className={`btn ${attackMode === "same_for_all" ? "btn-primary" : "btn-secondary"}`}
              onClick={() => setAttackMode("same_for_all")}
              disabled={running}
            >
              Same attack for all devices
            </button>
            <button
              type="button"
              className={`btn ${attackMode === "per_device" ? "btn-primary" : "btn-secondary"}`}
              onClick={() => setAttackMode("per_device")}
              disabled={running}
            >
              Choose per device
            </button>
          </div>
        </div>

        {attackMode === "same_for_all" ? (
          <div className="field-group">
            <label className="field-label" htmlFor="scenario-select">
              Attack scenario
            </label>
            <select
              id="scenario-select"
              className="select"
              value={scenario}
              onChange={(e) => setScenario(e.target.value as AttackScenario)}
              disabled={running}
            >
              {ATTACK_SCENARIOS.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>
        ) : (
          <div className="field-group">
            <span className="field-label">Attack scenario</span>
            <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              You'll pick each device's scenario right after its baseline registration completes.
              (invalid_subscriber isn't offered here — it has no baseline to compare against.)
            </span>
          </div>
        )}

        <div className="field-group">
          <label className="field-label" htmlFor="devices-this-run">
            Devices this run ({devicesThisRun}/{MAX_LIVE_DEVICES})
          </label>
          <input
            id="devices-this-run"
            type="range"
            min={1}
            max={MAX_LIVE_DEVICES}
            step={1}
            value={devicesThisRun}
            onChange={(e) => {
              const next = parseInt(e.target.value, 10);
              setDevicesThisRun(next);
              // Control 2 can never ask for more new devices than the run has room for.
              setNewDevicesCount((cur) => Math.min(cur, next));
            }}
            disabled={running}
          />
        </div>

        {isInvalidSubscriberRun ? (
          <div className="field-group">
            <span className="field-label">New devices to add</span>
            <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              Not applicable — invalid_subscriber always uses fresh, never-provisioned identities and
              never touches the device pool.
            </span>
          </div>
        ) : (
          <div className="field-group">
            <label className="field-label" htmlFor="new-devices-count">
              New devices to add ({newDevicesCount}/{devicesThisRun})
            </label>
            <input
              id="new-devices-count"
              type="number"
              className="select"
              min={0}
              max={devicesThisRun}
              step={1}
              value={newDevicesCount}
              onChange={(e) => {
                const raw = parseInt(e.target.value, 10);
                const clamped = Number.isNaN(raw) ? 0 : Math.max(0, Math.min(raw, devicesThisRun));
                setNewDevicesCount(clamped);
              }}
              disabled={running}
            />
            <span style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 2 }}>
              {devicesThisRun - newDevicesCount} returning
              {poolEntries !== null && ` (pool has ${poolEntries.length}/${poolCapacity})`} + {newDevicesCount} new.
              Default 0 — reuse the pool; raise this to demonstrate cold-start + RAG.
            </span>
          </div>
        )}

        <div className="field-group" style={{ justifyContent: "flex-end", gap: 8 }}>
          {running && (
            <button
              className="btn btn-secondary"
              onClick={handleStop}
              disabled={stopping}
              title="Stops before the next real step/device — never kills a registration mid-flight"
            >
              {stopping ? "Stopping…" : "Stop attack"}
            </button>
          )}
          <button className="btn btn-primary" onClick={handleRun} disabled={running}>
            {running ? (
              <span className="spinner" />
            ) : (
              `Run (${devicesThisRun} real device${devicesThisRun > 1 ? "s" : ""})`
            )}
          </button>
        </div>
      </Card>

      <div style={{ marginTop: 12 }}>
        <Card>
          <span style={{ color: "var(--status-warning)", fontWeight: 600 }}>
            Every run is real — against your real Open5GS/UERANSIM stack
          </span>
          <p style={{ color: "var(--text-secondary)", marginTop: 4, marginBottom: 0 }}>
            Each device adds a real subscriber to your Open5GS MongoDB and launches real{" "}
            <code>nr-ue</code> processes (requires a gNB already running and sudo access). One
            device's failure does not abort the rest of the batch.
            {etaSeconds !== null && running && (
              <>
                {" "}
                <strong>{formatEta(etaSeconds)}.</strong>
              </>
            )}
          </p>
        </Card>
      </div>

      {poolEntries !== null && (
        <div style={{ marginTop: 12 }}>
          <Card title={`Device pool (${poolEntries.length}/${poolCapacity})`}>
            {poolEntries.length === 0 ? (
              <p style={{ color: "var(--text-secondary)", margin: 0 }}>
                Empty — every device this run will be freshly generated. Devices you run are added here
                automatically and reused in future sessions.
              </p>
            ) : (
              <div className="device-grid">
                {poolEntries.map((d) => (
                  <div className="device-chip" key={d.imsi} style={{ cursor: "default" }}>
                    <div className="device-chip-top">
                      <span className="mono">{d.masked_identity}</span>
                      <span className="badge badge-neutral">
                        {d.total_times_run} run{d.total_times_run === 1 ? "" : "s"}
                      </span>
                    </div>
                    <span style={{ fontSize: 10, color: "var(--text-muted)" }}>
                      First seen {new Date(d.first_seen).toLocaleDateString()}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      )}

      {pendingSelection && (
        <div style={{ marginTop: 12 }}>
          <Card title={`Device ${pendingSelection.index + 1}: pick its attack scenario`}>
            <p style={{ color: "var(--text-secondary)", marginTop: 0 }}>
              This device's baseline registration is done. Pick what happens next — the batch is
              paused on this device until you choose.
            </p>
            <div className="toggle-row">
              {PER_DEVICE_ATTACK_SCENARIOS.map((s) => (
                <button
                  key={s.value}
                  type="button"
                  className="btn btn-primary"
                  disabled={selecting}
                  onClick={() => handleSelect(pendingSelection.index, s.value)}
                >
                  {s.label}
                </button>
              ))}
            </div>
          </Card>
        </div>
      )}

      {error && (
        <div style={{ marginTop: 12 }}>
          <Card>
            <span style={{ color: "var(--status-critical)" }}>{error}</span>
          </Card>
        </div>
      )}

      {summary && (
        <div className="card-grid" style={{ marginTop: 24, marginBottom: 16 }}>
          <Card title="Verdict counts">
            {Object.entries(summary.verdict_counts).map(([verdict, count]) => (
              <div className="metric-row" key={verdict}>
                <span className="metric-label">
                  <VerdictPill verdict={verdict as never} />
                </span>
                <span className="metric-value">{count}</span>
              </div>
            ))}
          </Card>
          <Card title="Cold-start + RAG contribution">
            <div className="hero-banner" style={{ margin: 0 }}>
              <div className="hero-label">Devices demonstrating cold-start + cross-UE RAG</div>
              <div className="hero-value">
                {summary.cold_start_rag_count} / {summary.total_devices}
              </div>
            </div>
          </Card>
          <Card title="Real stability + overhead">
            <div className="metric-row">
              <span className="metric-label">Real stability confirmed</span>
              <span className="metric-value">
                {summary.real_stability_confirmed_count ?? 0} / {summary.real_stability_eligible_count ?? 0}
              </span>
            </div>
            <div className="metric-row">
              <span className="metric-label">Avg. measured overhead (time_diff_pct)</span>
              <span className="metric-value">{summary.avg_overhead_delta ?? "n/a"}%</span>
            </div>
            {summary.live_failures !== undefined && summary.live_failures > 0 && (
              <div className="metric-row">
                <span className="metric-label">Failures</span>
                <span className="metric-value" style={{ color: "var(--status-critical)" }}>
                  {summary.live_failures}
                </span>
              </div>
            )}
            {summary.cancelled_count !== undefined && summary.cancelled_count > 0 && (
              <div className="metric-row">
                <span className="metric-label">Cancelled (stopped by user)</span>
                <span className="metric-value">{summary.cancelled_count}</span>
              </div>
            )}
          </Card>
        </div>
      )}

      {activeState && (
        <div style={{ marginTop: summary ? 0 : 24 }}>
          <DeviceStoryCard state={activeState} total={total} />
        </div>
      )}

      {deviceStates.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <Card title={`Devices (${total})`}>
            <div className="device-grid">
              {Array.from({ length: total }).map((_, i) => {
                const s = deviceStates[i];
                if (!s) {
                  return (
                    <div className="device-chip device-chip-queued" key={i}>
                      <div className="device-chip-top">
                        <span>Device {i + 1}</span>
                        <span className="badge badge-neutral">Queued</span>
                      </div>
                    </div>
                  );
                }
                const liveFailed = s.failureReason !== null;
                // Stop-attack task (Part 2): a cancelled device is NOT a
                // failure — nothing about it went wrong, it just wasn't
                // run (or wasn't finished) because the user asked the
                // batch to stop. Must read distinctly from "Failed".
                const cancelled = s.device?.cancelled === true;
                return (
                  <div
                    className={`device-chip ${activeIndex === i ? "is-active" : ""}`}
                    key={i}
                    onClick={() => {
                      setViewIndex(i);
                      if (s.device) onSelectDevice(s.device);
                    }}
                  >
                    <div className="device-chip-top">
                      <span className="mono">{s.maskedIdentity ?? `Device ${i + 1}`}</span>
                      {s.status === "processing" ? (
                        <span className="spinner" />
                      ) : cancelled ? (
                        <span className="badge badge-neutral">Cancelled</span>
                      ) : liveFailed ? (
                        <span className="badge badge-mode-live">Failed</span>
                      ) : s.finalVerdict ? (
                        <VerdictPill verdict={s.finalVerdict as never} />
                      ) : (
                        <span className="badge badge-neutral">Done</span>
                      )}
                    </div>
                    {s.comparison && (
                      <span
                        className="device-chip-scheme"
                        title={`${schemeFullLabel(s.comparison.scheme_a)} → ${schemeFullLabel(s.comparison.scheme_b)}`}
                      >
                        {s.comparison.scheme_a} → {s.comparison.scheme_b}
                      </span>
                    )}
                    {s.ueId === selectedUeId && (
                      <span style={{ fontSize: 10, color: "var(--accent-green-start)" }}>Selected</span>
                    )}
                    {s.status === "done" && (
                      <div style={{ display: "flex", gap: 4, flexWrap: "wrap", marginTop: 4 }}>
                        <DeviceOriginBadge origin={s.device?.device_origin} />
                        {s.ueId && s.device?.cold_start && <ColdStartBadge />}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </Card>
        </div>
      )}

      {deviceStates.length === 0 && !running && (
        <div className="empty-state">Run a scenario above to see results.</div>
      )}
    </div>
  );
}
