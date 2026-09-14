import type { ComparisonResult, DecisionTrace, DeviceResult, ExecutionResultJSON } from "../api/types";
import { STAGE_LABELS } from "../api/types";
import { DeviceOriginBadge, VerdictPill } from "./Badge";
import { SCHEME_FULL_NAMES } from "./SchemeLabel";

export interface StageEntry {
  stage: string;
  data: Record<string, unknown>;
}

export interface DeviceStoryState {
  index: number;
  ueId: string | null;
  maskedIdentity: string | null;
  status: "processing" | "done";
  stages: StageEntry[];
  comparison: ComparisonResult | null;
  decisionTrace: DecisionTrace | null;
  finalVerdict: string | null;
  verdictReason: string | null;
  failureReason: string | null;
  device: DeviceResult | null;
}

/**
 * Live narrative view of ONE device's real journey through the pipeline —
 * baseline registration → Agent's baseline preview (+ real execution) →
 * attack selected → real attack registration → Agent compares (suggests,
 * executes both schemes, checks stability with 3 more real replays) →
 * ranked → verdict. Every number shown here is real data that already
 * arrived from the backend; nothing is fabricated for effect.
 */
export function DeviceStoryCard({ state, total }: { state: DeviceStoryState; total: number }) {
  return (
    <div className="story-card">
      <div className="story-card-header">
        <span className="story-card-identity">
          {state.maskedIdentity ?? "Provisioning real subscriber…"}
          {state.status === "done" && (
            <span style={{ marginLeft: 8, verticalAlign: "middle" }}>
              <DeviceOriginBadge origin={state.device?.device_origin} />
            </span>
          )}
        </span>
        <span className="story-progress-count">
          Device {state.index + 1} / {total}
        </span>
      </div>

      <div className="story-stepper">
        {state.stages.map((entry, i) => (
          <StageRow
            key={`${entry.stage}-${i}`}
            entry={entry}
            isLast={i === state.stages.length - 1 && state.status === "processing"}
            comparison={state.comparison}
            decisionTrace={state.decisionTrace}
          />
        ))}
        {state.status === "processing" && state.stages.length === 0 && (
          <StageRow entry={{ stage: "credentials_ready", data: {} }} isLast comparison={null} decisionTrace={null} />
        )}
      </div>

      {state.status === "done" && (
        <div style={{ marginTop: 4 }}>
          {state.finalVerdict ? (
            <>
              <VerdictPill verdict={state.finalVerdict as never} />
              {state.verdictReason && (
                <p style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 8 }}>
                  {state.verdictReason}
                </p>
              )}
            </>
          ) : state.failureReason ? (
            <span className="badge badge-mode-live">Failed: {state.failureReason}</span>
          ) : (
            <span className="badge badge-neutral">No comparison for this scenario</span>
          )}
          <HybridBadge device={state.device} />
          <DualExecutionPanel device={state.device} />
          <SimulatedStabilityPanel device={state.device} />
          <RealStabilityPanel device={state.device} />
          <HistoryBasedBaselinePreview device={state.device} />
        </div>
      )}
    </div>
  );
}

function HybridBadge({ device }: { device: DeviceResult | null }) {
  if (!device) return null;
  const hybrid = device.hybrid_combination ?? device.recommendation?.hybrid_schemes ?? null;
  if (!hybrid || hybrid.length < 2) return null;
  return (
    <div style={{ marginTop: 8 }}>
      <span
        className="badge"
        style={{ background: "var(--accent-purple-dim)", color: "var(--accent-purple)" }}
        title={hybrid.map((h) => `${h}: ${SCHEME_FULL_NAMES[h] ?? h}`).join(" · ")}
      >
        Hybrid: {hybrid.join(" + ")}
      </span>
    </div>
  );
}

function hexPreview(hex: string | null, maxBytes = 16): string {
  if (!hex) return "—";
  const truncated = hex.slice(0, maxBytes * 2);
  return truncated.length < hex.length ? `${truncated}…` : truncated;
}

function ExecutionCard({ title, execution }: { title: string; execution: ExecutionResultJSON | null }) {
  if (!execution) return null;
  return (
    <div style={{ flex: "1 1 220px", minWidth: 200 }}>
      <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 2 }}>{title}</div>
      <div className="mono" style={{ fontSize: 13, fontWeight: 700 }}>
        {execution.scheme_name}
        {execution.is_placeholder && (
          <span style={{ fontSize: 10, color: "var(--status-warning)", marginLeft: 6 }}>placeholder</span>
        )}
      </div>
      <div style={{ fontSize: 10.5, color: "var(--text-muted)" }}>
        {SCHEME_FULL_NAMES[execution.scheme_name] ?? execution.scheme_name}
      </div>
      <div style={{ fontSize: 11, color: "var(--text-secondary)" }}>
        {execution.generation_time_ms.toFixed(2)}ms · {execution.output_size_bytes}B · {execution.output_type}
      </div>
      <div className="mono" style={{ fontSize: 10, color: "var(--text-muted)", wordBreak: "break-all" }}>
        {hexPreview(execution.output_value_hex)}
      </div>
    </div>
  );
}

/** Part F step 11: the REAL, forced-baseline scheme's execution (scheme_a,
 * per the baseline-forcing fix — ECIES/ML-KEM by real batch position,
 * never history-influenced), shown alongside the official attack-time
 * scheme_b execution — the "before, now this circumstance chose ML-KEM"
 * moment.
 *
 * Baseline-forcing-fix data-wiring fix: "Baseline (before the attack)"
 * and "Attack-time — scheme A" now BOTH read device.scheme_a_execution —
 * they are, by design, the same real execution shown under two temporal
 * labels (the forced baseline no longer varies between "before" and
 * "attack-time", so there is no longer a second, different value to show
 * here). Previously this card read device.baseline_execution, a SEPARATE,
 * still history-influenced computation the baseline-forcing fix never
 * touched — see HistoryBasedBaselinePreview below for what that value
 * became: a separate, clearly-labeled, relocated informational preview,
 * never shown as if it were the real baseline again. */
function DualExecutionPanel({ device }: { device: DeviceResult | null }) {
  if (!device) return null;
  const hasComparison = device.scheme_a_execution !== null && device.scheme_b_execution !== null;
  if (!hasComparison) return null;

  // Fix 2: the HYBRID badge at the top of this card is backed by real
  // data already computed (hybrid-execution-gap fix) and already shown
  // on the Assessment panel's "Hybrid Partner — real execution" block —
  // it was just missing from THIS screen. Reuses comparison_result.
  // hybrid_partner_scheme/hybrid_partner_execution directly, never
  // recomputed or duplicated. Only rendered when the recommendation is
  // actually a hybrid — non-hybrid devices keep exactly the 3 cards
  // above, unchanged.
  const hybridPartnerScheme = device.comparison_result?.hybrid_partner_scheme ?? null;
  const hybridPartnerExecution = device.comparison_result?.hybrid_partner_execution ?? null;

  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 6 }}>
        Real scheme executions
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 16 }}>
        <ExecutionCard title="Baseline (before the attack)" execution={device.scheme_a_execution} />
        <ExecutionCard title={`Attack-time — scheme A (${device.comparison_result?.scheme_a ?? "before"})`} execution={device.scheme_a_execution} />
        <ExecutionCard title={`Attack-time — scheme B (${device.comparison_result?.scheme_b ?? "after"})`} execution={device.scheme_b_execution} />
        {hybridPartnerScheme && hybridPartnerExecution && (
          <ExecutionCard
            title={`Hybrid partner (${hybridPartnerScheme}) — separate from Check 3 above`}
            execution={hybridPartnerExecution}
          />
        )}
      </div>
    </div>
  );
}

/** Baseline-forcing fix: NOT the assessment's real baseline (see
 * DualExecutionPanel's "Baseline" card above for that, now correctly
 * pointed at scheme_a_execution) — this is a separate, purely
 * informational preview of what the Agent's own reasoning, informed by
 * this device's real prior experience history, would have picked BEFORE
 * the attack was known. Kept (not deleted) because it's a real, working
 * signal that proves RAG/history retrieval is still functioning — but
 * deliberately relocated away from the real-executions block and given a
 * visually distinct (dashed, muted) treatment plus an unambiguous label,
 * so it can never again be mistaken for the actual forced baseline used
 * in the comparison above. Backed by device.baseline_execution /
 * pipeline_service.py's Step 5-6 _read_only_recommendation(pre_context)
 * call — intentionally unchanged by this fix (see that function's own
 * docstring for why its history-influenced behavior is correct there). */
function HistoryBasedBaselinePreview({ device }: { device: DeviceResult | null }) {
  const exec = device?.baseline_execution;
  if (!exec) return null;
  return (
    <div
      style={{
        marginTop: 16,
        padding: "10px 12px",
        border: "1px dashed var(--border-strong)",
        borderRadius: 8,
      }}
    >
      <div
        style={{
          fontSize: 11,
          color: "var(--text-muted)",
          textTransform: "uppercase",
          letterSpacing: "0.04em",
          marginBottom: 4,
        }}
      >
        ⓘ Agent's history-based instinct — informational only, NOT the assessment baseline
      </div>
      <p style={{ fontSize: 11, color: "var(--text-muted)", margin: "0 0 8px", maxWidth: 520 }}>
        What the Agent would have picked from this device's own real prior experience history,
        before the attack was known. The real comparison baseline used throughout the assessment
        above is always the forced ECIES/ML-KEM value (see "Baseline (before the attack)" earlier
        on this card) — this is a separate, real, but purely informational signal, never used in
        any check.
      </p>
      <ExecutionCard title="History-based pick" execution={exec} />
    </div>
  );
}

/** Diagnosis fix (Finding 3): assess_adaptation()'s OWN internal Check 2 —
 * `replay_count` more agent-only calls on the identical attack_context,
 * ENTIRELY in-process, no real hardware involved at all. Deliberately
 * rendered as its own distinctly-labeled, distinctly-styled block, right
 * next to RealStabilityPanel below, so the two real-but-different
 * stability signals can never again read as one contradictory
 * measurement — see RealStabilityPanel's disagreement note for why they
 * can legitimately differ. stability_confirmed/stability_detail
 * themselves are untouched by this fix — presentation only. */
function SimulatedStabilityPanel({ device }: { device: DeviceResult | null }) {
  const cr = device?.comparison_result;
  if (!cr) return null;
  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 6 }}>
        Simulated Stability (Check 2 — internal reasoning only, no hardware)
      </div>
      <span
        className="badge"
        style={{
          background: cr.stability_confirmed ? "var(--accent-green-dim, rgba(0,255,157,0.12))" : "var(--status-warning)",
          color: cr.stability_confirmed ? "var(--accent-green-start)" : "#000",
        }}
      >
        {cr.stability_detail}
      </span>
    </div>
  );
}

/** Part F step 10: 3 REAL nr-ue replay registrations confirming (or not)
 * that the Agent still picks scheme_b — distinct from ComparisonResult's
 * own simulated stability_confirmed (SimulatedStabilityPanel above;
 * assess_adaptation()'s internal Check 2, untouched by this fix), shown
 * here as a separate real signal. real_stability itself is unchanged by
 * this fix — presentation only. */
function RealStabilityPanel({ device }: { device: DeviceResult | null }) {
  const rs = device?.real_stability;
  if (!rs) return null;
  const cr = device?.comparison_result;
  // Only a meaningful disagreement when Check 2 actually ran on the
  // simulated side (adaptation_occurred) — a NO_CHANGE verdict SKIPS
  // Check 2 entirely (stability_confirmed=False trivially, "stability
  // check skipped"), which isn't the classification-drift phenomenon
  // this note explains and would be a misleading explanation there.
  const disagree =
    (cr?.adaptation_occurred ?? false) &&
    cr?.stability_confirmed !== undefined &&
    cr.stability_confirmed !== rs.confirmed;
  return (
    <div style={{ marginTop: 12 }}>
      <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em", marginBottom: 6 }}>
        Real Hardware Stability (live replay registrations)
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
        <span
          className="badge"
          style={{
            background: rs.confirmed ? "var(--accent-green-dim, rgba(0,255,157,0.12))" : "var(--status-warning)",
            color: rs.confirmed ? "var(--accent-green-start)" : "#000",
          }}
        >
          {rs.detail}
        </span>
        {rs.replays.map((r) => (
          <span key={r.replay_number} className="mono" style={{ fontSize: 11, color: "var(--text-secondary)" }}>
            #{r.replay_number}: {r.predicted_scheme ?? "?"} {r.matches_scheme_b ? "✓" : "✗"}
          </span>
        ))}
      </div>
      {disagree && (
        <p style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6, fontStyle: "italic", maxWidth: 560 }}>
          Simulated Stability and Real Hardware Stability disagree here — this is expected in Live
          Mode, not a bug. Real hardware registrations accumulate real rate/duplicate-detection
          state across the replay sequence, so later replays can be reclassified differently than
          the single fixed context the simulated check reasons over; the simulated check can't see
          that accumulation at all.
        </p>
      )}
    </div>
  );
}

function StageRow({
  entry,
  isLast,
  comparison,
  decisionTrace,
}: {
  entry: StageEntry;
  isLast: boolean;
  comparison: ComparisonResult | null;
  decisionTrace: DecisionTrace | null;
}) {
  const label = STAGE_LABELS[entry.stage] ?? entry.stage;
  const isActive = isLast;

  return (
    <div className="story-stage">
      <div className="story-stage-rail">
        <div className={`story-stage-dot ${isActive ? "is-active" : ""}`} />
        <div className={`story-stage-line ${!isActive ? "is-done" : ""}`} />
      </div>
      <div className="story-stage-body">
        <div className={`story-stage-label ${isActive ? "" : ""}`}>{label}</div>
        <StageDetail entry={entry} comparison={comparison} decisionTrace={decisionTrace} />
      </div>
    </div>
  );
}

function StageDetail({
  entry,
  comparison,
  decisionTrace,
}: {
  entry: StageEntry;
  comparison: ComparisonResult | null;
  decisionTrace: DecisionTrace | null;
}) {
  const d = entry.data;

  if (entry.stage === "registered" || entry.stage === "attack_registered") {
    const report = d.attack_report as { decision?: string; attack_type?: string; severity?: string } | undefined;
    if (!report) return null;
    return (
      <div className="story-stage-detail">
        <span className="mono">{report.decision}</span> · attack type{" "}
        <span className="mono">{report.attack_type}</span> · severity {report.severity}
      </div>
    );
  }

  if (entry.stage === "baseline_previewed" && d.winner) {
    // Same fix as HistoryBasedBaselinePreview below and the static
    // Baseline (before the attack) card: this is d.winner from the
    // backend's baseline_preview (pipeline_service.py's pre-attack,
    // history-influenced _read_only_recommendation() call) — a real but
    // purely informational preview, never the forced comparison_result
    // .scheme_a baseline that's actually executed for the real
    // before/after assessment. Explicitly labeled so it can never again
    // read as "what was executed."
    return (
      <div className="story-stage-detail">
        Agent's history-based instinct: <span className="mono">{String(d.winner)}</span>{" "}
        <span style={{ color: "var(--text-muted)" }}>(informational only — not the assessment baseline)</span>
      </div>
    );
  }

  if (entry.stage === "attack_selected" && d.attack_scenario) {
    return (
      <div className="story-stage-detail">
        Chosen scenario: <span className="mono">{String(d.attack_scenario)}</span>
      </div>
    );
  }

  if (entry.stage === "assessment_done" && comparison) {
    return (
      <div className="story-stage-detail">
        Suggested: <span className="mono">{comparison.scheme_a}</span> ({SCHEME_FULL_NAMES[comparison.scheme_a] ?? comparison.scheme_a}) →{" "}
        <span className="mono">{comparison.scheme_b}</span> ({SCHEME_FULL_NAMES[comparison.scheme_b] ?? comparison.scheme_b})
        {comparison.measured_overhead && (
          <>
            <br />
            Real execution: {comparison.measured_overhead.time_a_ms.toFixed(2)}ms/
            {comparison.measured_overhead.size_a_bytes}B ({comparison.scheme_a}) vs{" "}
            {comparison.measured_overhead.time_b_ms.toFixed(2)}ms/
            {comparison.measured_overhead.size_b_bytes}B ({comparison.scheme_b}) — Δ{" "}
            {comparison.measured_overhead.time_diff_pct}%
          </>
        )}
        {comparison.analytical_rationale && (
          <>
            <br />
            Re-analysis: analytically justified ={" "}
            <span className="mono">{String(comparison.analytical_rationale.analytically_justified)}</span>
          </>
        )}
        <br />
        Simulated Stability (Check 2 — internal reasoning only, no hardware): {comparison.stability_detail}
      </div>
    );
  }

  if (entry.stage === "stability_replay_done") {
    return (
      <div className="story-stage-detail">
        Replay {String(d.replay_number)}: predicted <span className="mono">{String(d.predicted_scheme)}</span>{" "}
        {d.matches_scheme_b ? "— matches scheme B" : "— does NOT match scheme B"}
      </div>
    );
  }

  if (entry.stage === "agent_done" && d.recommendation) {
    const rec = d.recommendation as { selected_scheme?: string };
    return (
      <div className="story-stage-detail">
        Real recommendation: <span className="mono">{rec.selected_scheme}</span>{" "}
        {rec.selected_scheme && `(${SCHEME_FULL_NAMES[rec.selected_scheme] ?? rec.selected_scheme})`}
      </div>
    );
  }

  if (entry.stage === "ranking_done" && decisionTrace) {
    const hybrid = d.hybrid_combination as string[] | null | undefined;
    return (
      <div className="story-stage-detail">
        Winner: <span className="mono">{decisionTrace.winner}</span>{" "}
        <span style={{ color: "var(--text-muted)" }}>
          {(decisionTrace.winner && SCHEME_FULL_NAMES[decisionTrace.winner]) ?? decisionTrace.winner}
        </span>{" "}
        ({decisionTrace.winner_score?.toFixed(3)}) · runner-up{" "}
        {decisionTrace.runner_up
          ? `${decisionTrace.runner_up} (${SCHEME_FULL_NAMES[decisionTrace.runner_up] ?? decisionTrace.runner_up})`
          : "—"}
        {hybrid && hybrid.length > 1 && (
          <>
            <br />
            <span style={{ color: "var(--accent-purple)" }}>
              Hybrid combination suggested: {hybrid.map((h) => `${h} (${SCHEME_FULL_NAMES[h] ?? h})`).join(" + ")}
            </span>
          </>
        )}
      </div>
    );
  }

  if (entry.stage === "launching_ue" && d.attempt) {
    return (
      <div className="story-stage-detail">
        Attempt {String(d.attempt)}/{String(d.of)}
      </div>
    );
  }

  if (entry.stage === "step_failed") {
    return <div className="story-stage-detail" style={{ color: "var(--status-critical)" }}>{String(d.reason)}</div>;
  }

  return null;
}
