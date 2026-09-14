// Mirrors the JSON shapes dashboard_backend actually returns (field names
// match the Python dataclasses/pydantic models verbatim via FastAPI's
// jsonable_encoder — see dashboard_backend/schemas.py's docstring for why
// no separate response schema is re-declared there).

export interface MeasuredOverhead {
  scheme_a: string;
  scheme_b: string;
  time_a_ms: number;
  size_a_bytes: number;
  time_b_ms: number;
  size_b_bytes: number;
  time_diff_pct: number;
  size_diff_pct: number;
  label: string;
  note: string;
  executor_a_error: string | null;
  executor_b_error: string | null;
}

export interface AnalyticalRationale {
  attack_type: string;
  scheme_a: string;
  scheme_b: string;
  affinity_a: boolean | null;
  affinity_b: boolean | null;
  reasoning_flags_a: Record<string, unknown>;
  reasoning_flags_b: Record<string, unknown>;
  agent_reason: string;
  agent_metric_summary: Record<string, number>;
  analytically_justified: boolean;
  justification_note: string;
  label: string;
  source_note: string;
}

export type OverallVerdict = "VALIDATED" | "INCONCLUSIVE" | "NO CHANGE";

export interface ComparisonResult {
  ue_id: string;
  scheme_a: string;
  scheme_b: string;
  adaptation_occurred: boolean;
  stability_confirmed: boolean;
  replay_count: number;
  stability_detail: string;
  measured_overhead: MeasuredOverhead | null;
  analytical_rationale: AnalyticalRationale | null;
  overall_verdict: OverallVerdict;
  verdict_reason: string;
  metadata: Record<string, unknown>;
  // Hybrid execution gap fix: scheme_a/scheme_b and measured_overhead above
  // are ALWAYS the primary scheme only, exactly as validated throughout
  // this project — never blended with these. Populated only when the
  // Agent's scheme_b recommendation is a hybrid combination (e.g. "GS +
  // DP"); null for the overwhelming majority of (non-hybrid) results.
  hybrid_partner_scheme: string | null;
  hybrid_partner_execution: ExecutionResultJSON | null;
}

export interface SchemeScore {
  scheme_id: string;
  scheme_name: string;
  short_name: string;
  fitness_score: number;
  privacy_match: number;
  performance_match: number;
  deployment_match: number;
  experience_alignment: number;
  tracking_protection_match: number;
  quantum_match: number;
  identity_protection_match: number;
  profile_match: number;
  final_score: number;
  score_breakdown: Record<string, number>;
  rejection_reasons: string[];
  is_rejected: boolean;
}

export interface ValidationResult {
  is_valid: boolean;
  warnings: string[];
  errors: string[];
  hybrid_compatible: boolean;
  completeness_score: number;
}

export interface PrivacyPolicy {
  policy_id: string;
  selected_scheme: string;
  selected_scheme_id: string;
  hybrid_schemes: string[] | null;
  reason: string;
  confidence: number;
  risk_assessment: string;
  timestamp: string;
  expiry: string;
  version: string;
  knowledge_version: string;
  reasoning_version: string;
  validation_result: ValidationResult;
  metric_summary: Record<string, number>;
  is_fallback: boolean;
}

export interface AttackReport {
  request_id: string;
  experiment_name: string;
  timestamp: string;
  ue_id: string;
  attack_detected: boolean;
  attack_type: string;
  decision: string;
  severity: string;
  confidence: number;
  risk_score: number;
  reasons: string[];
}

export interface PrivacyResult {
  privacy_score: number;
  privacy_risk_level: string;
  metadata_leakage: number;
  correlation_score: number;
}

export interface RegistrationContextJSON {
  ue_id: string;
  attack_type: string | null;
  request_classification: string | null;
  threat_score: number | null;
  [key: string]: unknown;
}

export interface SystemsValidationResult {
  passed: boolean;
  errors: string[];
  warnings: string[];
  score: number;
}

export interface SystemsDetectionResult {
  detected: boolean;
  attack_type: string;
  confidence: number;
  severity: string;
  score: number;
  message: string;
  current_rate: number;
  peak_rate: number;
  current_count: number;
  window_seconds: number;
}

export interface ValidationBreakdown {
  header_result: SystemsValidationResult;
  parameter_result: SystemsValidationResult;
  subscriber_result: SystemsValidationResult;
  duplicate_result: SystemsDetectionResult;
  rate_result: SystemsDetectionResult;
}

export interface MinimizedField {
  original: string;
  minimized: string;
}

export interface MinimizationResult {
  ue_id: MinimizedField;
  suci: MinimizedField;
  gnb_ip: MinimizedField;
  dnn: MinimizedField;
  snssai: MinimizedField;
  timestamp: MinimizedField;
}

export interface DeviceStep {
  request_id: string;
  timestamp: string;
  attack_report: AttackReport;
  privacy_result: PrivacyResult;
  context: RegistrationContextJSON;
  validation_breakdown: ValidationBreakdown;
  minimization: MinimizationResult;
}

export interface DecisionTrace {
  context_summary: Record<string, unknown>;
  requirement_profile: Record<string, unknown>;
  candidate_scores: SchemeScore[];
  top_candidates: SchemeScore[];
  comparison_details: Record<string, unknown>;
  winner: string | null;
  winner_score: number | null;
  runner_up: string | null;
  runner_up_score: number | null;
  score_gap: number | null;
  rules_fired: string[];
  context_influence: Record<string, unknown>;
  experience_contribution: { total_experiences: number; historical_agreement: number };
  knowledge_coverage: number;
  missing_knowledge: string[];
  adaptation_delta: number | null;
  previous_scheme: string | null;
  adaptation_reason: string | null;
  processing_time_ms: number;
}

export interface AgentExplanation {
  why_selected: string;
  why_alternatives_rejected: Record<string, string>;
  rules_fired: string[];
  context_influence: Record<string, number>;
  experience_influence: string;
  confidence_explanation: string;
  risk_explanation: string;
  adaptation_note: string;
}

export interface ExecutionResultJSON {
  success: boolean;
  output_type: string;
  output_value_hex: string | null;
  generation_time_ms: number;
  key_size_bytes: number;
  output_size_bytes: number;
  error: string | null;
  scheme_name: string;
  label: string;
  is_placeholder: boolean;
  metadata: Record<string, unknown>;
}

export interface BaselinePreview {
  winner: string;
  decision_trace: DecisionTrace;
}

export interface RealStabilityReplay {
  replay_number: number;
  success: boolean;
  failure_reason: string | null;
  predicted_scheme: string | null;
  matches_scheme_b: boolean;
}

// Distinct from ComparisonResult.stability_confirmed (assess_adaptation()'s
// OWN internal check — 3 SIMULATED replays of the same attack context,
// inside protected/unmodified code). This is an ADDITIONAL, genuinely
// real-hardware confirmation: 3 more real nr-ue registrations under the
// same attack scenario (Part F step 10). Both are shown, never conflated.
export interface RealStability {
  confirmed: boolean;
  replays: RealStabilityReplay[];
  detail: string;
}

// Device-pool task, Part 5: distinguishes a device genuinely pulled from
// the persistent pool (real prior history) from one freshly generated —
// either because the user explicitly asked for it (Control 2) or because
// the pool came up short of the requested returning_count (Part 4's
// auto-fill). Never collapse "new_autofilled" into "returning" — that
// would silently misrepresent a brand-new device as one with history.
export type DeviceOrigin = "returning" | "new_requested" | "new_autofilled";

export interface DeviceResult {
  ue_id: string;
  suci: string;
  masked_identity: string;
  attack_scenario: AttackScenario;
  steps: DeviceStep[];
  cold_start: boolean | null;
  device_origin: DeviceOrigin | null;
  // Read-only preview computed right after baseline registration, before
  // the attack scenario is even chosen (Part F steps 5-6) — null only for
  // invalid_subscriber, which has no baseline.
  baseline_preview: BaselinePreview | null;
  baseline_execution: ExecutionResultJSON | null;
  comparison_result: ComparisonResult | null;
  recommendation: PrivacyPolicy | null;
  no_comparison_reason: string | null;
  decision_trace: DecisionTrace | null;
  // Present whenever the Agent's winner is a hybrid of two schemes (see
  // capss/reasoning/engine.py's _evaluate_hybrids) — null otherwise.
  hybrid_combination: string[] | null;
  hybrid_benefit_score: number | null;
  hybrid_reason: string | null;
  explanation: AgentExplanation | null;
  // Official post-assessment executions of scheme_a/scheme_b — Part F
  // step 11's side-by-side "previously X, now this circumstance chose Y".
  scheme_a_execution: ExecutionResultJSON | null;
  scheme_b_execution: ExecutionResultJSON | null;
  real_stability: RealStability | null;
  live_success: boolean;
  failure_reason: string | null;
  // Stop-attack task (Part 2): true for a device that stopped cleanly
  // between real steps (or was never started at all) because of a manual
  // stop request — distinct from a genuine failure. live_success stays
  // false either way, but the UI must never label a cancelled device
  // "Failed".
  cancelled?: boolean;
  // Only present on Tier-2 Manual Scenario Builder results — Attack
  // Testing devices never carry this field.
  mode?: string;
  // LLM explainer task: a purely-additive, plain-language summary of the
  // already-final comparison_result, generated strictly AFTER Agent
  // scoring is done (see dashboard_backend/llm_explainer.py's module
  // docstring). null whenever the call failed for any reason (no key,
  // network error, timeout, malformed/incomplete response, ...) — never
  // render a partial box for that; winner_explanation, rejected_schemes,
  // and hybrid_partner_explanation always arrive together or not at all
  // (single call, all-or-nothing parse — see generate_full_explanation()).
  llm_explanation: LLMExplanation | null;
  // Performance panel task: two real time.perf_counter() measurements from
  // dashboard_backend/pipeline_service.py — "Initial registration" (Systems
  // classification + Privacy scoring + the Agent's baseline recommendation
  // for pre_context) and "Post-attack computation" (Systems + Privacy
  // classification of the attack event through assess_adaptation()'s full
  // run, to the final verdict). Independent measurements, never one
  // double-counted inside the other. null when the corresponding stage
  // never ran or never completed (e.g. invalid_subscriber has no baseline
  // concept at all; Manual Scenario Builder has no baseline registration
  // step, so initial_registration_ms is always null there; a device that
  // fails before a stage finishes reports null only for that stage, not
  // both — see pipeline_service.py's _live_failure_result docstring).
  initial_registration_ms: number | null;
  post_attack_computation_ms: number | null;
}

export interface RejectedSchemeExplanation {
  scheme: string; // short_name, e.g. "ZKP"
  reason: string; // one grounded sentence citing a real dimension/score
}

export interface LLMExplanation {
  winner_explanation: string;
  rejected_schemes: RejectedSchemeExplanation[];
  // Only present when the recommendation is a real hybrid (comparison_
  // result.hybrid_partner_scheme is set) — that partner is excluded from
  // rejected_schemes entirely, since it was not rejected.
  hybrid_partner_explanation: string | null;
}

export interface RunSummary {
  verdict_counts: Record<string, number>;
  cold_start_rag_count: number;
  avg_overhead_delta: number | null;
  total_devices: number;
  live_failures?: number;
  cancelled_count?: number;
  real_stability_confirmed_count?: number;
  real_stability_eligible_count?: number;
}

export interface RunResult {
  run_id: string;
  devices: DeviceResult[];
  summary: RunSummary;
}

export type AttackScenario =
  | "replay"
  | "duplicate_registration"
  | "flooding"
  | "invalid_subscriber"
  | "mixed";

export const ATTACK_SCENARIOS: { value: AttackScenario; label: string }[] = [
  { value: "replay", label: "Replay" },
  { value: "duplicate_registration", label: "Duplicate Registration" },
  { value: "flooding", label: "Flooding" },
  { value: "invalid_subscriber", label: "Invalid Subscriber" },
  { value: "mixed", label: "Mixed" },
];

// Selectable in the "choose per device" picker (Part E) — excludes
// invalid_subscriber, which has no baseline and so can't be chosen AFTER
// one has already happened (see pipeline_service.py's module docstring).
export const PER_DEVICE_ATTACK_SCENARIOS: { value: AttackScenario; label: string }[] =
  ATTACK_SCENARIOS.filter((s) => s.value !== "invalid_subscriber");

export type AttackMode = "same_for_all" | "per_device";

// Matches dashboard_backend/live_mode.py's MAX_LIVE_DEVICES (Part D).
export const MAX_LIVE_DEVICES = 20;

// ---------------------------------------------------------------------------
// Device pool (device-pool task — GET /api/device-pool)
// ---------------------------------------------------------------------------

export interface DevicePoolEntry {
  imsi: string;
  masked_identity: string;
  first_seen: string;
  total_times_run: number;
}

export interface DevicePoolResponse {
  devices: DevicePoolEntry[];
  capacity: number;
}

// ---------------------------------------------------------------------------
// Streaming (POST /api/attack-test/run-stream, NDJSON)
// ---------------------------------------------------------------------------

export interface IdentityPair {
  ue_id: string;
  suci: string;
}

export type StreamEventType = "run_started" | "device_start" | "stage" | "device_done" | "batch_done";

export interface StreamEvent {
  type: StreamEventType;
  index?: number;
  total?: number;
  stage?: string;
  device?: DeviceResult;
  run_id?: string;
  attack_mode?: AttackMode;
  summary?: RunSummary;
  identities?: IdentityPair[];
  ue_id?: string;
  attack_report?: AttackReport;
  comparison?: ComparisonResult;
  decision_trace?: DecisionTrace;
  recommendation?: PrivacyPolicy;
  reason?: string;
  imsi?: string;
  config_path?: string;
  attempt?: number;
  of?: number;
  request_count?: number;
  winner?: string;
  execution?: ExecutionResultJSON;
  attack_scenario?: AttackScenario;
  scheme_a_execution?: ExecutionResultJSON;
  scheme_b_execution?: ExecutionResultJSON;
  replay_number?: number;
  predicted_scheme?: string;
  matches_scheme_b?: boolean;
  real_stability?: RealStability;
  estimated_seconds_remaining?: number;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Scaling / Throughput panel (POST /api/scaling-run/run-stream, NDJSON)
//
// Deliberately a SEPARATE, minimal event/device shape from StreamEvent/
// DeviceResult above — the Scaling panel task explicitly requires minimal
// per-device data at 100-500 device scale (identity, success/failure, and
// the scheme actually selected only — no candidate breakdown, no decision
// trace, no LLM text), matching pipeline_service.run_scale_device()'s own
// deliberately minimal backend return shape.
// ---------------------------------------------------------------------------

export interface ScalingDeviceResult {
  ue_id: string | null;
  masked_identity: string;
  success: boolean;
  stage: string;
  failure_reason: string | null;
  scheme_a: string | null;
  scheme_b: string | null;
  overall_verdict: string | null;
  elapsed_s: number;
}

export type ScalingStreamEventType = "run_started" | "device_start" | "device_done" | "scaling_done";

export interface ScalingStreamEvent {
  type: ScalingStreamEventType;
  index?: number;
  total?: number;
  attack_scenario?: AttackScenario;
  replay_count?: number;
  device?: ScalingDeviceResult;
  estimated_seconds_remaining?: number;
  // scaling_done fields
  total_devices?: number;
  succeeded?: number;
  failed?: number;
  total_elapsed_s?: number;
  avg_seconds_per_device?: number;
  replay_count_used?: number;
}

export interface ScalingRunSummary {
  total_devices: number;
  succeeded: number;
  failed: number;
  total_elapsed_s: number;
  avg_seconds_per_device: number;
  replay_count_used: number;
}

// Human-readable narration for each real backend stage — no jargon, no
// raw enum values shown to the user.
export const STAGE_LABELS: Record<string, string> = {
  registering_context: "Building registration context from real network data",
  registered: "Baseline registration recorded",
  // Investigation fix (third instance of the "narration reads stale
  // history-based value instead of real forced baseline" bug — same root
  // cause as the Adaptation-text and Recommendation-panel fixes, and
  // already correctly disclaimed on the static card's
  // HistoryBasedBaselinePreview — see DeviceStoryCard.tsx). This value
  // (backend's baseline_winner) is the deterministic scorer's OWN
  // pre-attack instinct, computed before comparison_result even exists —
  // it is never the real, forced baseline (comparison_result.scheme_a)
  // used throughout the actual before/after assessment. Labeled
  // "informational only" so it can't be misread as what was actually
  // executed, matching the static card's wording exactly.
  baseline_previewed: "Agent's history-based instinct computed (informational only)",
  baseline_executed: "Agent's instinct scheme executed for real (informational only — not the assessment baseline)",
  awaiting_attack_selection: "Waiting for you to pick this device's attack scenario",
  attack_selected: "Attack scenario selected",
  attack_registered: "Real attack registration recorded",
  consulting_agent: "Consulting Agent — comparing before/after, checking stability, executing both schemes",
  assessment_done: "Agent comparison complete",
  ranking_done: "Full 7-scheme ranking computed",
  schemes_executed: "Both schemes executed for real, side by side",
  stability_replay_done: "Real stability replay complete",
  real_stability_done: "Real stability check complete (3/3 replays)",
  agent_done: "Agent recommendation generated",
  credentials_ready: "Identity ready (fresh or reused from the device pool)",
  adding_subscriber: "Adding subscriber to Open5GS (real MongoDB write)",
  subscriber_added: "Subscriber added to the real network",
  skipping_subscriber_add: "Skipping subscriber provisioning — testing an unknown-subscriber rejection",
  reusing_subscriber: "Reusing this returning device — already provisioned in a prior session",
  generating_config: "Generating real UE configuration file",
  config_ready: "UE configuration ready",
  config_reused: "Reusing this device's UE configuration from a prior session",
  launching_ue: "Launching real nr-ue process",
  ue_registered: "Real registration observed in the AMF log",
  parsing_amf_log: "Parsing the real AMF log",
  amf_log_parsed: "Real registration data extracted",
  step_failed: "Step failed",
};

// ---------------------------------------------------------------------------
// Tier 2 types
// ---------------------------------------------------------------------------

// PrivacyScheme has a large, deeply nested real shape (capss/schemas/scheme.py)
// — typed loosely here for the fields the Knowledge Base Viewer renders, with
// an index signature for everything else rather than mirroring every nested
// field (avoids silent drift from the real dataclass).
export interface PrivacyScheme {
  id: string;
  name: string;
  short_name: string;
  version: string;
  description: string;
  category: string;
  primary_privacy_goal: string;
  performance: Record<string, unknown>;
  deployment: Record<string, unknown>;
  advantages: string[];
  limitations: string[];
  decision_support: {
    recommendation_profile: {
      threat_level: string;
      privacy_level: string;
      latency_level: string;
      capabilities: string[];
      best_when: string[];
      avoid_when: string[];
      reasoning_profile: { attack_type_affinity: Record<string, boolean> };
    };
  };
  [key: string]: unknown;
}

export interface KnowledgeBaseResponse {
  knowledge_version: string;
  schemes: PrivacyScheme[];
}

export interface KnowledgeBaseCompareResponse {
  scheme_a: PrivacyScheme;
  scheme_b: PrivacyScheme;
}

export interface AdaptationHistoryEntry {
  timestamp: string;
  from: string;
  to: string;
  reason: string;
}

export interface ConfidenceTrendEntry {
  timestamp: string;
  confidence: number;
  selected_scheme: string;
}

export interface ExperienceTimeline {
  ue_id: string;
  adaptation_history: AdaptationHistoryEntry[];
  confidence_trend: ConfidenceTrendEntry[];
}

export interface ExperienceStats {
  total_experiences: number;
  total_ues: number;
  avg_per_ue: number;
}

export interface ManualScenarioInput {
  threat_score: number;
  privacy_score: number;
  privacy_risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  metadata_leakage: number;
  correlation_score: number;
  detection_confidence: number;
  registration_type: "initial" | "mobility" | "periodic" | "emergency";
  slice_type: "eMBB" | "URLLC" | "mMTC";
  dnn: string;
  attack_type: string | null;
  attack_severity: "NORMAL" | "SUSPICIOUS" | "MALICIOUS";
  request_classification: "ALLOW" | "TAG" | "BLOCK";
}

export const DEFAULT_MANUAL_SCENARIO: ManualScenarioInput = {
  threat_score: 0.5,
  privacy_score: 0.5,
  privacy_risk_level: "MEDIUM",
  metadata_leakage: 0.5,
  correlation_score: 0.5,
  detection_confidence: 0.5,
  registration_type: "initial",
  slice_type: "eMBB",
  dnn: "internet",
  attack_type: null,
  attack_severity: "SUSPICIOUS",
  request_classification: "TAG",
};

