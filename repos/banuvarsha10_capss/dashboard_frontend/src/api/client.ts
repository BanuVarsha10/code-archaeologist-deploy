import type {
  AttackScenario,
  AttackMode,
  RunResult,
  KnowledgeBaseResponse,
  KnowledgeBaseCompareResponse,
  ExperienceTimeline,
  ExperienceStats,
  ManualScenarioInput,
  DeviceResult,
  DevicePoolResponse,
  IdentityPair,
  StreamEvent,
  ScalingStreamEvent,
} from "./types";

// Empty string = relative to whatever origin served this page (works both
// for plain "npm run dev" on localhost AND through an ngrok tunnel),
// relying on vite.config.ts's server.proxy to forward /api/* to the real
// backend on :8000 server-side. Hardcoding "http://localhost:8000" here
// only ever worked for whoever runs the backend on their own machine — a
// teammate loading this through ngrok has their OWN localhost:8000
// (nothing listening there), which is why every API call was failing for
// them. VITE_API_BASE_URL remains available as an explicit override for
// any setup that doesn't go through the dev proxy.
const BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

// TEMPORARY dev-only: free ngrok tunnels show an interstitial HTML
// "you are about to visit..." warning page to any client that hasn't
// clicked through it in that browser before — including fetch() calls
// from JS, not just page navigation. Without this header, a request
// through a fresh ngrok tunnel gets that HTML page back instead of the
// real JSON/NDJSON response, and JSON.parse() on it throws — which is
// almost certainly the "Unexpected error" teammates were seeing. This
// header tells ngrok to skip that page. Harmless no-op against a non-
// ngrok backend (any other server just ignores an unrecognized header).
const NGROK_HEADERS = { "ngrok-skip-browser-warning": "true" };

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let resp: Response;
  try {
    resp = await fetch(`${BASE_URL}${path}`, {
      headers: { "Content-Type": "application/json", ...NGROK_HEADERS },
      ...init,
    });
  } catch (err) {
    throw new ApiError(
      0,
      `Could not reach the backend at ${BASE_URL} (${err instanceof Error ? err.message : "network error"}). ` +
        `Check the backend is running and, if using ngrok, that VITE_API_BASE_URL points at its tunnel.`,
    );
  }
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    throw new ApiError(
      resp.status,
      body.message || body.detail || `Request to ${path} failed (${resp.status})`,
    );
  }
  return resp.json() as Promise<T>;
}

export interface StreamAttackTestParams {
  attackMode: AttackMode;
  // Required when attackMode is "same_for_all"; omitted for "per_device"
  // (each device's scenario is chosen interactively — see selectScenario).
  attackScenario?: AttackScenario;
  // Device-pool task (Control 1): total devices to run this session.
  devicesThisRun: number;
  // Device-pool task (Control 2): how many of those should be freshly
  // generated rather than pulled from the persistent device pool.
  // Defaults to 0 — reusing the pool is the default, generating fresh
  // devices is a deliberate, explicit choice.
  newDevicesCount?: number;
}

async function streamNdjson<T = StreamEvent>(
  path: string,
  body: Record<string, unknown>,
  onEvent: (event: T) => void,
  signal?: AbortSignal,
): Promise<void> {
  let resp: Response;
  try {
    resp = await fetch(`${BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...NGROK_HEADERS },
      body: JSON.stringify(body),
      signal,
    });
  } catch (err) {
    throw new ApiError(
      0,
      `Could not reach the backend at ${BASE_URL} (${err instanceof Error ? err.message : "network error"}). ` +
        `Check the backend is running and, if using ngrok, that VITE_API_BASE_URL points at its tunnel.`,
    );
  }

  if (!resp.ok || !resp.body) {
    const errBody = await resp.json().catch(() => ({}));
    throw new ApiError(
      resp.status,
      errBody.detail || errBody.message || `Stream request to ${path} failed (${resp.status})`,
    );
  }

  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  function parseLine(line: string): void {
    try {
      onEvent(JSON.parse(line) as T);
    } catch {
      // Most likely cause: an ngrok interstitial/warning page (HTML) came
      // back instead of the real NDJSON stream — surface that plainly
      // instead of a cryptic "Unexpected token '<'" JSON parse error.
      throw new ApiError(
        0,
        line.trim().startsWith("<")
          ? "Backend returned an HTML page instead of data — likely an ngrok " +
            "browser-warning interstitial. Open the backend's ngrok URL directly " +
            "in a browser once and click through the warning, then retry."
          : "Backend returned a response that wasn't valid data.",
      );
    }
  }

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let newlineIndex: number;
    while ((newlineIndex = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newlineIndex);
      buffer = buffer.slice(newlineIndex + 1);
      if (line.trim()) parseLine(line);
    }
  }
  if (buffer.trim()) parseLine(buffer);
}

/**
 * Streams real per-device, per-stage progress as it actually happens on
 * the backend (NDJSON over a chunked HTTP response) — not a client-side
 * replay animation. `onEvent` is called once per line as soon as it
 * arrives — stages can be seconds apart, since the underlying operations
 * (dbctl, real nr-ue registrations — up to 5+ per device) really do take
 * that long.
 */
export function streamAttackTest(
  params: StreamAttackTestParams,
  onEvent: (event: StreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  return streamNdjson(
    "/api/attack-test/run-stream",
    {
      attack_mode: params.attackMode,
      attack_scenario: params.attackScenario ?? null,
      devices_this_run: params.devicesThisRun,
      new_devices_count: params.newDevicesCount ?? 0,
    },
    onEvent,
    signal,
  );
}

/** The persistent device pool (device-pool task) — every device's real
 * history summary, ranked the same way a "returning" selection would
 * prefer them (most prior runs first). */
export function getDevicePool(): Promise<DevicePoolResponse> {
  return request<DevicePoolResponse>("/api/device-pool");
}

/** Manual pool pruning — only removes the entry from the POOL; its
 * accumulated experience history and already-provisioned Open5GS
 * subscriber are untouched, so it simply stops being offered as
 * "returning" in future runs. */
export function deleteDevicePoolEntry(imsi: string): Promise<{ status: string; removed: string }> {
  return request(`/api/device-pool/${encodeURIComponent(imsi)}`, { method: "DELETE" });
}

/** Requests a running batch stop at the next safe point (between real
 * steps/devices — never mid real registration). Devices not yet started
 * come back labeled "cancelled", not "failed". */
export function stopAttackTest(runId: string): Promise<{ status: string }> {
  return request(`/api/attack-test/${encodeURIComponent(runId)}/stop`, { method: "POST" });
}

/** Destructive — wipes ALL accumulated per-UE experience/EAS history.
 * Does NOT touch the device pool (device identities remain reusable, just
 * with no history). Caller is responsible for confirming with the user
 * first; this function does not ask again. */
export function clearExperienceStore(): Promise<{ status: string; cleared_ue_count: number }> {
  return request("/api/experience/clear", { method: "DELETE" });
}

/** Resolves ONE device's pending attack-scenario selection (Part E "choose
 * per device" mode) — the stream genuinely blocks on this device until it
 * arrives. */
export function selectScenario(
  runId: string,
  deviceIndex: number,
  attackScenario: AttackScenario,
): Promise<{ status: string }> {
  return request("/api/attack-test/select-scenario", {
    method: "POST",
    body: JSON.stringify({ run_id: runId, device_index: deviceIndex, attack_scenario: attackScenario }),
  });
}

/** Same real-time streaming as streamAttackTest, for one manually-built
 * device — reuseIdentity pins the SAME UE across repeated manual runs. */
export function streamManualScenario(
  input: ManualScenarioInput,
  reuseIdentity: IdentityPair | null,
  onEvent: (event: StreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  return streamNdjson(
    "/api/manual-scenario/run-stream",
    { ...input, reuse_identity: reuseIdentity },
    onEvent,
    signal,
  );
}

/** Scaling/throughput panel — 100-500 real devices, streamed exactly like
 * streamAttackTest but with the deliberately minimal ScalingStreamEvent/
 * ScalingDeviceResult shape (see types.ts) — no per-scheme breakdown, no
 * decision trace, at this device count. */
export function streamScalingRun(
  deviceCount: number,
  attackScenario: AttackScenario,
  onEvent: (event: ScalingStreamEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  return streamNdjson<ScalingStreamEvent>(
    "/api/scaling-run/run-stream",
    { device_count: deviceCount, attack_scenario: attackScenario },
    onEvent,
    signal,
  );
}

export function getRun(runId: string): Promise<RunResult> {
  return request<RunResult>(`/api/run/${runId}`);
}

export function getHealth(): Promise<{ status: string }> {
  return request("/api/health");
}

export function getKnowledgeBase(): Promise<KnowledgeBaseResponse> {
  return request<KnowledgeBaseResponse>("/api/knowledge-base");
}

export function compareKnowledgeBase(a: string, b: string): Promise<KnowledgeBaseCompareResponse> {
  return request<KnowledgeBaseCompareResponse>(
    `/api/knowledge-base/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`,
  );
}

export function getExperienceStats(): Promise<ExperienceStats> {
  return request<ExperienceStats>("/api/experience/stats");
}

export function getExperienceUes(): Promise<{ ue_ids: string[] }> {
  return request<{ ue_ids: string[] }>("/api/experience/ues");
}

export function getExperienceTimeline(ueId: string): Promise<ExperienceTimeline> {
  return request<ExperienceTimeline>(`/api/experience/${encodeURIComponent(ueId)}/timeline`);
}

export function runManualScenario(input: ManualScenarioInput): Promise<{ run_id: string; device: DeviceResult }> {
  return request("/api/manual-scenario/run", {
    method: "POST",
    body: JSON.stringify(input),
  });
}
