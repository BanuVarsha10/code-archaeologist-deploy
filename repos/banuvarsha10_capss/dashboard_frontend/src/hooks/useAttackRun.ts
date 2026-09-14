import { useCallback, useRef, useState } from "react";
import type {
  AttackMode,
  AttackScenario,
  DeviceResult,
  RunResult,
  RunSummary,
  StreamEvent,
} from "../api/types";
import { ApiError, streamAttackTest, selectScenario as apiSelectScenario, stopAttackTest } from "../api/client";
import type { DeviceStoryState } from "../components/DeviceStoryCard";

function emptyDeviceState(index: number, ueId: string | null): DeviceStoryState {
  return {
    index,
    ueId,
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

export interface StartRunParams {
  attackMode: AttackMode;
  attackScenario?: AttackScenario;
  devicesThisRun: number;
  newDevicesCount?: number;
}

/**
 * Bug 1 fix: owns the attack-test run's ENTIRE live state and the streaming
 * subscription itself. Must be instantiated exactly once, at a component
 * that never unmounts while the app is open (App.tsx) -- NOT inside
 * AttackTestingPanel, which mounts/unmounts every time the user switches
 * sidebar tabs. Panels read this via props/return value; they don't own it.
 *
 * See the Bug 1 diagnosis: previously every piece of this lived in
 * AttackTestingPanel's own useState/useRef, so navigating away unmounted
 * the component and silently discarded all of it, while the real batch
 * (real Open5GS/UERANSIM hardware calls) kept running unseen and
 * un-stoppable in the background.
 */
export function useAttackRun() {
  const [running, setRunning] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deviceStates, setDeviceStates] = useState<DeviceStoryState[]>([]);
  const [total, setTotal] = useState(0);
  const [viewIndex, setViewIndex] = useState<number | null>(null);
  const [summary, setSummary] = useState<RunSummary | null>(null);
  const [etaSeconds, setEtaSeconds] = useState<number | null>(null);
  const [pendingSelection, setPendingSelection] = useState<{ runId: string; index: number } | null>(null);
  const [selecting, setSelecting] = useState(false);
  const [runId, setRunId] = useState<string | null>(null);

  const runIdRef = useRef<string | null>(null);
  const devicesRef = useRef<DeviceResult[]>([]);
  // Bug 1, requirement 3: a real AbortController, decoupled from any
  // component's lifecycle -- only ever aborted by this hook itself
  // (see stop()'s comment for why the normal stop path deliberately does
  // NOT call abort() on the happy path), never by a panel unmounting.
  const abortRef = useRef<AbortController | null>(null);

  const startRun = useCallback(
    (
      params: StartRunParams,
      onComplete: (run: RunResult) => void,
      onSelectDevice: (device: DeviceResult) => void,
    ) => {
      // Defensive cleanup only -- discards a stale subscription if a new
      // run is somehow started while a previous one's stream hasn't
      // finished reading yet. Never triggered by navigation.
      abortRef.current?.abort();

      setRunning(true);
      setError(null);
      setDeviceStates([]);
      setTotal(0);
      setViewIndex(null);
      setSummary(null);
      setEtaSeconds(null);
      setPendingSelection(null);
      setStopping(false);
      runIdRef.current = null;
      setRunId(null);
      devicesRef.current = [];

      const controller = new AbortController();
      abortRef.current = controller;

      function handleEvent(event: StreamEvent) {
        if (event.type === "run_started") {
          runIdRef.current = event.run_id ?? null;
          setRunId(event.run_id ?? null);
          setTotal(event.total ?? 0);
        } else if (event.type === "device_start") {
          const idx = event.index!;
          setViewIndex(idx);
          setDeviceStates((prev) => {
            const next = [...prev];
            next[idx] = emptyDeviceState(idx, event.ue_id ?? null);
            return next;
          });
        } else if (event.type === "stage") {
          const idx = event.index!;
          if (event.stage === "awaiting_attack_selection" && runIdRef.current) {
            setPendingSelection({ runId: runIdRef.current, index: idx });
          }
          if (event.stage === "attack_selected") {
            setPendingSelection(null);
          }
          setDeviceStates((prev) => {
            const next = [...prev];
            const cur = next[idx] ?? emptyDeviceState(idx, event.ue_id ?? null);
            const stages = [...cur.stages, { stage: event.stage!, data: event as Record<string, unknown> }];
            const comparison =
              event.stage === "assessment_done" && event.comparison ? event.comparison : cur.comparison;
            const decisionTrace =
              event.stage === "ranking_done" && event.decision_trace ? event.decision_trace : cur.decisionTrace;
            next[idx] = { ...cur, stages, comparison, decisionTrace };
            return next;
          });
        } else if (event.type === "device_done") {
          const idx = event.index!;
          const device = event.device!;
          devicesRef.current[idx] = device;
          setPendingSelection(null);
          if (typeof event.estimated_seconds_remaining === "number") setEtaSeconds(event.estimated_seconds_remaining);
          setDeviceStates((prev) => {
            const next = [...prev];
            const cur = next[idx] ?? emptyDeviceState(idx, device.ue_id);
            next[idx] = {
              ...cur,
              status: "done",
              ueId: device.ue_id,
              maskedIdentity: device.masked_identity,
              comparison: device.comparison_result,
              decisionTrace: device.decision_trace,
              finalVerdict: device.comparison_result?.overall_verdict ?? null,
              verdictReason: device.comparison_result?.verdict_reason ?? null,
              failureReason: device.live_success === false ? device.failure_reason ?? null : null,
              device,
            };
            return next;
          });
        } else if (event.type === "batch_done") {
          setEtaSeconds(null);
          if (event.summary) setSummary(event.summary);
          if (event.run_id && event.summary) {
            onComplete({ run_id: event.run_id, devices: devicesRef.current, summary: event.summary });
          }
          const firstDone = devicesRef.current.find(Boolean);
          if (firstDone) onSelectDevice(firstDone);
        }
      }

      streamAttackTest(params, handleEvent, controller.signal)
        .catch((err) => {
          // A client-initiated abort surfaces here as an AbortError -- that's
          // an intentional cancellation (see startRun's own defensive-abort
          // above), never a real failure to report to the user.
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(err instanceof ApiError ? err.message : "Unexpected error while running the attack test.");
        })
        .finally(() => {
          setRunning(false);
          setStopping(false);
          if (abortRef.current === controller) abortRef.current = null;
        });
    },
    [],
  );

  const stop = useCallback(() => {
    if (!runIdRef.current) return;
    setStopping(true);
    // Deliberately request-only: this POSTs to the existing stop endpoint
    // and lets the still-open stream keep reading -- the backend reports
    // each remaining device as "cancelled" and still emits a real final
    // batch_done/summary once it winds down at its next safe checkpoint
    // (see run_control.py / pipeline_service.should_cancel). Calling
    // abortRef.current.abort() here instead would close the underlying
    // HTTP connection immediately, which (via Starlette's disconnect
    // handling on the sync generator backing this route) risks cutting the
    // backend off before it reaches store.save_run()/batch_done -- throwing
    // away the graceful cancelled-device reporting this endpoint was built
    // to produce. abortRef stays reserved for genuinely replacing a stale
    // subscription (see startRun), not the normal user-facing stop path.
    stopAttackTest(runIdRef.current).catch((err) => {
      setError(err instanceof ApiError ? err.message : "Failed to stop the run.");
      setStopping(false);
    });
  }, []);

  const selectDeviceScenario = useCallback((deviceIndex: number, picked: AttackScenario) => {
    if (!runIdRef.current) return;
    setSelecting(true);
    apiSelectScenario(runIdRef.current, deviceIndex, picked)
      .then(() => setPendingSelection(null))
      .catch((err) => {
        setError(err instanceof ApiError ? err.message : "Failed to submit the attack scenario selection.");
      })
      .finally(() => setSelecting(false));
  }, []);

  return {
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
    runId,
    startRun,
    stop,
    selectDeviceScenario,
  };
}

export type UseAttackRunReturn = ReturnType<typeof useAttackRun>;
