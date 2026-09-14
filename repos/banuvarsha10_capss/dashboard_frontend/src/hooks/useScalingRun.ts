import { useCallback, useRef, useState } from "react";
import type { AttackScenario, ScalingDeviceResult, ScalingRunSummary, ScalingStreamEvent } from "../api/types";
import { ApiError, streamScalingRun } from "../api/client";

/**
 * Owned at App.tsx level (same Bug 1 pattern as useAttackRun) so a long
 * 100-500 device run survives the user switching sidebar tabs instead of
 * being silently discarded — this run can genuinely take a long time.
 */
export function useScalingRun() {
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [devices, setDevices] = useState<ScalingDeviceResult[]>([]);
  const [total, setTotal] = useState(0);
  const [summary, setSummary] = useState<ScalingRunSummary | null>(null);
  // Wall-clock start time (client-side) — the LIVE elapsed timer ticks off
  // this locally every second while running, independent of backend
  // events, so it genuinely counts real time as it happens rather than
  // only updating when a device_done event happens to arrive.
  const [startedAtMs, setStartedAtMs] = useState<number | null>(null);

  const abortRef = useRef<AbortController | null>(null);

  const startRun = useCallback((deviceCount: number, attackScenario: AttackScenario) => {
    abortRef.current?.abort();

    setRunning(true);
    setError(null);
    setDevices([]);
    setTotal(deviceCount);
    setSummary(null);
    setStartedAtMs(Date.now());

    const controller = new AbortController();
    abortRef.current = controller;

    function handleEvent(event: ScalingStreamEvent) {
      if (event.type === "run_started") {
        setTotal(event.total ?? deviceCount);
      } else if (event.type === "device_done" && event.device) {
        const device = event.device;
        setDevices((prev) => {
          const idx = event.index ?? prev.length;
          const next = [...prev];
          next[idx] = device;
          return next;
        });
      } else if (event.type === "scaling_done") {
        setSummary({
          total_devices: event.total_devices ?? 0,
          succeeded: event.succeeded ?? 0,
          failed: event.failed ?? 0,
          total_elapsed_s: event.total_elapsed_s ?? 0,
          avg_seconds_per_device: event.avg_seconds_per_device ?? 0,
          replay_count_used: event.replay_count_used ?? 0,
        });
      }
    }

    streamScalingRun(deviceCount, attackScenario, handleEvent, controller.signal)
      .catch((err) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(err instanceof ApiError ? err.message : "Unexpected error while running the scaling test.");
      })
      .finally(() => {
        setRunning(false);
        if (abortRef.current === controller) abortRef.current = null;
      });
  }, []);

  return { running, error, devices, total, summary, startedAtMs, startRun };
}

export type UseScalingRunReturn = ReturnType<typeof useScalingRun>;
