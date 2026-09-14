import type { DeviceOrigin, OverallVerdict } from "../api/types";

export function Badge({
  children,
  variant = "neutral",
}: {
  children: React.ReactNode;
  variant?: "neutral" | "cold-start";
}) {
  return <span className={`badge badge-${variant}`}>{children}</span>;
}

export function ColdStartBadge() {
  return <Badge variant="cold-start">Cold-start + RAG</Badge>;
}

// Device-pool task, Part 4: these three must never look alike — a device
// silently auto-filled because the pool came up short is NOT the same
// claim as one genuinely returning with real history, or one the user
// explicitly asked to add.
const DEVICE_ORIGIN_LABELS: Record<DeviceOrigin, string> = {
  returning: "Returning",
  new_requested: "New (requested)",
  new_autofilled: "New (auto-filled)",
};

export function DeviceOriginBadge({ origin }: { origin: DeviceOrigin | null | undefined }) {
  if (!origin) return null;
  return <span className={`badge badge-origin-${origin}`}>{DEVICE_ORIGIN_LABELS[origin]}</span>;
}

export function VerdictPill({ verdict }: { verdict: OverallVerdict | "NO_COMPARISON" }) {
  const className = `verdict-pill verdict-${verdict.replace(/\s+/g, "_")}`;
  const label = verdict === "NO_COMPARISON" ? "No comparison" : verdict;
  return <span className={className}>{label}</span>;
}
