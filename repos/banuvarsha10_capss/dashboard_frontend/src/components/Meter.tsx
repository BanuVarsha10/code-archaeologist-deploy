/**
 * Labeled severity meter — fill carries severity (accent -> warning ->
 * critical), unfilled track is a lighter step of the same ramp, per the
 * dataviz spec. `value` is 0-1. By default higher = better (fill grows
 * toward --status-good). Pass `invertColor` for metrics where higher is
 * WORSE (e.g. a raw leakage/exposure score, as opposed to a "minimization"
 * or "protection" framing of the same number) — the displayed percentage
 * and fill width always literally reflect `value`; only the color ramp's
 * direction flips, via the same 0.7/0.4 thresholds mirrored around 0.5
 * (0.3/0.6), so every existing "higher = good" usage is unaffected unless
 * it explicitly opts in.
 */
export function Meter({
  label,
  value,
  detail,
  invertColor = false,
}: {
  label: string;
  value: number;
  detail?: string;
  invertColor?: boolean;
}) {
  const pct = Math.max(0, Math.min(1, value)) * 100;
  const color = invertColor
    ? value <= 0.3
      ? "var(--status-good)"
      : value <= 0.6
        ? "var(--status-warning)"
        : "var(--status-critical)"
    : value >= 0.7
      ? "var(--status-good)"
      : value >= 0.4
        ? "var(--status-warning)"
        : "var(--status-critical)";

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 4 }}>
        <span style={{ color: "var(--text-secondary)" }}>{label}</span>
        <span className="mono" style={{ color, fontWeight: 700 }}>
          {pct.toFixed(0)}%
        </span>
      </div>
      <div
        style={{
          height: 8,
          borderRadius: 4,
          background: "var(--bg-panel-raised)",
          border: "1px solid var(--border-subtle)",
          overflow: "hidden",
        }}
      >
        <div
          style={{
            width: `${pct}%`,
            height: "100%",
            background: color,
            transition: "width 300ms ease",
          }}
        />
      </div>
      {detail && <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{detail}</div>}
    </div>
  );
}
