import type { ConfidenceTrendEntry } from "../api/types";

/**
 * Single-series line chart (confidence over time for one UE) — 2px line,
 * end-marker with a surface ring, direct label only at the end point
 * (dataviz skill: label the endpoint, not every point). No legend needed
 * for a single series.
 */
export function ConfidenceTrendChart({ entries }: { entries: ConfidenceTrendEntry[] }) {
  if (entries.length === 0) return null;

  const width = 560;
  const height = 140;
  const padding = 24;
  const innerW = width - padding * 2;
  const innerH = height - padding * 2;

  const points = entries.map((e, i) => {
    const x = padding + (entries.length === 1 ? innerW / 2 : (i / (entries.length - 1)) * innerW);
    const y = padding + (1 - e.confidence) * innerH;
    return { x, y, entry: e };
  });

  const path = points.map((p, i) => `${i === 0 ? "M" : "L"} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(" ");
  const last = points[points.length - 1];

  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Confidence trend over time">
      {/* recessive baseline gridlines */}
      {[0, 0.5, 1].map((frac) => (
        <line
          key={frac}
          x1={padding}
          x2={width - padding}
          y1={padding + frac * innerH}
          y2={padding + frac * innerH}
          stroke="var(--border-subtle)"
          strokeWidth={1}
        />
      ))}
      <path d={path} fill="none" stroke="var(--accent-green-start)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
      {points.map((p, i) => (
        <circle
          key={i}
          cx={p.x}
          cy={p.y}
          r={4}
          fill="var(--accent-green-start)"
          stroke="var(--bg-panel)"
          strokeWidth={2}
        />
      ))}
      <text x={last.x} y={last.y - 12} fill="var(--text-primary)" fontSize="11" textAnchor="end" fontWeight={700}>
        {last.entry.confidence.toFixed(2)}
      </text>
    </svg>
  );
}
