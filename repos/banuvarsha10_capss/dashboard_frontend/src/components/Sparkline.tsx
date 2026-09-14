/**
 * Small single-hue trend line across real per-step values (e.g. privacy
 * metrics across a scenario's registration steps). Deliberately one
 * metric per sparkline (small multiples) rather than one combined
 * multi-series chart — avoids needing a validated categorical palette for
 * what's really 2-6 data points per metric.
 */
export function Sparkline({
  values,
  label,
  format = (v: number) => v.toFixed(2),
  height = 40,
}: {
  values: number[];
  label: string;
  format?: (v: number) => string;
  height?: number;
}) {
  const width = 160;
  const pad = 4;
  const max = Math.max(...values, 0.001);
  const min = Math.min(...values, 0);
  const range = max - min || 1;

  const points = values.map((v, i) => {
    const x = values.length > 1 ? (i / (values.length - 1)) * (width - pad * 2) + pad : width / 2;
    const y = height - pad - ((v - min) / range) * (height - pad * 2);
    return `${x},${y}`;
  });

  const last = values[values.length - 1];

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, color: "var(--text-muted)" }}>
        <span>{label}</span>
        <span className="mono" style={{ color: "var(--text-primary)" }}>
          {format(last)}
        </span>
      </div>
      <svg width={width} height={height} role="img" aria-label={`${label} trend, ${values.length} points`}>
        <polyline
          points={points.join(" ")}
          fill="none"
          stroke="var(--accent-green-start)"
          strokeWidth={2}
          strokeLinejoin="round"
          strokeLinecap="round"
        />
        {values.length > 1 && (
          <circle
            cx={points[points.length - 1].split(",")[0]}
            cy={points[points.length - 1].split(",")[1]}
            r={4}
            fill="var(--accent-green-start)"
            stroke="var(--bg-panel)"
            strokeWidth={2}
          />
        )}
      </svg>
    </div>
  );
}
