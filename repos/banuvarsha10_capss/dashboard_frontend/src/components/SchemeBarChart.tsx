import type { SchemeScore } from "../api/types";
import { SCHEME_FULL_NAMES } from "./SchemeLabel";

/**
 * Single-hue magnitude chart (final_score across all 7 schemes) — not a
 * categorical/identity chart, so no multi-hue palette is needed (dataviz
 * skill: sequential = one hue). The winner gets the full accent gradient;
 * every other bar is a dimmed step of the same hue. Value at the bar tip,
 * no legend (single series — the card title already says what's plotted).
 */
export function SchemeBarChart({ scores }: { scores: SchemeScore[] }) {
  const sorted = [...scores].sort((a, b) => b.final_score - a.final_score);
  const max = Math.max(...sorted.map((s) => s.final_score), 0.01);
  const winnerId = sorted[0]?.scheme_id;

  return (
    <div className="bar-chart" role="img" aria-label="Final score by scheme, highest first">
      {sorted.map((s) => {
        const isWinner = s.scheme_id === winnerId;
        const pct = Math.max((s.final_score / max) * 100, 2);
        return (
          <div
            className="bar-chart-row"
            key={s.scheme_id}
            title={`${SCHEME_FULL_NAMES[s.short_name] ?? s.short_name} (${s.short_name}): ${s.final_score.toFixed(3)}`}
          >
            <span className={`bar-chart-label ${isWinner ? "is-winner" : ""}`}>{s.short_name}</span>
            <div className="bar-chart-track">
              <div
                className={`bar-chart-fill ${isWinner ? "is-winner" : ""}`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className={`bar-chart-value ${isWinner ? "is-winner" : ""}`}>
              {s.final_score.toFixed(3)}
            </span>
          </div>
        );
      })}
    </div>
  );
}
