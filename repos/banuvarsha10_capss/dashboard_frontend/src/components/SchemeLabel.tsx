// Full scheme names, pulled from the real knowledge base's own "name"
// field — used everywhere a scheme's short form (GS, DP, AP, ZKP, IBE,
// ECIES, ML-KEM) is displayed, so the short form is never shown alone.
export const SCHEME_FULL_NAMES: Record<string, string> = {
  ECIES: "Elliptic Curve Integrated Encryption Scheme",
  "ML-KEM": "Module-Lattice Key Encapsulation Mechanism",
  DP: "Dynamic Pseudonyms",
  AP: "Adaptive Padding",
  ZKP: "Zero-Knowledge Proofs",
  GS: "Group Signatures",
  IBE: "Identity-Based Encryption",
};

/** "Group Signatures (GS)" — full name first, short form in parens. Use
 * in prose/sentences and anywhere a single combined string is needed. */
export function schemeFullLabel(shortName: string | null | undefined): string {
  if (!shortName) return "—";
  const full = SCHEME_FULL_NAMES[shortName];
  return full ? `${full} (${shortName})` : shortName;
}

/** Compact display: short form stays visually primary (tables, badges,
 * chart axes), full name added alongside in muted text — never replaces
 * the short form, only adds to it. */
export function SchemeLabel({
  shortName,
  className,
  style,
}: {
  shortName: string | null | undefined;
  className?: string;
  style?: React.CSSProperties;
}) {
  if (!shortName) {
    return (
      <span className={className} style={style}>
        —
      </span>
    );
  }
  const full = SCHEME_FULL_NAMES[shortName];
  return (
    <span className={className} style={style}>
      <span className="mono" style={{ fontWeight: 700 }}>
        {shortName}
      </span>
      {full && (
        <span style={{ color: "var(--text-muted)", fontSize: "0.85em", marginLeft: 6 }}>{full}</span>
      )}
    </span>
  );
}
