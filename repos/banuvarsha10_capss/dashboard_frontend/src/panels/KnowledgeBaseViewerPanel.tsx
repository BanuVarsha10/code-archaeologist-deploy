import { useEffect, useState } from "react";
import type { PrivacyScheme } from "../api/types";
import { getKnowledgeBase } from "../api/client";
import { Card } from "../components/Card";

export function KnowledgeBaseViewerPanel() {
  const [schemes, setSchemes] = useState<PrivacyScheme[] | null>(null);
  const [version, setVersion] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const [compareA, setCompareA] = useState<string | null>(null);
  const [compareB, setCompareB] = useState<string | null>(null);

  useEffect(() => {
    getKnowledgeBase()
      .then((res) => {
        setSchemes(res.schemes);
        setVersion(res.knowledge_version);
      })
      .catch((err) => setError(err.message ?? "Failed to load knowledge base"));
  }, []);

  if (error) {
    return (
      <div>
        <PageHeader version={version} />
        <div className="empty-state">{error}</div>
      </div>
    );
  }

  if (!schemes) {
    return (
      <div>
        <PageHeader version={version} />
        <div className="empty-state">
          <span className="spinner" /> Loading knowledge base…
        </div>
      </div>
    );
  }

  const schemeA = schemes.find((s) => s.short_name === compareA);
  const schemeB = schemes.find((s) => s.short_name === compareB);

  return (
    <div>
      <PageHeader version={version} />

      <div className="card-grid">
        {schemes.map((s) => (
          <Card key={s.id} title={`${s.short_name} — ${s.name}`}>
            <p style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 0 }}>{s.description}</p>
            <div className="metric-row">
              <span className="metric-label">Category</span>
              <span className="metric-value">{s.category}</span>
            </div>
            <div className="metric-row">
              <span className="metric-label">Threat level</span>
              <span className="metric-value">
                {s.decision_support.recommendation_profile.threat_level}
              </span>
            </div>
            <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 4 }}>
              {s.decision_support.recommendation_profile.capabilities.slice(0, 4).map((c) => (
                <span className="badge badge-neutral" key={c}>
                  {c}
                </span>
              ))}
            </div>
            <button
              className="btn btn-secondary"
              style={{ marginTop: 12 }}
              onClick={() => (compareA ? setCompareB(s.short_name) : setCompareA(s.short_name))}
            >
              {compareA === s.short_name || compareB === s.short_name ? "Selected for compare" : "Compare"}
            </button>
          </Card>
        ))}
      </div>

      {schemeA && schemeB && (
        <div style={{ marginTop: 24 }}>
          <Card
            title={`Compare: ${schemeA.name} (${schemeA.short_name}) vs ${schemeB.name} (${schemeB.short_name})`}
          >
            <button
              className="btn btn-secondary"
              style={{ marginBottom: 12 }}
              onClick={() => {
                setCompareA(null);
                setCompareB(null);
              }}
            >
              Clear comparison
            </button>
            <div className="check4-grid">
              <SchemeDetail scheme={schemeA} />
              <SchemeDetail scheme={schemeB} />
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

function SchemeDetail({ scheme }: { scheme: PrivacyScheme }) {
  const profile = scheme.decision_support.recommendation_profile;
  return (
    <Card>
      <div className="block-kicker">
        {scheme.short_name} — {scheme.name}
      </div>
      <div className="metric-row">
        <span className="metric-label">Privacy level</span>
        <span className="metric-value">{profile.privacy_level}</span>
      </div>
      <div className="metric-row">
        <span className="metric-label">Latency level</span>
        <span className="metric-value">{profile.latency_level}</span>
      </div>
      <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8 }}>Best when:</p>
      <ul style={{ fontSize: 12, color: "var(--text-secondary)", paddingLeft: 18, margin: 0 }}>
        {profile.best_when.map((b) => (
          <li key={b}>{b}</li>
        ))}
      </ul>
      <p style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 8 }}>Advantages:</p>
      <ul style={{ fontSize: 12, color: "var(--text-secondary)", paddingLeft: 18, margin: 0 }}>
        {scheme.advantages.slice(0, 4).map((a) => (
          <li key={a}>{a}</li>
        ))}
      </ul>
    </Card>
  );
}

function PageHeader({ version }: { version: string }) {
  return (
    <div className="page-header">
      <h1 className="page-title">Knowledge Base</h1>
      <p className="page-subtitle">
        All 7 privacy schemes from data/privacy_schemes.json (read-only){version && ` · ${version}`}.
      </p>
    </div>
  );
}
