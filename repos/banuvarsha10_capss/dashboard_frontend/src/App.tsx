import { Fragment, useState } from "react";
import type { DeviceResult, RunResult } from "./api/types";
import { useAttackRun } from "./hooks/useAttackRun";
import { useScalingRun } from "./hooks/useScalingRun";
import { AttackTestingPanel } from "./panels/AttackTestingPanel";
import { AIAgentPanel } from "./panels/AIAgentPanel";
import { ExplainabilityPanel } from "./panels/ExplainabilityPanel";
import { RecommendationPanel } from "./panels/RecommendationPanel";
import { AssessmentPanel } from "./panels/AssessmentPanel";
import { PerformancePanel } from "./panels/PerformancePanel";
import { ExperienceTimelinePanel } from "./panels/ExperienceTimelinePanel";
import { SystemsPrivacyPanel } from "./panels/SystemsPrivacyPanel";
import { PipelineVisualizerPanel } from "./panels/PipelineVisualizerPanel";
import { ManualScenarioPanel } from "./panels/ManualScenarioPanel";
import { KnowledgeBaseViewerPanel } from "./panels/KnowledgeBaseViewerPanel";
import { ScalingPanel } from "./panels/ScalingPanel";

const TABS = [
  { key: "attack-testing", label: "Attack Testing", tier: 1 },
  { key: "ai-agent", label: "AI Agent", tier: 1 },
  { key: "explainability", label: "Explainability", tier: 1 },
  { key: "recommendation", label: "Recommendation", tier: 1 },
  { key: "assessment", label: "Assessment", tier: 1 },
  { key: "performance", label: "Performance", tier: 1 },
  { key: "pipeline-visualizer", label: "Pipeline Visualizer", tier: 2 },
  { key: "systems-privacy", label: "Systems + Privacy", tier: 2 },
  { key: "experience-timeline", label: "Experience Timeline", tier: 2 },
  { key: "manual-scenario", label: "Manual Scenario", tier: 2 },
  { key: "knowledge-base", label: "Knowledge Base", tier: 2 },
  { key: "scaling", label: "Scaling / Throughput", tier: 2 },
] as const;

type TabKey = (typeof TABS)[number]["key"];

export default function App() {
  const [activeTab, setActiveTab] = useState<TabKey>("attack-testing");
  const [selectedDevice, setSelectedDevice] = useState<DeviceResult | null>(null);

  // Bug 1 fix: owned here, not inside AttackTestingPanel -- App never
  // unmounts while switching sidebar tabs, so the run's state and its
  // streaming subscription now survive navigation. AttackTestingPanel only
  // reads this via props; it no longer owns any of its own run state.
  const attackRun = useAttackRun();
  // Same Bug 1 pattern as attackRun -- owned here so a long 100-500 device
  // scaling run survives switching sidebar tabs instead of being discarded.
  const scalingRun = useScalingRun();

  function handleRunComplete(run: RunResult) {
    if (run.devices.length > 0) setSelectedDevice(run.devices[0]);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">CAPSS Dashboard</div>
        {TABS.map((tab, i) => (
          <Fragment key={tab.key}>
            {i === 6 && (
              <div
                style={{
                  fontSize: 10,
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                  color: "var(--text-muted)",
                  padding: "12px 12px 4px",
                  fontWeight: 700,
                }}
              >
                Tier 2
              </div>
            )}
            <button
              className={`nav-item ${activeTab === tab.key ? "active" : ""}`}
              onClick={() => setActiveTab(tab.key)}
            >
              {tab.label}
            </button>
          </Fragment>
        ))}
      </aside>

      <main className="main-content">
        {/* Bug 1, requirement 4: visible/actionable from every panel, not
            just Attack Testing -- a real batch keeps touching real hardware
            regardless of which tab is active, so the ability to see and
            stop it can't be scoped to one panel. */}
        {attackRun.running && activeTab !== "attack-testing" && (
          <div className="global-run-banner">
            <span className="spinner" />
            <span>
              Attack batch running in the background
              {attackRun.total > 0 && ` — device ${(attackRun.viewIndex ?? 0) + 1} of ${attackRun.total}`}.
            </span>
            <span className="global-run-banner-actions">
              <button className="btn btn-secondary" onClick={() => setActiveTab("attack-testing")}>
                View
              </button>
              <button className="btn btn-secondary" onClick={attackRun.stop} disabled={attackRun.stopping}>
                {attackRun.stopping ? "Stopping…" : "Stop attack"}
              </button>
            </span>
          </div>
        )}

        {activeTab === "attack-testing" && (
          <AttackTestingPanel
            attackRun={attackRun}
            onRun={(params) => attackRun.startRun(params, handleRunComplete, setSelectedDevice)}
            selectedUeId={selectedDevice?.ue_id ?? null}
            onSelectDevice={setSelectedDevice}
          />
        )}
        {activeTab === "ai-agent" && <AIAgentPanel device={selectedDevice} />}
        {activeTab === "explainability" && <ExplainabilityPanel device={selectedDevice} />}
        {activeTab === "recommendation" && <RecommendationPanel device={selectedDevice} />}
        {activeTab === "assessment" && <AssessmentPanel device={selectedDevice} />}
        {activeTab === "performance" && <PerformancePanel attackRun={attackRun} />}
        {activeTab === "pipeline-visualizer" && <PipelineVisualizerPanel device={selectedDevice} />}
        {activeTab === "systems-privacy" && <SystemsPrivacyPanel device={selectedDevice} />}
        {activeTab === "experience-timeline" && (
          <ExperienceTimelinePanel selectedUeId={selectedDevice?.ue_id ?? null} />
        )}
        {activeTab === "manual-scenario" && <ManualScenarioPanel onResult={setSelectedDevice} />}
        {activeTab === "knowledge-base" && <KnowledgeBaseViewerPanel />}
        {activeTab === "scaling" && <ScalingPanel scalingRun={scalingRun} />}
      </main>
    </div>
  );
}
