import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { useState } from "react";
import type { AgentTaskSnapshot } from "./agent/types";

import { AgentInspectorShell } from "./components/AgentInspectorShell";
import { AgentMobileNav } from "./components/AgentMobileNav";
import { AgentSidebar } from "./components/AgentSidebar";
import { GuidedTour } from "./components/GuidedTour";
import { AnalyzePage } from "./pages/AnalyzePage";
import { ChallengePage } from "./pages/ChallengePage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { EventsPage } from "./pages/EventsPage";
import { LabPage } from "./pages/LabPage";
import { AgentWorkspacePage } from "./pages/AgentWorkspacePage";
import { TOURS } from "./tourConfig";
import "./styles.css";

function Shell() {
  const location = useLocation();
  const tour = TOURS[location.pathname];
  const [menuOpen, setMenuOpen] = useState(false);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [agentTask, setAgentTask] = useState<AgentTaskSnapshot | null>(null);

  return (
    <div className="app-shell">
      <AgentMobileNav onMenu={() => setMenuOpen(true)} onInspector={() => setInspectorOpen(true)} />
      <AgentSidebar className={menuOpen ? "is-open" : ""} onNavigate={() => setMenuOpen(false)} />
      {menuOpen || inspectorOpen ? <button className="agent-drawer-scrim" type="button" aria-label="关闭浮层" onClick={() => { setMenuOpen(false); setInspectorOpen(false); }} /> : null}
      <div className="agent-main-stage">
        <Routes>
          <Route path="/analyze" element={<AnalyzePage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/evaluation" element={<EvaluationPage />} />
          <Route path="/lab" element={<LabPage />} />
          <Route path="/super-agent" element={<AgentWorkspacePage onTaskChange={setAgentTask} />} />
          <Route path="/challenge" element={<ChallengePage />} />
          <Route path="*" element={<Navigate to="/super-agent" replace />} />
        </Routes>
      </div>
      <AgentInspectorShell pathname={location.pathname} task={agentTask} className={inspectorOpen ? "is-open" : ""} onClose={() => setInspectorOpen(false)} />
      {tour && location.pathname !== "/challenge" ? <GuidedTour key={location.pathname} route={location.pathname} steps={tour} /> : null}
    </div>
  );
}

export function App() {
  return <BrowserRouter><Shell /></BrowserRouter>;
}
