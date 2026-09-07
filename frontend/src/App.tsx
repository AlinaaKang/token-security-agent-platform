import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useCallback, useEffect, useState } from "react";
import type { AgentTaskSnapshot } from "./agent/types";
import type { PcapDetectionMissionResult } from "./types";
import { api } from "./api";
import { agentWorkspaceUrl, resolveAgentWorkspaceMode } from "./agent/workspaceMode";
import { clearLocalConversation } from "./agent/localConversation";

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
import { AgentResourcePage } from "./pages/AgentResourcePage";
import { PcapChallengePage } from "./pages/PcapChallengePage";
import { PcapProfilePage } from "./pages/PcapProfilePage";
import { PcapEvaluationPage } from "./pages/PcapEvaluationPage";
import { resolveTour } from "./tourConfig";
import "./styles.css";

function Shell() {
  const location = useLocation();
  const navigate = useNavigate();
  const tour = resolveTour(location.pathname, location.search);
  const resource = new URLSearchParams(location.search).get("resource");
  const [menuOpen, setMenuOpen] = useState(false);
  const [inspectorOpen, setInspectorOpen] = useState(false);
  const [agentTask, setAgentTask] = useState<AgentTaskSnapshot | null>(null);
  const [recentTasks, setRecentTasks] = useState<AgentTaskSnapshot[]>([]);
  const [pcapMission, setPcapMission] = useState<PcapDetectionMissionResult | null>(null);
  const params = new URLSearchParams(location.search);
  const selectedTaskId = params.has("task") ? params.get("task") : params.has("mode") ? null : undefined;
  const workspaceMode = resolveAgentWorkspaceMode(location.search, agentTask);
  const showAgentInspector = location.pathname === "/super-agent" && !resource;

  const updateRecentTask = useCallback((task: AgentTaskSnapshot) => {
    setRecentTasks((items) => [task, ...items.filter((item) => item.task_id !== task.task_id)]
      .sort((left, right) => right.updated_at.localeCompare(left.updated_at))
      .slice(0, 20));
  }, []);

  const deleteRecentTask = useCallback(async (taskId: string, mode: "prompt" | "pcap") => {
    await api.deleteAgentTask(taskId);
    clearLocalConversation(taskId);
    setRecentTasks((items) => items.filter((item) => item.task_id !== taskId));
    if (selectedTaskId === taskId || agentTask?.task_id === taskId) {
      setAgentTask(null);
      navigate(agentWorkspaceUrl(mode));
    }
  }, [agentTask?.task_id, navigate, selectedTaskId]);

  useEffect(() => {
    if (location.pathname !== "/super-agent") return;
    let active = true;
    api.listAgentTasks().then((page) => {
      if (active) setRecentTasks(page.items);
    }).catch(() => undefined);
    return () => { active = false; };
  }, [location.pathname]);

  useEffect(() => {
    if (!showAgentInspector) setInspectorOpen(false);
  }, [showAgentInspector]);

  return (
    <div className={`app-shell${showAgentInspector ? " has-agent-inspector" : ""}`}>
      <AgentMobileNav showInspector={showAgentInspector} onMenu={() => setMenuOpen(true)} onInspector={() => setInspectorOpen(true)} />
      <AgentSidebar className={menuOpen ? "is-open" : ""} onNavigate={() => setMenuOpen(false)} recentTasks={recentTasks} activeTaskId={selectedTaskId ?? agentTask?.task_id ?? null} onDeleteTask={deleteRecentTask} />
      {menuOpen || inspectorOpen ? <button className="agent-drawer-scrim" type="button" aria-label="关闭浮层" onClick={() => { setMenuOpen(false); setInspectorOpen(false); }} /> : null}
      <div className="agent-main-stage">
        <Routes>
          <Route path="/analyze" element={<AnalyzePage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/evaluation" element={<EvaluationPage />} />
          <Route path="/lab" element={<LabPage />} />
          <Route path="/super-agent" element={resource ? <AgentResourcePage resource={resource} /> : <AgentWorkspacePage
            mode={workspaceMode}
            selectedTaskId={selectedTaskId}
            onTaskChange={setAgentTask}
            onTaskUpdate={updateRecentTask}
            onTaskSelect={(taskId, mode = workspaceMode) => navigate(agentWorkspaceUrl(mode, taskId))}
            pcapMission={pcapMission}
            onPcapMissionChange={setPcapMission}
          />} />
          <Route path="/challenge" element={<ChallengePage />} />
          <Route path="/pcap-challenge" element={<PcapChallengePage />} />
          <Route path="/pcap-profile" element={<PcapProfilePage />} />
          <Route path="/pcap-evaluation" element={<PcapEvaluationPage />} />
          <Route path="*" element={<Navigate to="/super-agent" replace />} />
        </Routes>
      </div>
      {showAgentInspector ? <AgentInspectorShell pathname={location.pathname} task={agentTask} pcapMission={agentTask ? null : pcapMission} resource={resource} className={inspectorOpen ? "is-open" : ""} onClose={() => setInspectorOpen(false)} /> : null}
      {tour && location.pathname !== "/challenge" ? <GuidedTour key={tour.route} route={tour.route} steps={tour.steps} /> : null}
    </div>
  );
}

export function App() {
  return <BrowserRouter><Shell /></BrowserRouter>;
}
