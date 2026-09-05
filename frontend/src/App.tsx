import { BarChart3, FileWarning, FlaskConical, Gamepad2, ScanLine, ShieldCheck, Workflow } from "lucide-react";
import { BrowserRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";

import { AnalyzePage } from "./pages/AnalyzePage";
import { ChallengePage } from "./pages/ChallengePage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { EventsPage } from "./pages/EventsPage";
import { LabPage } from "./pages/LabPage";
import { SuperAgentPage } from "./pages/SuperAgentPage";
import "./styles.css";

const navigationGroups = [
  {
    id: "detection-response",
    label: "检测与处置",
    items: [
      { to: "/analyze", label: "安全分析", icon: ScanLine },
      { to: "/super-agent", label: "自主处置", icon: Workflow },
      { to: "/events", label: "安全事件", icon: FileWarning },
    ],
  },
  {
    id: "validation-evaluation",
    label: "验证与评测",
    items: [
      { to: "/lab", label: "攻防实验舱", icon: FlaskConical },
      { to: "/evaluation", label: "评测中心", icon: BarChart3 },
    ],
  },
  {
    id: "interactive-demo",
    label: "互动演示",
    items: [
      { to: "/challenge", label: "Token 侦探挑战", icon: Gamepad2 },
    ],
  },
] as const;

function Shell() {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark"><ShieldCheck size={22} /></div>
          <span>Token Sentinel</span>
        </div>
        <p className="product-name">面向AI安全的Token流量异常检测智能体平台</p>
        <nav aria-label="主导航">
          {navigationGroups.map((group) => (
            <div className="nav-group" role="group" aria-label={group.label} key={group.id}>
              <span className="nav-group-label" aria-hidden="true">{group.label}</span>
              <div className="nav-group-links">
                {group.items.map(({ to, label, icon: Icon }) => (
                  <NavLink key={to} to={to} className={({ isActive }) => isActive ? "active" : undefined}>
                    <Icon size={18} /> <span>{label}</span>
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="system-state"><span /> 研究原型 · 基础与进阶任务</div>
      </aside>
      <Routes>
        <Route path="/analyze" element={<AnalyzePage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/evaluation" element={<EvaluationPage />} />
        <Route path="/lab" element={<LabPage />} />
        <Route path="/super-agent" element={<SuperAgentPage />} />
        <Route path="/challenge" element={<ChallengePage />} />
        <Route path="*" element={<Navigate to="/analyze" replace />} />
      </Routes>
    </div>
  );
}

export function App() {
  return <BrowserRouter><Shell /></BrowserRouter>;
}
