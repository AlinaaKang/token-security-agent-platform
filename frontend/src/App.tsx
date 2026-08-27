import { BarChart3, FileWarning, FlaskConical, ScanLine, ShieldCheck } from "lucide-react";
import { BrowserRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";

import { AnalyzePage } from "./pages/AnalyzePage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { EventsPage } from "./pages/EventsPage";
import { LabPage } from "./pages/LabPage";
import "./styles.css";

const navigation = [
  { to: "/analyze", label: "安全分析", icon: ScanLine },
  { to: "/events", label: "安全事件", icon: FileWarning },
  { to: "/evaluation", label: "评测中心", icon: BarChart3 },
  { to: "/lab", label: "攻防实验舱", icon: FlaskConical },
];

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
          {navigation.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} className={({ isActive }) => isActive ? "active" : undefined}>
              <Icon size={18} /> <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="system-state"><span /> 研究原型 · 基础与进阶任务</div>
      </aside>
      <Routes>
        <Route path="/analyze" element={<AnalyzePage />} />
        <Route path="/events" element={<EventsPage />} />
        <Route path="/evaluation" element={<EvaluationPage />} />
        <Route path="/lab" element={<LabPage />} />
        <Route path="*" element={<Navigate to="/analyze" replace />} />
      </Routes>
    </div>
  );
}

export function App() {
  return <BrowserRouter><Shell /></BrowserRouter>;
}
