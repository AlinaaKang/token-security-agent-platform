import { FileClock, ScanLine } from "lucide-react";
import { NavLink } from "react-router-dom";

export function PromptAnalysisNav() {
  return (
    <nav className="prompt-analysis-nav" aria-label="Prompt 安全分析视图">
      <NavLink to="/analyze" end><ScanLine size={16} aria-hidden="true" />检测分析</NavLink>
      <NavLink to="/events"><FileClock size={16} aria-hidden="true" />安全事件</NavLink>
    </nav>
  );
}
