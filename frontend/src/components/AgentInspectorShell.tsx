import { Braces, CircleDot, PanelRightClose } from "lucide-react";

type AgentInspectorShellProps = {
  pathname: string;
  className?: string;
  onClose?: () => void;
};

const labels: Record<string, { title: string; context: string }> = {
  "/super-agent": { title: "案件检查器", context: "证据、工具与报告会随当前任务更新" },
  "/analyze": { title: "分析检查器", context: "核对语义、Token 与知识证据" },
  "/events": { title: "事件检查器", context: "查看脱敏审计记录与运行状态" },
  "/evaluation": { title: "评测检查器", context: "核对指标口径、版本与覆盖范围" },
  "/lab": { title: "实验检查器", context: "区分真实检测、内部工具与仿真结果" },
  "/challenge": { title: "挑战检查器", context: "检查选择、证据位置与回合得分" },
};

export function AgentInspectorShell({ pathname, className = "", onClose }: AgentInspectorShellProps) {
  const copy = labels[pathname] ?? labels["/super-agent"];
  return (
    <aside className={`agent-inspector-shell ${className}`.trim()} aria-label={copy.title}>
      <header>
        <div><Braces size={17} /><strong>{copy.title}</strong></div>
        {onClose ? <button type="button" onClick={onClose} aria-label="关闭检查器"><PanelRightClose size={18} /></button> : null}
      </header>
      <div className="agent-inspector-empty">
        <CircleDot size={20} />
        <strong>等待选择</strong>
        <p>{copy.context}</p>
      </div>
      <footer><span />公开结构化数据</footer>
    </aside>
  );
}
