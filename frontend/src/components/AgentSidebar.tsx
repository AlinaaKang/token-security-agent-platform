import {
  BarChart3,
  BookOpenCheck,
  Bot,
  Cable,
  FileClock,
  FileText,
  FlaskConical,
  Gamepad2,
  ScanLine,
  ShieldCheck,
  Wrench,
} from "lucide-react";
import { Link, NavLink } from "react-router-dom";

type AgentSidebarProps = {
  className?: string;
  onNavigate?: () => void;
};

const groups = [
  {
    label: "安全案件",
    items: [
      { to: "/super-agent", label: "安全智能体", icon: Bot },
      { to: "/events", label: "安全事件", icon: FileClock },
    ],
  },
  {
    label: "专业工作区",
    items: [
      { to: "/analyze", label: "安全分析", icon: ScanLine },
      { to: "/lab", label: "攻防实验舱", icon: FlaskConical },
      { to: "/evaluation", label: "评测中心", icon: BarChart3 },
      { to: "/challenge", label: "Token 侦探挑战", icon: Gamepad2 },
    ],
  },
] as const;

const resources = [
  { query: "skills", label: "检测技能", icon: Wrench },
  { query: "knowledge", label: "安全知识库", icon: BookOpenCheck },
  { query: "connectors", label: "数据连接器", icon: Cable },
  { query: "reports", label: "调查报告", icon: FileText },
] as const;

export function AgentSidebar({ className = "", onNavigate }: AgentSidebarProps) {
  return (
    <aside className={`sidebar agent-sidebar ${className}`.trim()}>
      <Link className="agent-brand" to="/super-agent" onClick={onNavigate} aria-label="Token Security 首页">
        <span className="agent-brand-mark"><ShieldCheck size={21} /></span>
        <span><strong>Token Security</strong><small>自主安全调查</small></span>
      </Link>
      <nav aria-label="主导航">
        {groups.map((group) => (
          <section className="agent-nav-group" role="group" aria-label={group.label} key={group.label}>
            <h2>{group.label}</h2>
            <div>
              {group.items.map(({ to, label, icon: Icon }) => (
                <NavLink key={to} to={to} onClick={onNavigate}>
                  <Icon size={17} aria-hidden="true" /><span>{label}</span>
                </NavLink>
              ))}
            </div>
          </section>
        ))}
        <section className="agent-nav-group" role="group" aria-label="智能体资源">
          <h2>智能体资源</h2>
          <div>
            {resources.map(({ query, label, icon: Icon }) => (
              <Link key={query} to={`/super-agent?resource=${query}`} onClick={onNavigate}>
                <Icon size={17} aria-hidden="true" /><span>{label}</span>
              </Link>
            ))}
          </div>
        </section>
      </nav>
      <div className="agent-runtime-state"><span aria-hidden="true" />本地编排可用</div>
    </aside>
  );
}
