import { Network, ScanSearch, ShieldAlert } from "lucide-react";

const roles = [
  {
    stage: 1,
    title: "包解析员",
    detail: "查看协议、方向、时间与脱敏包内容",
    Icon: ScanSearch,
  },
  {
    stage: 2,
    title: "流量关联员",
    detail: "比较正常基线并定位首次异常",
    Icon: Network,
  },
  {
    stage: 3,
    title: "攻击研判员",
    detail: "判断攻击类型、目的与影响",
    Icon: ShieldAlert,
  },
] as const;

export function PcapForensicRoles({ activeStage }: { activeStage: 1 | 2 | 3 }) {
  return <section className="pcap-forensic-workflow" aria-label="PCAP 三角色取证流程">
    <ol className="pcap-forensic-roles">
      {roles.map(({ stage, title, detail, Icon }) => <li
        className="pcap-forensic-role"
        aria-current={activeStage === stage ? "step" : undefined}
        key={title}
      >
        <span className="pcap-forensic-role-icon"><Icon size={20} aria-hidden="true" /></span>
        <div><small>步骤 {stage}</small><strong>{title}</strong><p>{detail}</p></div>
      </li>)}
    </ol>
  </section>;
}
