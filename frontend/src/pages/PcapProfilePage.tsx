import { Activity, ShieldCheck } from "lucide-react";

import { PcapReconWorkspace } from "./PcapReconWorkspace";

export function PcapProfilePage() {
  return <main className="page pcap-profile-page" aria-label="PCAP 流量画像">
    <header className="page-header">
      <div><h1>PCAP 流量画像</h1><p>可自定义样本数量或覆盖全部可选文件，认识协议、规模、时长和可见性分布。</p></div>
      <span className="privacy-mark"><ShieldCheck size={15} /> 仅返回聚合统计</span>
    </header>
    <section className="pcap-profile-boundary" aria-label="画像边界">
      <Activity size={19} aria-hidden="true" />
      <div><strong>用于认识数据，不执行攻击检测</strong><p>页面不展示文件身份、地址、端口或载荷；需要定位异常时请使用“PCAP 数据调查”。</p></div>
    </section>
    <PcapReconWorkspace />
  </main>;
}
