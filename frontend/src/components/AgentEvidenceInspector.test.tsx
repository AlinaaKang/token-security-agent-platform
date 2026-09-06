import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import type { AgentEvidence, AgentHypothesis } from "../agent/types";
import { AgentEvidenceInspector } from "./AgentEvidenceInspector";
import { AgentHypothesisPanel } from "./AgentHypothesisPanel";

const observed = "2026-09-07T08:00:00Z";
function evidence(evidence_id: string, authenticity: AgentEvidence["authenticity"], outcome: string): AgentEvidence {
  return { evidence_id, authenticity, source_type: "pcap_detection", source_ref: "授权批次", tool_id: "detect_pcap_batch", summary: `${evidence_id} 的公开检测结果`, observed_at: observed, uncertainty: "未证明攻击成功。", metadata: { outcome } };
}

afterEach(cleanup);

describe("AgentEvidenceInspector", () => {
  it("never presents simulated evidence as real", () => {
    render(<AgentEvidenceInspector evidence={[evidence("ev_sim", "simulated", "anomaly")]} />);
    expect(screen.getByText("仿真")).toBeVisible();
    expect(screen.queryByText("真实检测")).not.toBeInTheDocument();
  });

  it("separates anomaly failure and no-hit states", () => {
    render(<AgentEvidenceInspector evidence={[
      evidence("ev_alert", "real", "anomaly"),
      evidence("ev_failed", "real", "failed"),
      evidence("ev_clear", "real", "no_hit"),
    ]} />);
    expect(screen.getByText("发现异常候选")).toBeVisible();
    expect(screen.getByText("检测失败")).toBeVisible();
    expect(screen.getByText("当前范围未命中")).toBeVisible();
  });

  it("shows public packet ranges and filters with an attack-purpose caveat", () => {
    render(<AgentEvidenceInspector evidence={[{
      ...evidence("ev_http", "derived", "anomaly"),
      metadata: { outcome: "anomaly", packet_range: "packet 4-4", wireshark_filter: "frame.number == 4", attack_purpose: "疑似探测内部管理接口" },
    }]} />);
    expect(screen.getByText("packet 4-4")).toBeVisible();
    expect(screen.getByText("frame.number == 4")).toBeVisible();
    expect(screen.getByText(/目的候选，不代表攻击已成功/)).toBeVisible();
  });
});

describe("AgentHypothesisPanel", () => {
  it("shows support counter-evidence and confidence changes", () => {
    const hypotheses: AgentHypothesis[] = [{
      hypothesis_id: "hyp_01", title: "存在提示词注入侦察", status: "investigating", confidence: 0.68,
      supporting_evidence_refs: ["ev_http"], opposing_evidence_refs: ["ev_normal"],
      confidence_changes: [{ before: 0.35, after: 0.68, evidence_refs: ["ev_http"], reason: "HTTP 异常模式提高置信度", changed_at: observed }],
      limitations: ["仍需响应侧证据。"],
    }];
    render(<AgentHypothesisPanel hypotheses={hypotheses} />);
    expect(screen.getByText("支持证据")).toBeVisible();
    expect(screen.getByText("反对证据")).toBeVisible();
    expect(screen.getByText("置信度变化")).toBeVisible();
    expect(screen.getByText("35% → 68%")).toBeVisible();
  });
});
