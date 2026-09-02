import { describe, expect, it } from "vitest";

import type { PcapMissionResult } from "../types";
import {
  buildPcapRoleLines,
  finishPcapRole,
  initialPcapInvestigationState,
  roleStateForPcap,
  selectPcapRole,
} from "./investigation";

const networkOnlyMission: PcapMissionResult = {
  mission_id: "mission_public",
  objective: "triage_pcap_evidence",
  status: "completed",
  batch_id: "batch_public",
  events: [],
  summary: {
    schema_version: 1,
    batch_id: "batch_public",
    selected_count: 3,
    succeeded_count: 2,
    failed_count: 1,
    skipped_count: 0,
    captures: [
      {
        capture_id: "capture_plaintext",
        status: "succeeded",
        packet_count: 24,
        protocol_counts: { http: 24 },
        visibility: {
          plaintext_application_protocol_observed: true,
          encrypted_transport_observed: false,
          tls_observed: false,
          quic_observed: false,
        },
        capability: "token_eligible",
        error_code: null,
      },
      {
        capture_id: "capture_encrypted",
        status: "succeeded",
        packet_count: 18,
        protocol_counts: { tls: 18 },
        visibility: {
          plaintext_application_protocol_observed: false,
          encrypted_transport_observed: true,
          tls_observed: true,
          quic_observed: false,
        },
        capability: "traffic_only",
        error_code: null,
      },
      {
        capture_id: "capture_failed",
        status: "failed",
        packet_count: 0,
        protocol_counts: {},
        visibility: {
          plaintext_application_protocol_observed: false,
          encrypted_transport_observed: false,
          tls_observed: false,
          quic_observed: false,
        },
        capability: null,
        error_code: "inspection_failed",
      },
    ],
  },
  report: {
    confirmed: ["traffic_only_evidence"],
    candidates: ["plaintext_application_protocol_candidate_not_proven_llm_traffic"],
    unknowns: ["cpd_evidence_unavailable", "token_evidence_unavailable"],
    recommended_action: ["retain_public_metadata"],
  },
  limitations: ["no_packet_payload_retained", "token_evidence_unavailable"],
  created_at: "2026-09-01T02:00:00Z",
};

describe("PCAP investigation state", () => {
  it("unlocks Guard then CPD then Captain and allows completed-role review", () => {
    let state = initialPcapInvestigationState();
    expect(roleStateForPcap(state, "guard")).toBe("ready");
    expect(roleStateForPcap(state, "cpd")).toBe("locked");
    expect(roleStateForPcap(state, "captain")).toBe("locked");

    state = finishPcapRole(selectPcapRole(state, "guard"), "guard");
    expect(roleStateForPcap(state, "cpd")).toBe("ready");
    state = finishPcapRole(selectPcapRole(state, "cpd"), "cpd");
    expect(roleStateForPcap(state, "captain")).toBe("ready");
    state = finishPcapRole(selectPcapRole(state, "captain"), "captain");

    expect(selectPcapRole(state, "guard").selectedRole).toBe("guard");
  });

  it("ignores selection of a role that has not unlocked", () => {
    const state = initialPcapInvestigationState();
    expect(selectPcapRole(state, "cpd")).toBe(state);
    expect(selectPcapRole(state, "captain")).toBe(state);
  });
});

describe("PCAP public evidence builders", () => {
  it("limits Guard evidence to visibility and unavailable Prompt semantics", () => {
    expect(buildPcapRoleLines(networkOnlyMission, "guard")).toEqual([
      { section: "evidence", text: "尚未恢复 Prompt，语义证据暂不可用" },
      { section: "evidence", text: "明文应用协议可见：1 / 3 个捕获" },
      { section: "evidence", text: "加密传输可见：1 / 3 个捕获；加密载荷内容不可见" },
    ]);
  });

  it("describes token eligibility only as a plaintext protocol candidate", () => {
    const lines = buildPcapRoleLines(networkOnlyMission, "cpd");
    expect(lines).toEqual([
      {
        section: "evidence",
        text: "明文应用协议候选：1 个；仅表示协议可见性，不证明 LLM 流量、越狱、CPD 或 Token 异常",
      },
      { section: "evidence", text: "模型与 Token 证据不可用" },
    ]);
    expect(lines.map(({ text }) => text).join(" ")).not.toMatch(/异常 Token 起点|Token 位置|Prompt 内容/);
  });

  it("separates Captain counts into confirmed, candidate, and unknown findings", () => {
    expect(buildPcapRoleLines(networkOnlyMission, "captain")).toEqual([
      { section: "evidence", text: "批次计数：已选择 3，成功 2，失败 1，跳过 0" },
      { section: "confirmed", text: "仅有网络流量证据" },
      { section: "candidate", text: "明文应用协议候选，不证明 LLM 流量" },
      { section: "unknown", text: "CPD 证据不可用；Token 证据不可用" },
    ]);
  });
});
