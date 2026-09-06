import { describe, expect, it } from "vitest";

import type { PcapCaptureEvidence } from "../types";
import {
  buildPcapRoleLines,
  finishPcapRole,
  initialPcapInvestigationState,
  roleStateForPcap,
  selectPcapRole,
} from "./investigation";

const plaintextCapture: PcapCaptureEvidence = {
  capture_id: "capture_plaintext",
  status: "succeeded",
  packet_count: 12,
  protocol_counts: { tls: 2, http: 12 },
  visibility: {
    plaintext_application_protocol_observed: true,
    encrypted_transport_observed: false,
    tls_observed: false,
    quic_observed: false,
  },
  capability: "token_eligible",
  error_code: null,
};

const encryptedCapture: PcapCaptureEvidence = {
  capture_id: "capture_encrypted",
  status: "succeeded",
  packet_count: 18,
  protocol_counts: { quic: 3, tls: 18 },
  visibility: {
    plaintext_application_protocol_observed: false,
    encrypted_transport_observed: true,
    tls_observed: true,
    quic_observed: true,
  },
  capability: "traffic_only",
  error_code: null,
};

const failedCapture: PcapCaptureEvidence = {
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
  error_code: "inspector_failed",
};

const failedWithoutCodeCapture: PcapCaptureEvidence = {
  ...failedCapture,
  capture_id: "capture_failed_without_code",
  error_code: null,
};

const skippedCapture: PcapCaptureEvidence = {
  ...failedCapture,
  capture_id: "capture_skipped",
  status: "skipped",
  error_code: null,
};

const insufficientCapture: PcapCaptureEvidence = {
  ...plaintextCapture,
  capture_id: "capture_insufficient",
  protocol_counts: {},
  visibility: {
    plaintext_application_protocol_observed: false,
    encrypted_transport_observed: false,
    tls_observed: false,
    quic_observed: false,
  },
  capability: "insufficient_evidence",
};

describe("PCAP investigation state", () => {
  it("unlocks parser then traffic then captain and allows completed-role review", () => {
    let state = initialPcapInvestigationState();
    expect(roleStateForPcap(state, "parser")).toBe("ready");
    expect(roleStateForPcap(state, "traffic")).toBe("locked");
    expect(roleStateForPcap(state, "captain")).toBe("locked");

    state = finishPcapRole(selectPcapRole(state, "parser"), "parser");
    expect(roleStateForPcap(state, "traffic")).toBe("ready");
    state = finishPcapRole(selectPcapRole(state, "traffic"), "traffic");
    expect(roleStateForPcap(state, "captain")).toBe("ready");
    state = finishPcapRole(selectPcapRole(state, "captain"), "captain");

    expect(selectPcapRole(state, "parser").selectedRole).toBe("parser");
  });

  it("ignores selection of a role that has not unlocked", () => {
    const state = initialPcapInvestigationState();
    expect(selectPcapRole(state, "traffic")).toBe(state);
    expect(selectPcapRole(state, "captain")).toBe(state);
  });
});

describe("PCAP per-capture evidence builders", () => {
  it("describes a successful plaintext capture for the parser", () => {
    expect(buildPcapRoleLines(plaintextCapture, "parser")).toEqual([
      { section: "evidence", text: "检查成功；已验证 12 个数据包" },
    ]);
  });

  it("exposes only a public error code for a failed parser check", () => {
    expect(buildPcapRoleLines(failedCapture, "parser")).toEqual([
      { section: "evidence", text: "检查失败；错误代码：inspector_failed" },
    ]);
    expect(buildPcapRoleLines(failedWithoutCodeCapture, "parser")).toEqual([
      { section: "evidence", text: "检查失败；错误代码：未提供错误代码" },
    ]);
  });

  it("describes a skipped capture without forming a new result", () => {
    expect(buildPcapRoleLines(skippedCapture, "parser")).toEqual([
      { section: "evidence", text: "检查跳过；未形成新的检查结果" },
    ]);
  });

  it("sorts protocol counts and explains plaintext evidence capability", () => {
    expect(buildPcapRoleLines(plaintextCapture, "traffic")).toEqual([
      { section: "evidence", text: "协议计数：HTTP 12" },
      { section: "evidence", text: "协议计数：TLS 2" },
      { section: "evidence", text: "明文应用协议可见" },
      { section: "evidence", text: "证据能力：可继续进行应用层检测；不证明存在 LLM 流量或攻击" },
    ]);
  });

  it("distinguishes encrypted and unavailable application-layer visibility", () => {
    expect(buildPcapRoleLines(encryptedCapture, "traffic")).toEqual([
      { section: "evidence", text: "协议计数：QUIC 3" },
      { section: "evidence", text: "协议计数：TLS 18" },
      { section: "evidence", text: "加密传输可见；应用层内容不可见" },
      { section: "evidence", text: "证据能力：仅有网络证据可用，无法恢复应用层语义" },
    ]);
    expect(buildPcapRoleLines(insufficientCapture, "traffic")).toEqual([
      { section: "evidence", text: "协议计数：无可用协议计数" },
      { section: "evidence", text: "应用层不可见" },
      { section: "evidence", text: "证据能力：可观测证据不足，无法形成可靠结论" },
    ]);
  });

  it("summarizes a failed capture with four captain sections", () => {
    expect(buildPcapRoleLines(failedCapture, "captain")).toEqual([
      { section: "confirmed", text: "未形成可验证检查结果" },
      { section: "candidate", text: "暂无可复核网络证据" },
      { section: "unknown", text: "失败原因：inspector_failed" },
      { section: "recommendation", text: "建议重试该文件" },
    ]);
  });

  it.each([
    [plaintextCapture, "建议进入异常检测继续研判"],
    [encryptedCapture, "建议保留网络元数据供人工复核"],
    [insufficientCapture, "建议补充可见流量后重试"],
  ] as const)("gives a bounded captain recommendation for %s", (capture, recommendation) => {
    const lines = buildPcapRoleLines(capture, "captain");
    expect(lines.map(({ section }) => section)).toEqual(["confirmed", "candidate", "unknown", "recommendation"]);
    expect(lines.at(-1)).toEqual({ section: "recommendation", text: recommendation });
  });

  it("does not expose attack or semantic verdicts in any role output", () => {
    const captures = [plaintextCapture, encryptedCapture, failedCapture, skippedCapture, insufficientCapture];
    const lines = captures.flatMap((capture) => [
      ...buildPcapRoleLines(capture, "parser"),
      ...buildPcapRoleLines(capture, "traffic"),
      ...buildPcapRoleLines(capture, "captain"),
    ]);
    expect(lines.map(({ text }) => text).join(" ")).not.toMatch(/Prompt|CPD|Token 异常|SQL 注入/);
  });
});
