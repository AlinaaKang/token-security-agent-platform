import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { AgentTaskSnapshot } from "../agent/types";
import type { PcapDetectionMissionResult } from "../types";
import { AgentInspectorShell } from "./AgentInspectorShell";

const timestamp = "2026-09-07T08:00:00Z";

function task(taskType: string): AgentTaskSnapshot {
  return {
    task_id: "task_01", version: 1, task_type: taskType, status: "completed",
    title: "调查", objective_summary: "调查目标", created_at: timestamp, updated_at: timestamp,
    messages: [], plan: [], observations: [], evidence: [], hypotheses: [], timeline: [], conflicts: [], events: [],
    replan_count: 0, authorization_scopes: [], final_status: "safe", report: null, limitations: [],
  };
}

function mission(): PcapDetectionMissionResult {
  return {
    detection_id: "detection_01", objective: "detect_pcap_anomalies", status: "completed", events: [],
    summary: { schema_version: 1, analyzed_count: 1, succeeded_count: 1, failed_count: 0, evidence: [], processed_samples: [{ sample_index: 1, status: "succeeded", evidence_count: 0, failure_code: null }] },
    report: { confirmed_evidence_ids: [], candidate_evidence_ids: [], unknowns: ["no_localized_attack_evidence"], recommended_actions: ["allow_no_rule_evidence"] },
    failure_code: null, created_at: timestamp,
  };
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("AgentInspectorShell task-specific views", () => {
  it("shows Prompt investigation labels for a Prompt task", () => {
    render(<AgentInspectorShell pathname="/super-agent" task={task("prompt_investigation")} />);

    expect(screen.getByRole("complementary", { name: "Prompt 调查检查器" })).toBeVisible();
    for (const label of ["Guard", "Token", "复核", "工具", "报告"]) {
      expect(screen.getByRole("button", { name: label })).toBeVisible();
    }
  });

  it("shows PCAP mission labels and does not cancel when switching tabs", () => {
    render(<AgentInspectorShell pathname="/super-agent" task={null} pcapMission={mission()} />);

    expect(screen.getByRole("complementary", { name: "PCAP 调查检查器" })).toBeVisible();
    for (const label of ["概况", "Packet", "解析", "报告"]) {
      expect(screen.getByRole("button", { name: label })).toBeVisible();
    }
    fireEvent.click(screen.getByRole("button", { name: "Packet" }));
    expect(screen.getByText("没有可定位的异常 Packet")).toBeVisible();
  });

  it("keeps the general evidence inspector for a cross-domain case", () => {
    render(<AgentInspectorShell pathname="/super-agent" task={task("cross_domain_case")} />);
    expect(screen.getByRole("complementary", { name: "案件检查器" })).toBeVisible();
    expect(screen.getByRole("button", { name: "证据" })).toBeVisible();
    expect(screen.getByRole("button", { name: "时间线" })).toBeVisible();
  });
});
