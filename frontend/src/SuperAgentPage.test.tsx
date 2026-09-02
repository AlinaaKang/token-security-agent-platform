import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";


const PRIVATE_SENTINEL = "PRIVATE_SUPERAGENT_SENTINEL";

const scenarios = [
  { scenario_id: "synthetic_safe", label: "普通无害", scenario_kind: "synthetic", attack_family: null, ready: true },
  { scenario_id: "sample_gcg", label: "GCG 优化攻击", scenario_kind: "protected", attack_family: "gcg", ready: true },
];

const capabilities = {
  ready: true,
  internal_only: true,
  objectives: ["investigate_and_respond"],
  actors: ["coordinator", "semantic_analyst", "token_analyst", "knowledge_analyst", "response_operator"],
  max_tool_calls: 3,
  max_trace_events: 12,
  replanning_limit: 1,
};

const blockMission = {
  mission_id: "mission_0123456789abcdef0123456789abcdef",
  run_id: "lab_0123456789abcdef0123456789abcdef",
  objective: "investigate_and_respond",
  scenario_id: "sample_gcg",
  scenario_label: "GCG 优化攻击",
  attack_family: "gcg",
  mode: "analysis",
  base_action: "block",
  final_status: "contained",
  initial_plan: [
    { sequence: 1, actor: "semantic_analyst", action_code: "inspect_semantic_evidence", summary: "检查语义安全等级和归一化类别。" },
    { sequence: 2, actor: "token_analyst", action_code: "inspect_token_distribution", summary: "检查 CPD 状态和脱敏异常起点。" },
  ],
  final_plan: ["gateway_enforcement", "security_case", "evidence_bundle"],
  events: [
    { sequence: 1, phase: "plan", actor: "coordinator", status: "succeeded", summary: "已建立有界调查计划。", evidence_codes: ["policy:bounded-react-v1"], tool_id: null },
    { sequence: 2, phase: "act", actor: "coordinator", status: "succeeded", summary: "基础检测与反事实检查已经完成。", evidence_codes: ["source:lab-run"], tool_id: null },
    { sequence: 3, phase: "observe", actor: "semantic_analyst", status: "succeeded", summary: "语义证据已归一化为 unsafe。", evidence_codes: ["semantic:unsafe"], tool_id: null, private: { raw: PRIVATE_SENTINEL } },
    { sequence: 4, phase: "observe", actor: "token_analyst", status: "succeeded", summary: "Token 分布证据已完成，存在异常候选。", evidence_codes: ["cpd:token_anomaly_candidate", "onset:42"], tool_id: null },
    { sequence: 5, phase: "observe", actor: "knowledge_analyst", status: "succeeded", summary: "知识证据已核验并保留真实知识 ID。", evidence_codes: ["knowledge_id:owasp-llm01-prompt-injection"], tool_id: null },
    { sequence: 6, phase: "replan", actor: "coordinator", status: "succeeded", summary: "基础动作 block 保持不变，选择 3 个平台内部工具。", evidence_codes: ["base_action:block"], tool_id: null },
    { sequence: 7, phase: "act", actor: "response_operator", status: "succeeded", summary: "内部网关状态执行成功。", evidence_codes: ["tool:gateway_enforcement"], tool_id: "gateway_enforcement" },
    { sequence: 8, phase: "observe", actor: "response_operator", status: "succeeded", summary: "内部工具回执已核验，执行动作保持基础判定。", evidence_codes: ["execution_count:3"], tool_id: null },
    { sequence: 9, phase: "complete", actor: "coordinator", status: "succeeded", summary: "任务闭环：平台内部响应全部完成。", evidence_codes: ["final_status:contained"], tool_id: null },
  ],
  executions: [
    { execution_id: "exec_01", tool_id: "gateway_enforcement", status: "succeeded", source_action: "block", effective_action: "block", receipt_id: "receipt_gateway", artifact_id: null, evidence_sha256: null },
    { execution_id: "exec_02", tool_id: "security_case", status: "succeeded", source_action: "block", effective_action: "block", receipt_id: "receipt_case", artifact_id: null, evidence_sha256: null },
    { execution_id: "exec_03", tool_id: "evidence_bundle", status: "succeeded", source_action: "block", effective_action: "block", receipt_id: "receipt_evidence", artifact_id: "artifact_01", evidence_sha256: `sha256:${"a".repeat(64)}` },
  ],
  limitations: ["仅执行平台内部仿真工具，不代表已联动外部安全设备。", "轨迹是结构化审计事件，不包含模型隐藏思维链。"],
  created_at: "2026-08-29T02:00:00Z",
};

const safeMission = {
  ...blockMission,
  scenario_id: "synthetic_safe",
  scenario_label: "普通无害",
  attack_family: null,
  base_action: "allow",
  final_status: "closed_safe",
  final_plan: [],
  executions: [],
  events: [
    { sequence: 1, phase: "plan", actor: "coordinator", status: "succeeded", summary: "已建立有界安全检查计划。", evidence_codes: ["policy:bounded-react-v1"], tool_id: null },
    { sequence: 2, phase: "act", actor: "coordinator", status: "succeeded", summary: "基础检测与反事实检查已经完成。", evidence_codes: ["source:lab-run"], tool_id: null },
    { sequence: 3, phase: "observe", actor: "semantic_analyst", status: "succeeded", summary: "语义证据已归一化为 safe。", evidence_codes: ["semantic:safe"], tool_id: null },
    { sequence: 4, phase: "observe", actor: "token_analyst", status: "succeeded", summary: "Token 分布未发现异常。", evidence_codes: ["detector:no_token_anomaly"], tool_id: null },
    { sequence: 5, phase: "replan", actor: "coordinator", status: "succeeded", summary: "基础动作 allow 保持不变，无需平台内部工具。", evidence_codes: ["base_action:allow"], tool_id: null },
    { sequence: 6, phase: "complete", actor: "coordinator", status: "succeeded", summary: "任务闭环：证据支持安全放行。", evidence_codes: ["final_status:closed_safe"], tool_id: null },
  ],
};

function response(payload: unknown, ok = true, status = 200) {
  return Promise.resolve({ ok, status, json: async () => payload });
}

function installFetch(mission: unknown = blockMission) {
  vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
    const url = String(input);
    if (url === "/api/v1/lab/scenarios") return response(scenarios);
    if (url === "/api/v1/superagent/capabilities") return response(capabilities);
    if (url === "/api/v1/superagent/missions") return response(mission, true, 201);
    if (url === `/api/v1/superagent/missions/${blockMission.mission_id}`) return response(mission);
    throw new Error(`Unexpected request: ${url}`);
  }));
}

function requestUrls() {
  return vi.mocked(fetch).mock.calls.map(([input]) => new URL(String(input), window.location.origin).pathname);
}

describe("bounded SuperAgent workspace", () => {
  beforeEach(() => {
    window.history.pushState({}, "", "/super-agent");
    installFetch();
  });

  afterEach(() => {
    cleanup();
    window.sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("labels the mission as an internal simulation and exposes bounded controls", async () => {
    render(<App />);

    expect(await screen.findByText("平台内部仿真闭环")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Prompt 安全调查" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "PCAP 证据分诊" })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByLabelText("任务场景")).toBeInTheDocument();
    expect(screen.getByLabelText("工作模式")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "启动自主任务" })).toBeEnabled();
    expect(screen.getByText("最多 3 次工具调用")).toBeInTheDocument();
    expect(requestUrls()).not.toContain("/api/v1/superagent/pcap/overview");
  });

  it("renders the auditable ReAct trace and bound execution receipts", async () => {
    render(<App />);
    const scenario = await screen.findByLabelText("任务场景");
    fireEvent.change(scenario, { target: { value: "sample_gcg" } });
    fireEvent.click(screen.getByRole("button", { name: "启动自主任务" }));

    expect(await screen.findByText(
      "任务闭环：平台内部响应全部完成。",
      {},
      { timeout: 3000 },
    )).toBeInTheDocument();
    const chain = screen.getByRole("region", { name: "可审计推理链" });
    expect(within(chain).getByRole("button", { name: /观察证据/ })).toBeInTheDocument();
    expect(within(chain).getByRole("button", { name: /应用规则/ })).toBeInTheDocument();
    expect(within(chain).getByRole("button", { name: /调整计划/ })).toBeInTheDocument();
    expect(within(chain).getByRole("button", { name: /执行动作/ })).toBeInTheDocument();
    expect(within(chain).getByRole("button", { name: /验证结果/ })).toBeInTheDocument();
    expect(within(chain).getByText("结构化审计轨迹，不包含隐藏思维链")).toBeInTheDocument();
    fireEvent.click(within(chain).getByRole("button", { name: /观察证据/ }));
    expect(screen.getByText("内部网关状态")).toBeInTheDocument();
    expect(screen.getByText("receipt_gateway")).toBeInTheDocument();
    expect(screen.getByText("owasp-llm01-prompt-injection")).toBeInTheDocument();
    expect(window.sessionStorage.getItem("token-security-superagent-mission-id")).toBe(
      blockMission.mission_id,
    );
    expect(document.body.textContent).not.toContain(PRIVATE_SENTINEL);
  });

  it("closes a safe mission without pretending to execute a response tool", async () => {
    cleanup();
    vi.unstubAllGlobals();
    installFetch(safeMission);
    render(<App />);
    await screen.findByLabelText("任务场景");
    fireEvent.click(screen.getByRole("button", { name: "启动自主任务" }));

    expect(await screen.findByText(
      "任务闭环：证据支持安全放行。",
      {},
      { timeout: 3000 },
    )).toBeInTheDocument();
    const chain = screen.getByRole("region", { name: "可审计推理链" });
    fireEvent.click(within(chain).getByRole("button", { name: /调整计划/ }));
    expect(within(chain).queryByText(/选择 3 个平台内部工具/)).not.toBeInTheDocument();
    fireEvent.click(within(chain).getByRole("button", { name: /验证结果/ }));
    expect(within(chain).queryByText(/内部工具回执已核验/)).not.toBeInTheDocument();
    expect(within(chain).queryByText("内部网关状态")).not.toBeInTheDocument();
    expect(screen.getByText("无需执行处置工具")).toBeInTheDocument();
    expect(screen.queryByText("内部网关状态")).not.toBeInTheDocument();
  });

  it("restores the sanitized mission after a page refresh", async () => {
    window.sessionStorage.setItem(
      "token-security-superagent-mission-id",
      blockMission.mission_id,
    );

    render(<App />);

    expect(await screen.findByText(
      "任务闭环：平台内部响应全部完成。",
      {},
      { timeout: 3000 },
    )).toBeInTheDocument();
    expect(fetch).toHaveBeenCalledWith(
      `/api/v1/superagent/missions/${blockMission.mission_id}`,
      undefined,
    );
  });

  it("clears an expired mission id without blocking the workspace", async () => {
    window.sessionStorage.setItem(
      "token-security-superagent-mission-id",
      blockMission.mission_id,
    );
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      if (url === "/api/v1/lab/scenarios") return response(scenarios);
      if (url === "/api/v1/superagent/capabilities") return response(capabilities);
      if (url.endsWith(blockMission.mission_id)) {
        return response({ error: { message: "任务已过期" } }, false, 410);
      }
      throw new Error(`Unexpected request: ${url}`);
    }));

    render(<App />);

    expect(await screen.findByRole("button", { name: "启动自主任务" })).toBeEnabled();
    expect(window.sessionStorage.getItem("token-security-superagent-mission-id")).toBeNull();
    expect(screen.queryByText("任务闭环：平台内部响应全部完成。")).not.toBeInTheDocument();
  });
});
