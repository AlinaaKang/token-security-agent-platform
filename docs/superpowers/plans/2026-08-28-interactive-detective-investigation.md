# Token 侦探互动调查模式 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `/challenge` 增加默认的三侦探点击调查模式，同时完整保留现有 `700ms` 自动演示回放。

**Architecture:** `ChallengePage` 拥有展示模式、调查步骤和重置规则；新的纯函数状态模块控制 guard -> cpd -> agent 解锁；`MascotTeam` 只渲染可访问按钮和动作；`InvestigationDesk` 只把已返回的 `LabRunResult` 转换为确定性证据。互动状态不进入后端、挑战 reducer、评分或持久化。

**Tech Stack:** React 19、TypeScript 5.8、Vitest、Testing Library、现有 SVG 曲线、CSS keyframes。

## Global Constraints

- 只修改挑战页前端、挑战文档和对应测试；不修改后端、API、模型、CPD、融合策略、评分、样本、知识智能体、工具执行、`/analyze` 或 `/lab` 行为。
- `互动调查` 是默认展示模式；`自动演示` 保留固定 `700ms` 回放和“跳过回放”。展示模式只能在进入挑战前选择。
- 互动顺序固定为 guard -> cpd -> agent；队长完成前不显示答题区，队长汇报不得展示 `decision` 或正确处置动作。
- 已访问角色可回看；回看不改变解锁进度，也不重新播放完整走路动画。
- 后端未返回或请求失败时不解锁角色；单项证据不可用不得阻断三步调查。
- 受保护样本不显示 `prompt`、`suffix`、`token_text`、`token_id`、`query_text`、`raw_output` 或 `guard_raw_output`。当前 `LabRunResult` 不包含合成样本原文，本轮不得虚构或新增该字段。
- 三名角色始终占据稳定空间，不覆盖证据台、题目或按钮，不产生全局横向滚动。
- `prefers-reduced-motion: reduce` 下取消入场、走位、倾斜、呼吸和庆祝，但点击、选中、汇报、回看和答题解锁必须完整可用。
- 不新增动画库、声音、自由拖拽、遥测、持久化、排行榜或 Playwright 运行时依赖。

## File Map

- Create `frontend/src/challenge/investigation.ts`: 纯调查状态、解锁规则和角色状态派生。
- Create `frontend/src/challenge/investigation.test.ts`: 状态机和回看规则测试。
- Create `frontend/src/components/InvestigationDesk.tsx`: 三类确定性证据面板。
- Create `frontend/src/components/InvestigationDesk.test.tsx`: 字段映射、不可用状态和决策保密测试。
- Modify `frontend/src/components/ChallengeSignalPicker.tsx`: 增加只读曲线模式。
- Modify `frontend/src/components/ChallengeSignalPicker.test.tsx`: 锁定只读模式无 Token 选择按钮。
- Modify `frontend/src/components/MascotTeam.tsx`: 公仔按钮语义、锁定/就绪/汇报/回看状态和点击事件。
- Modify `frontend/src/components/MascotTeam.test.tsx`: 键盘可达、严格解锁和动作测试。
- Modify `frontend/src/pages/ChallengePage.tsx`: 模式选择、互动状态所有权、证据台和答题门控。
- Modify `frontend/src/ChallengePage.test.tsx`: 两种模式、三步流程、重置与现有自动回放回归。
- Modify `frontend/src/styles.css`: 模式分段控制、中央证据台、角色按钮、响应式和 reduced-motion。
- Modify `docs/token-detective-challenge.md`: 使用说明、互动边界和最新验证记录。

---

### Task 1: 纯调查状态与严格解锁

**Files:**
- Create: `frontend/src/challenge/investigation.ts`
- Create: `frontend/src/challenge/investigation.test.ts`

**Interfaces:**
- Consumes: 无外部运行时状态。
- Produces: `PresentationMode`、`InvestigationRole`、`InvestigationStep`、`InvestigationSelectionKind`、`InvestigationRoleState`、`InvestigationState`、`createInvestigationState()`、`canInspectRole()`、`inspectRole()`、`roleStateFor()`。

- [ ] **Step 1: 写状态机失败测试**

创建 `frontend/src/challenge/investigation.test.ts`：

```ts
import { describe, expect, it } from "vitest";

import {
  canInspectRole,
  createInvestigationState,
  inspectRole,
  roleStateFor,
} from "./investigation";

describe("interactive detective investigation", () => {
  it("starts with only the semantic detective ready", () => {
    const state = createInvestigationState();
    expect(state.step).toBe("semantic");
    expect(roleStateFor(state, "guard")).toBe("ready");
    expect(roleStateFor(state, "cpd")).toBe("locked");
    expect(roleStateFor(state, "agent")).toBe("locked");
  });

  it("unlocks guard, cpd, and agent in that order", () => {
    let state = createInvestigationState();
    state = inspectRole(state, "guard");
    expect(state.step).toBe("cpd");
    expect(roleStateFor(state, "guard")).toBe("presenting");
    expect(roleStateFor(state, "cpd")).toBe("ready");

    state = inspectRole(state, "cpd");
    expect(state.step).toBe("captain");
    expect(roleStateFor(state, "agent")).toBe("ready");

    state = inspectRole(state, "agent");
    expect(state.step).toBe("complete");
    expect(state.visitedRoles).toEqual(new Set(["guard", "cpd", "agent"]));
  });

  it("ignores a locked role", () => {
    const state = createInvestigationState();
    expect(canInspectRole(state, "agent")).toBe(false);
    expect(inspectRole(state, "agent")).toBe(state);
  });

  it("allows revisiting without changing progress", () => {
    let state = inspectRole(createInvestigationState(), "guard");
    state = inspectRole(state, "cpd");
    const reviewed = inspectRole(state, "guard");
    expect(reviewed.step).toBe("captain");
    expect(reviewed.selectedRole).toBe("guard");
    expect(reviewed.selectionKind).toBe("review");
    expect(roleStateFor(reviewed, "guard")).toBe("visited");
    expect(roleStateFor(reviewed, "agent")).toBe("ready");
  });

  it("marks first visits separately from reviews", () => {
    const first = inspectRole(createInvestigationState(), "guard");
    expect(first.selectionKind).toBe("first_visit");
    const review = inspectRole(first, "guard");
    expect(review.selectionKind).toBe("review");
  });

  it("creates a fresh independent visited set on reset", () => {
    const changed = inspectRole(createInvestigationState(), "guard");
    const reset = createInvestigationState();
    expect(changed.visitedRoles.has("guard")).toBe(true);
    expect(reset.visitedRoles.size).toBe(0);
  });
});
```

- [ ] **Step 2: 运行测试并确认 RED**

Run:

```powershell
cd frontend
npm.cmd test -- src/challenge/investigation.test.ts
```

Expected: FAIL，因为 `./investigation` 尚不存在。

- [ ] **Step 3: 实现最小纯状态模块**

创建 `frontend/src/challenge/investigation.ts`：

```ts
export type PresentationMode = "interactive" | "auto";
export type InvestigationRole = "guard" | "cpd" | "agent";
export type InvestigationStep = "semantic" | "cpd" | "captain" | "complete";
export type InvestigationSelectionKind = "first_visit" | "review" | null;
export type InvestigationRoleState = "locked" | "ready" | "presenting" | "visited";

export interface InvestigationState {
  step: InvestigationStep;
  selectedRole: InvestigationRole | null;
  selectionKind: InvestigationSelectionKind;
  visitedRoles: ReadonlySet<InvestigationRole>;
}

const STEP_ROLE: Record<Exclude<InvestigationStep, "complete">, InvestigationRole> = {
  semantic: "guard",
  cpd: "cpd",
  captain: "agent",
};

const NEXT_STEP: Record<InvestigationRole, InvestigationStep> = {
  guard: "cpd",
  cpd: "captain",
  agent: "complete",
};

export function createInvestigationState(): InvestigationState {
  return {
    step: "semantic",
    selectedRole: null,
    selectionKind: null,
    visitedRoles: new Set<InvestigationRole>(),
  };
}

export function canInspectRole(state: InvestigationState, role: InvestigationRole): boolean {
  if (state.visitedRoles.has(role)) return true;
  return state.step !== "complete" && STEP_ROLE[state.step] === role;
}

export function inspectRole(
  state: InvestigationState,
  role: InvestigationRole,
): InvestigationState {
  if (!canInspectRole(state, role)) return state;
  const revisiting = state.visitedRoles.has(role);
  const visitedRoles = new Set(state.visitedRoles);
  visitedRoles.add(role);
  return {
    step: revisiting ? state.step : NEXT_STEP[role],
    selectedRole: role,
    selectionKind: revisiting ? "review" : "first_visit",
    visitedRoles,
  };
}

export function roleStateFor(
  state: InvestigationState,
  role: InvestigationRole,
): InvestigationRoleState {
  if (state.selectedRole === role && state.selectionKind === "first_visit") return "presenting";
  if (state.visitedRoles.has(role)) return "visited";
  if (state.step !== "complete" && STEP_ROLE[state.step] === role) return "ready";
  return "locked";
}
```

- [ ] **Step 4: 运行测试并确认 GREEN**

Run:

```powershell
npm.cmd test -- src/challenge/investigation.test.ts
```

Expected: 6 tests PASS。

- [ ] **Step 5: 提交状态模块**

```powershell
git add frontend/src/challenge/investigation.ts frontend/src/challenge/investigation.test.ts
git commit -m "feat: model interactive investigation state"
```

---

### Task 2: 只读曲线与中央证据台

**Files:**
- Modify: `frontend/src/components/ChallengeSignalPicker.tsx`
- Modify: `frontend/src/components/ChallengeSignalPicker.test.tsx`
- Create: `frontend/src/components/InvestigationDesk.tsx`
- Create: `frontend/src/components/InvestigationDesk.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `LabRunResult`、Task 1 的 `InvestigationRole`、现有 `expectedEvidenceRelation()`。
- Produces: `ChallengeSignalPicker` 新增 `readOnly?: boolean`；`InvestigationDesk({ run, role })`。

- [ ] **Step 1: 写只读曲线失败测试**

在 `ChallengeSignalPicker.test.tsx` 增加：

```tsx
it("renders the signal chart without Token controls in read-only mode", () => {
  const onSelect = vi.fn();
  render(
    <ChallengeSignalPicker
      signals={signals}
      selectedIndex={null}
      onSelect={onSelect}
      readOnly
    />,
  );
  expect(screen.getByRole("img", { name: "Token 挑战信号曲线" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /选择 Token/ })).not.toBeInTheDocument();
  expect(onSelect).not.toHaveBeenCalled();
});
```

- [ ] **Step 2: 写证据台失败测试**

创建 `InvestigationDesk.test.tsx`。先定义完整固定对象和浅覆盖 helper：

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { LabRunResult } from "../types";
import { InvestigationDesk } from "./InvestigationDesk";

const run = {
  run_id: "run-redacted-001",
  status: "completed",
  scenario_id: "synthetic_safe",
  scenario_kind: "synthetic",
  scenario_label: "普通无害请求",
  attack_family: null,
  mode: "analysis",
  created_at: "2026-08-27T09:00:00Z",
  stages: [],
  detection: {
    decision: "sanitize_recheck",
    risk_score: 0.72,
    detector_score: 8.4,
    detector_status: "token_anomaly_candidate",
    semantic_severity: "safe",
    semantic_categories: ["jailbreak"],
    semantic_model_id: "guard-model",
    semantic_model_version: "guard-v1",
    semantic_latency_ms: 4,
    fusion_reason: "cpd_candidate",
    suspicious_span: { token_start: 2, token_end: 3, char_start: 0, char_end: 0 },
    signals: [
      { index: 0, entropy: 0.8, nll: 1.1, cpd_entropy: 0, cpd_nll: 0, risk: 0.1 },
      { index: 2, entropy: 3.8, nll: 4.4, cpd_entropy: 5.8, cpd_nll: 0, risk: 0.9 },
    ],
    provenance: {
      model_id: "qwen-model",
      tokenizer_id: "qwen-tokenizer",
      system_prompt_hash: "redacted-hash",
      calibration_version: "cal-v2",
      thresholds: { k: 0.5, h: 5 },
    },
    latency_ms: 28,
    knowledge_status: "off",
    knowledge_snapshot_version: null,
    knowledge_latency_ms: 0,
    knowledge_evidence: [],
    report_status: "off",
  },
  counterfactual: {
    interpretation: "inconclusive",
    reason: "no_predicted_onset",
    char_start: null,
    calibration_version: "cal-v2",
    original: {
      semantic_severity: "safe",
      detector_status: "token_anomaly_candidate",
      risk_score: 0.72,
      detector_score: 8.4,
      decision: "sanitize_recheck",
      latency_ms: 28,
    },
    rechecked: null,
    risk_score_delta: null,
    detector_score_delta: null,
    action_changed: false,
  },
  tool_plans: [],
  tool_results: [],
  case_report: {
    report_status: "deterministic",
    summary: "脱敏测试报告",
    evidence_ids: [],
    handling_steps: [],
    limitations: [],
    tool_statuses: {},
  },
} satisfies LabRunResult;

function withDetection(overrides: Partial<LabRunResult["detection"]>): LabRunResult {
  return { ...run, detection: { ...run.detection, ...overrides } };
}
```

随后加入以下六个用例：

```tsx
it("shows semantic evidence for the guard", () => {
  render(<InvestigationDesk run={run} role="guard" />);
  expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("语义安全");
  expect(screen.getByText("jailbreak")).toBeInTheDocument();
  expect(screen.getByText("4.0 ms")).toBeInTheDocument();
  expect(screen.getByText("guard-model / guard-v1")).toBeInTheDocument();
});

it("shows a stable semantic unavailable report", () => {
  render(<InvestigationDesk run={withDetection({ semantic_severity: "unavailable" })} role="guard" />);
  expect(screen.getByText("语义证据不可用")).toBeInTheDocument();
});

it("shows CPD status, score, threshold, onset, and a read-only chart", () => {
  render(<InvestigationDesk run={run} role="cpd" />);
  expect(screen.getByText("发现分布候选")).toBeInTheDocument();
  expect(screen.getByText("8.40")).toBeInTheDocument();
  expect(screen.getByText("5.00")).toBeInTheDocument();
  expect(screen.getByText("Token 2")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /选择 Token/ })).not.toBeInTheDocument();
});

it("states that a distribution candidate is not proof of maliciousness", () => {
  render(<InvestigationDesk run={run} role="cpd" />);
  expect(screen.getByText("分布异常只代表候选信号，不单独证明恶意")).toBeInTheDocument();
});

it("shows an unavailable onset without blocking the CPD report", () => {
  render(<InvestigationDesk run={withDetection({ suspicious_span: null })} role="cpd" />);
  expect(screen.getByText("不适用")).toBeInTheDocument();
});

it("summarizes evidence without revealing the final decision", () => {
  render(<InvestigationDesk run={withDetection({ decision: "block" })} role="agent" />);
  const desk = screen.getByRole("region", { name: "中央证据台" });
  expect(desk).toHaveTextContent("仅分布异常");
  expect(desk).toHaveTextContent("两路证据存在分歧");
  expect(desk).not.toHaveTextContent("拦截");
  expect(desk).not.toHaveTextContent("block");
});
```

固定对象使用 `satisfies LabRunResult` 做编译期接口校验；`withDetection` 只浅覆盖 `run.detection`，保留其余完整脱敏结果。

- [ ] **Step 3: 运行两组测试并确认 RED**

Run:

```powershell
npm.cmd test -- src/components/ChallengeSignalPicker.test.tsx src/components/InvestigationDesk.test.tsx
```

Expected: FAIL，因为 `readOnly` 和 `InvestigationDesk` 尚不存在。

- [ ] **Step 4: 实现只读曲线模式**

给 `ChallengeSignalPickerProps` 增加：

```ts
readOnly?: boolean;
```

组件参数设置 `readOnly = false`，并把目标按钮容器改为：

```tsx
{!readOnly ? (
  <div className="challenge-signal-targets">
    {signals.map((signal, position) => (
      <button
        type="button"
        className={signal.index === selectedIndex ? "selected" : ""}
        style={{ left: `${(xAtPosition(position, signals.length) / SIGNAL_CHART_WIDTH) * 100}%` }}
        aria-label={`选择 Token ${signal.index}`}
        title={`选择 Token ${signal.index}`}
        key={signal.index}
        ref={(node) => { buttonRefs.current[position] = node; }}
        onClick={() => onSelect(signal.index)}
        onKeyDown={(event) => handleKeyDown(event, position)}
      >
        <Flag size={13} aria-hidden="true" />
      </button>
    ))}
  </div>
) : null}
```

不改变现有交互模式的键盘行为、最小宽度或信号不足回退。

- [ ] **Step 5: 实现证据台组件**

创建 `InvestigationDesk.tsx`，使用以下接口和确定性映射：

```tsx
import { Activity, BadgeCheck, ShieldCheck } from "lucide-react";

import { expectedEvidenceRelation } from "../challenge/scoring";
import type { InvestigationRole } from "../challenge/investigation";
import type { EvidenceRelation } from "../challenge/types";
import type { LabRunResult } from "../types";
import { ChallengeSignalPicker } from "./ChallengeSignalPicker";

interface InvestigationDeskProps {
  run: LabRunResult;
  role: InvestigationRole;
}

const EVIDENCE_LABELS: Record<EvidenceRelation, string> = {
  dual_normal: "双路正常",
  semantic_only: "仅语义风险",
  distribution_only: "仅分布异常",
  dual_risk: "双路风险",
};

const SEMANTIC_LABELS = {
  safe: "语义安全",
  controversial: "语义争议",
  unsafe: "语义危险",
  unavailable: "语义证据不可用",
} as const;

export function InvestigationDesk({ run, role }: InvestigationDeskProps) {
  const detection = run.detection;
  const relation = expectedEvidenceRelation(run);
  const conflict = relation === "semantic_only" || relation === "distribution_only";

  return (
    <section className="challenge-investigation-desk" aria-label="中央证据台" aria-live="polite">
      {role === "guard" ? (
        <>
          <header><ShieldCheck aria-hidden="true" /><strong>语义侦探汇报</strong></header>
           <div className="challenge-investigation-facts">
             <div><span>语义等级</span><strong>{SEMANTIC_LABELS[detection.semantic_severity]}</strong></div>
             <div><span>风险类别</span><strong>{detection.semantic_categories.length ? detection.semantic_categories.join("、") : "未命中风险类别"}</strong></div>
             <div><span>检测耗时</span><strong>{detection.semantic_latency_ms.toFixed(1)} ms</strong></div>
             <div><span>模型版本</span><strong>{detection.semantic_model_id} / {detection.semantic_model_version}</strong></div>
           </div>
        </>
      ) : null}
      {role === "cpd" ? (
        <>
          <header><Activity aria-hidden="true" /><strong>曲线侦探汇报</strong></header>
          <div className="challenge-investigation-facts">
            <div><span>检测状态</span><strong>{detection.detector_status === "token_anomaly_candidate" ? "发现分布候选" : "未发现分布候选"}</strong></div>
            <div><span>CPD 分数</span><strong>{detection.detector_score.toFixed(2)}</strong></div>
            <div><span>阈值 h</span><strong>{detection.provenance.thresholds.h?.toFixed(2) ?? "不可用"}</strong></div>
            <div><span>异常起点</span><strong>{detection.suspicious_span ? `Token ${detection.suspicious_span.token_start}` : "不适用"}</strong></div>
          </div>
          <p className="challenge-investigation-caveat">分布异常只代表候选信号，不单独证明恶意</p>
          <ChallengeSignalPicker signals={detection.signals} selectedIndex={null} onSelect={() => undefined} readOnly />
        </>
      ) : null}
      {role === "agent" ? (
        <>
          <header><BadgeCheck aria-hidden="true" /><strong>小队队长总结</strong></header>
          <div className="challenge-investigation-conclusion">
            <span>证据关系</span><strong>{relation ? EVIDENCE_LABELS[relation] : "证据不可用"}</strong>
            <p>{relation === null ? "现有证据不足以形成双路关系" : conflict ? "两路证据存在分歧" : "两路证据结论一致"}</p>
          </div>
        </>
      ) : null}
    </section>
  );
}
```

- [ ] **Step 6: 添加证据台基础样式**

在挑战样式区增加：

```css
.challenge-investigation-desk {
  min-width: 0;
  margin-top: 14px;
  padding: 18px;
  border: 1px solid var(--line);
  border-top: 2px solid var(--trusted);
  border-radius: 8px;
  background: var(--surface);
}
.challenge-investigation-desk > header { display: flex; align-items: center; gap: 8px; }
.challenge-investigation-desk > header svg { color: var(--trusted); }
.challenge-investigation-facts {
  margin-top: 14px;
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border: 1px solid var(--line);
}
.challenge-investigation-facts > div { min-width: 0; padding: 11px; display: grid; gap: 5px; border-right: 1px solid var(--line); }
.challenge-investigation-facts > div:last-child { border-right: 0; }
.challenge-investigation-facts span,
.challenge-investigation-conclusion span { color: var(--muted); font-size: 10px; }
.challenge-investigation-facts strong { overflow-wrap: anywhere; font-size: 12px; }
.challenge-investigation-caveat { margin: 12px 0; color: var(--review); font-size: 11px; }
.challenge-investigation-conclusion { margin-top: 14px; padding: 14px; border-left: 3px solid var(--trusted); background: var(--trusted-soft); display: grid; gap: 6px; }
.challenge-investigation-conclusion p { margin: 0; color: var(--muted); font-size: 11px; }
```

- [ ] **Step 7: 运行组件测试和构建**

Run:

```powershell
npm.cmd test -- src/components/ChallengeSignalPicker.test.tsx src/components/InvestigationDesk.test.tsx
npm.cmd run build
```

Expected: 两个测试文件全部 PASS，构建成功。

- [ ] **Step 8: 提交证据台**

```powershell
git add frontend/src/components/ChallengeSignalPicker.tsx frontend/src/components/ChallengeSignalPicker.test.tsx frontend/src/components/InvestigationDesk.tsx frontend/src/components/InvestigationDesk.test.tsx frontend/src/styles.css
git commit -m "feat: add interactive investigation desk"
```

---

### Task 3: 可点击公仔与首次汇报动作

**Files:**
- Modify: `frontend/src/components/MascotTeam.tsx`
- Modify: `frontend/src/components/MascotTeam.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: Task 1 的 `InvestigationState`、`InvestigationRole`、`canInspectRole()`、`roleStateFor()`。
- Produces: `MascotTeam` 新增可选 `interaction` 属性：`{ state: InvestigationState; onSelect(role: InvestigationRole): void }`。

- [ ] **Step 1: 写互动公仔失败测试**

在 `MascotTeam.test.tsx` 增加以下五个用例：

```tsx
function interactiveTeam(state = createInvestigationState(), onSelect = vi.fn()) {
  return render(
    <MascotTeam
      phase="guessing"
      replayStageId={null}
      evidenceConflict={false}
      interaction={{ state, onSelect }}
    />,
  );
}

it("renders real role buttons and enables only the ready detective", () => {
  interactiveTeam();
  expect(screen.getByRole("button", { name: /Guard 语义侦探.*可以汇报/ })).toBeEnabled();
  expect(screen.getByRole("button", { name: /CPD 曲线侦探.*等待语义侦探/ })).toBeDisabled();
  expect(screen.getByRole("button", { name: /Agent 小队队长.*等待曲线侦探/ })).toBeDisabled();
});

it("emits the selected role from mouse or keyboard activation", () => {
  const onSelect = vi.fn();
  interactiveTeam(createInvestigationState(), onSelect);
  fireEvent.click(screen.getByRole("button", { name: /Guard 语义侦探/ }));
  expect(onSelect).toHaveBeenCalledWith("guard");
});

it("marks a first visit as presenting and moves only that role", () => {
  const state = inspectRole(createInvestigationState(), "guard");
  interactiveTeam(state);
  const figure = screen.getByRole("button", { name: /Guard 语义侦探/ }).closest("figure");
  expect(figure).toHaveAttribute("data-role-state", "presenting");
  expect(figure).toHaveAttribute("data-motion", "approach");
});

it("keeps a reviewed role in the lineup without replaying approach", () => {
  const first = inspectRole(createInvestigationState(), "guard");
  const reviewed = inspectRole(first, "guard");
  interactiveTeam(reviewed);
  const figure = screen.getByRole("button", { name: /Guard 语义侦探/ }).closest("figure");
  expect(figure).toHaveAttribute("data-role-state", "visited");
  expect(figure).toHaveAttribute("data-motion", "idle");
  expect(screen.getByRole("button", { name: /Guard 语义侦探.*回看汇报/ })).toHaveAttribute("aria-pressed", "true");
});

it("preserves the existing automatic replay mapping without interaction props", () => {
  render(<MascotTeam phase="investigating" replayStageId="entropy_cpd" evidenceConflict={false} />);
  expect(screen.getByRole("button", { name: "CPD 曲线侦探" }).closest("figure"))
    .toHaveAttribute("data-motion", "inspect");
});
```

- [ ] **Step 2: 运行公仔测试并确认 RED**

Run:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx
```

Expected: 新测试 FAIL，因为 `interaction` 和角色按钮尚不存在；既有 18 个测试保持原有结果。

- [ ] **Step 3: 扩展公仔接口和状态映射**

在 `MascotTeam.tsx` 导入 Task 1 类型和函数，并增加：

```ts
interface MascotInteraction {
  state: InvestigationState;
  onSelect: (role: InvestigationRole) => void;
}

interface MascotTeamProps {
  phase: ChallengePhase;
  replayStageId: LabStage["stage_id"] | null;
  evidenceConflict: boolean;
  interaction?: MascotInteraction;
}

function interactionMotion(
  role: InvestigationRole,
  roleState: InvestigationRoleState,
): MascotMotion {
  if (roleState !== "presenting") return "idle";
  if (role === "cpd") return "inspect";
  if (role === "agent") return "conclude";
  return "approach";
}
```

每个角色计算：

```ts
const roleState = interaction ? roleStateFor(interaction.state, role) : null;
const selected = interaction?.state.selectedRole === role;
const motion = interaction
  ? interactionMotion(role, roleState!)
  : motionFor(role, phase, replayStageId, revealEvidenceConflict);
const canInspect = interaction ? canInspectRole(interaction.state, role) : false;
```

在 `figure` 增加 `data-role-state={roleState ?? undefined}`，把图片和图标放入真正的按钮：

```tsx
<button
  type="button"
  className="challenge-mascot-control"
  disabled={!canInspect}
  aria-pressed={interaction ? selected : undefined}
  aria-label={interaction ? `${name}，${roleStatusLabel(role, roleState!)}` : name}
  onClick={() => interaction?.onSelect(role)}
>
  <div className="challenge-mascot-image-wrap">
    <img src={image} alt="" width="512" height="512" />
    <Icon data-mascot-status-icon aria-hidden="true" size={18} strokeWidth={2.2} />
  </div>
</button>
```

为避免按钮和内部图片重复生成可访问名称，互动与非互动状态统一让按钮承担名称，图片使用空 `alt`；同步把既有测试的角色查询从 `getByRole("img")` 改为角色按钮或 `figure` 的 `data-role`。给 `figure` 增加 `data-role={role}`，既有三角色数量和动作断言必须保留。

`roleStatusLabel` 固定返回：

```ts
function roleStatusLabel(role: InvestigationRole, state: InvestigationRoleState): string {
  if (state === "ready") return "可以汇报";
  if (state === "presenting") return "正在汇报";
  if (state === "visited") return "回看汇报";
  if (role === "cpd") return "等待语义侦探";
  if (role === "agent") return "等待曲线侦探";
  return "等待调查开始";
}
```

- [ ] **Step 4: 添加按钮与互动动作样式**

增加：

```css
.challenge-mascot-control {
  width: 100%;
  padding: 0;
  border: 0;
  color: inherit;
  background: transparent;
  display: grid;
  justify-items: center;
}
.challenge-mascot-control:disabled { cursor: not-allowed; }
.challenge-mascot[data-role-state="ready"] .challenge-mascot-control,
.challenge-mascot[data-role-state="visited"] .challenge-mascot-control { cursor: pointer; }
.challenge-mascot[data-role-state="ready"] .challenge-mascot-image-wrap { opacity: 1; filter: none; box-shadow: 0 0 0 3px rgba(20, 120, 99, .18); border-radius: 50%; }
.challenge-mascot[data-role-state="locked"] .challenge-mascot-image-wrap { opacity: .38; filter: grayscale(.45) saturate(.5); }
.challenge-mascot[data-role-state="visited"] .challenge-mascot-image-wrap { opacity: .72; filter: none; }
.challenge-mascot[data-role-state="presenting"] { transform: translateX(var(--mascot-travel-x)) translateY(-6px); }
```

保留自动回放现有选择器。互动首次汇报使用 `data-motion` 动画；回看状态固定为 `idle`，不得触发 `challenge-mascot-approach`。

- [ ] **Step 5: 运行公仔和全量组件测试**

Run:

```powershell
npm.cmd test -- src/components/MascotTeam.test.tsx
npm.cmd test -- src/components/ChallengeSignalPicker.test.tsx src/components/InvestigationDesk.test.tsx
npm.cmd run build
```

Expected: 所有指定测试 PASS，构建成功，自动回放映射无回归。

- [ ] **Step 6: 提交互动公仔**

```powershell
git add frontend/src/components/MascotTeam.tsx frontend/src/components/MascotTeam.test.tsx frontend/src/styles.css
git commit -m "feat: make detective mascots interactive"
```

---

### Task 4: 两种展示模式与页面级流程集成

**Files:**
- Modify: `frontend/src/pages/ChallengePage.tsx`
- Modify: `frontend/src/ChallengePage.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: Tasks 1-3 的 `PresentationMode`、`InvestigationState`、`createInvestigationState()`、`inspectRole()`、`MascotTeam.interaction` 和 `InvestigationDesk`。
- Produces: 设置页“互动调查 / 自动演示”控制；互动完成门控答题；自动模式行为不变。

- [ ] **Step 1: 为既有自动回放测试增加显式模式选择**

在 `ChallengePage.test.tsx` 增加：

```tsx
function selectAutomaticPresentation() {
  fireEvent.click(screen.getByRole("button", { name: "自动演示" }));
}
```

所有依赖“检测结果回放”“跳过回放”或 `700ms` 计时的既有测试，在 `beginChallengeWhenReady()` 前调用该函数。包括三关完整流程、阶段计时、证据分歧回放、跳过计时器、失败后重试进入回放、知识不可用评分、证据关系不可用和无可选起点用例。假计时器测试继续在点击“进入挑战”前完成现有微任务刷新。

- [ ] **Step 2: 写互动页面失败测试**

增加以下六类页面用例：

```tsx
it("defaults to interactive investigation and keeps auto mode selectable before start", async () => {
  installFetch();
  render(<App />);
  expect(await screen.findByRole("button", { name: "互动调查" })).toHaveAttribute("aria-pressed", "true");
  expect(screen.getByRole("button", { name: "自动演示" })).toHaveAttribute("aria-pressed", "false");
});

it("reveals evidence in strict detective order before showing the answer workspace", async () => {
  installFetch();
  render(<App />);
  await beginChallengeWhenReady();

  expect(await screen.findByRole("button", { name: /Guard 语义侦探.*可以汇报/ })).toBeEnabled();
  expect(screen.queryByRole("region", { name: "本关线索" })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: /Guard 语义侦探/ }));
  expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("语义侦探汇报");
  fireEvent.click(screen.getByRole("button", { name: /CPD 曲线侦探/ }));
  expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("曲线侦探汇报");
  fireEvent.click(screen.getByRole("button", { name: /Agent 小队队长/ }));
  expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("小队队长总结");
  expect(screen.getByRole("region", { name: "本关线索" })).toBeInTheDocument();
});

it("does not expose the system decision before the player answers", async () => {
  installFetch({ run: { ...runResult, detection: { ...runResult.detection, decision: "block" } } });
  render(<App />);
  await beginChallengeWhenReady();
  fireEvent.click(await screen.findByRole("button", { name: /Guard 语义侦探/ }));
  fireEvent.click(screen.getByRole("button", { name: /CPD 曲线侦探/ }));
  fireEvent.click(screen.getByRole("button", { name: /Agent 小队队长/ }));
  expect(screen.getByRole("region", { name: "中央证据台" })).not.toHaveTextContent("拦截");
});

it("reviews an earlier report without locking the captain again", async () => {
  installFetch();
  render(<App />);
  await beginChallengeWhenReady();
  fireEvent.click(await screen.findByRole("button", { name: /Guard 语义侦探/ }));
  fireEvent.click(screen.getByRole("button", { name: /CPD 曲线侦探/ }));
  fireEvent.click(screen.getByRole("button", { name: /Guard 语义侦探/ }));
  expect(screen.getByRole("region", { name: "中央证据台" })).toHaveTextContent("语义侦探汇报");
  expect(screen.getByRole("button", { name: /Agent 小队队长.*可以汇报/ })).toBeEnabled();
});

it("lets unavailable evidence complete all three investigation steps", async () => {
  installFetch({
    run: {
      ...runResult,
      detection: {
        ...runResult.detection,
        semantic_severity: "unavailable",
        semantic_categories: [],
        suspicious_span: null,
        signals: [],
      },
    },
  });
  render(<App />);
  await beginChallengeWhenReady();
  fireEvent.click(await screen.findByRole("button", { name: /Guard 语义侦探/ }));
  expect(screen.getByText("语义证据不可用")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: /CPD 曲线侦探/ }));
  fireEvent.click(screen.getByRole("button", { name: /Agent 小队队长/ }));
  expect(screen.getByRole("region", { name: "本关线索" })).toBeInTheDocument();
});

it("resets interactive progress on retry, next round, and exit", async () => {
  const requests = installFetch({ failRunAttempts: 1 });
  render(<App />);
  await beginChallengeWhenReady();

  expect(await screen.findByText("本关调查失败")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /语义侦探.*可以汇报/ })).not.toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "重试本关" }));
  await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(2));
  expect(await screen.findByRole("button", { name: /Guard 语义侦探.*可以汇报/ })).toBeEnabled();
  expect(screen.getByRole("button", { name: /CPD 曲线侦探.*等待语义侦探/ })).toBeDisabled();
  expect(screen.getByRole("button", { name: /Agent 小队队长.*等待曲线侦探/ })).toBeDisabled();

  async function investigateAndAnswerRound() {
    fireEvent.click(screen.getByRole("button", { name: /Guard 语义侦探/ }));
    fireEvent.click(screen.getByRole("button", { name: /CPD 曲线侦探/ }));
    fireEvent.click(screen.getByRole("button", { name: /Agent 小队队长/ }));
    fireEvent.click(screen.getByRole("button", { name: "仅分布异常" }));
    fireEvent.click(screen.getByRole("button", { name: "人工复核" }));
    fireEvent.click(screen.getByRole("button", { name: "选择 Token 2" }));
    fireEvent.click(screen.getByRole("button", { name: "提交研判" }));
    await screen.findByRole("region", { name: "本关揭晓" });
  }

  await investigateAndAnswerRound();
  fireEvent.click(screen.getByRole("button", { name: "下一关" }));
  await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(3));
  expect(await screen.findByRole("button", { name: /Guard 语义侦探.*可以汇报/ })).toBeEnabled();
  expect(screen.getByRole("button", { name: /CPD 曲线侦探.*等待语义侦探/ })).toBeDisabled();
  expect(screen.queryByRole("region", { name: "中央证据台" })).not.toBeInTheDocument();

  await investigateAndAnswerRound();
  fireEvent.click(screen.getByRole("button", { name: "下一关" }));
  await waitFor(() => expect(requests.filter((item) => item.url === "/api/v1/lab/runs")).toHaveLength(4));
  expect(await screen.findByRole("button", { name: /Guard 语义侦探.*可以汇报/ })).toBeEnabled();
  await investigateAndAnswerRound();

  fireEvent.click(screen.getByRole("button", { name: "查看总分" }));
  fireEvent.click(screen.getByRole("button", { name: "退出挑战" }));
  expect(screen.getByRole("button", { name: "进入挑战" })).toBeInTheDocument();
  expect(screen.queryByRole("region", { name: "中央证据台" })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /语义侦探.*汇报/ })).not.toBeInTheDocument();
});
```

该用例通过现有 `failRunAttempts`、三关流程和真实按钮观察重置边界，不读取 React 内部状态：重试成功后 Guard 为唯一就绪角色；进入下一关后 Guard 再次为唯一就绪角色；退出后回到设置页且不存在“中央证据台”。

- [ ] **Step 3: 运行页面测试并确认 RED**

Run:

```powershell
npm.cmd test -- src/ChallengePage.test.tsx
```

Expected: 新互动测试 FAIL；显式选择自动模式后的既有回放测试继续描述原行为。

- [ ] **Step 4: 增加页面级模式与调查状态**

在 `ChallengePage.tsx` 增加：

```tsx
const [presentationMode, setPresentationMode] = useState<PresentationMode>("interactive");
const [investigation, setInvestigation] = useState<InvestigationState>(createInvestigationState);
```

增加统一重置函数并在 `executeRound` 开始、`retryRound`、`advanceRound` 的新一关和 `exitChallenge` 中调用：

```ts
function resetInvestigation() {
  setInvestigation(createInvestigationState());
}
```

检测成功后仅在自动模式初始化阶段回放：

```ts
if (presentationMode === "auto") {
  setReplayStageIndex(run.stages.length > 0 ? 0 : null);
  setReplayComplete(run.stages.length === 0);
} else {
  setReplayStageIndex(null);
  setReplayComplete(false);
}
```

`executeRound` 会读取设置页锁定的 `presentationMode`。模式在挑战期间不渲染切换控制，因此不会中途改变。

- [ ] **Step 5: 添加设置页展示模式控制**

在关卡组之后增加：

```tsx
<fieldset className="challenge-presentation-mode">
  <legend>调查方式</legend>
  <div role="group" aria-label="调查方式">
    <button
      type="button"
      aria-label="互动调查"
      aria-pressed={presentationMode === "interactive"}
      className={presentationMode === "interactive" ? "active" : ""}
      onClick={() => setPresentationMode("interactive")}
    >互动调查</button>
    <button
      type="button"
      aria-label="自动演示"
      aria-pressed={presentationMode === "auto"}
      className={presentationMode === "auto" ? "active" : ""}
      onClick={() => setPresentationMode("auto")}
    >自动演示</button>
  </div>
</fieldset>
```

该控件只存在于 `session.phase === "setup"` 分支。

- [ ] **Step 6: 分离自动回放和互动门控**

使用以下派生值替换当前笼统的 `replaying`：

```ts
const autoReplaying = presentationMode === "auto"
  && session.phase === "guessing"
  && run !== null
  && !replayComplete;
const interactiveInvestigating = presentationMode === "interactive"
  && session.phase === "guessing"
  && run !== null;
const investigationComplete = presentationMode === "auto"
  ? replayComplete
  : investigation.step === "complete";
const activeReplayStage = replayStageIndex === null ? null : run?.stages[replayStageIndex] ?? null;
const mascotReplayStageId = autoReplaying ? activeReplayStage?.stage_id ?? null : null;
```

页面集成：

```tsx
<MascotTeam
  phase={autoReplaying ? "investigating" : session.phase}
  replayStageId={mascotReplayStageId}
  evidenceConflict={revealEvidenceConflict}
  interaction={interactiveInvestigating ? {
    state: investigation,
    onSelect: (role) => setInvestigation((current) => inspectRole(current, role)),
  } : undefined}
/>

{interactiveInvestigating && investigation.selectedRole ? (
  <InvestigationDesk run={run} role={investigation.selectedRole} />
) : null}

{autoReplaying && activeReplayStage ? (
  // 保留现有检测结果回放 section，内容不变
) : null}

{session.phase === "guessing" && run && investigationComplete ? (
  // 保留现有本关线索和答题 section，内容不变
) : null}
```

自动回放 effect 的首个条件增加 `presentationMode !== "auto"` 保护；`skipReplay()` 只从自动模式按钮触发。互动模式不得渲染“跳过回放”。

- [ ] **Step 7: 添加模式控制与互动布局样式**

增加：

```css
.challenge-presentation-mode { min-width: 0; margin: 16px 0 0; padding: 0; border: 0; }
.challenge-presentation-mode legend { margin-bottom: 7px; color: var(--muted); font-size: 11px; font-weight: 700; }
.challenge-presentation-mode > div { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); padding: 3px; border: 1px solid var(--line); border-radius: 6px; background: #edf1f4; }
.challenge-presentation-mode button { min-height: 36px; border: 0; border-radius: 4px; color: var(--muted); background: transparent; cursor: pointer; }
.challenge-presentation-mode button.active { color: #123f36; background: var(--surface); box-shadow: 0 1px 4px rgba(35, 53, 70, .12); font-weight: 750; }
```

在 `max-width: 760px` 下保持两段横排；按钮文字不得溢出。

- [ ] **Step 8: 运行页面、全量测试和构建**

Run sequentially:

```powershell
npm.cmd test -- src/ChallengePage.test.tsx --no-file-parallelism
npm.cmd test -- --no-file-parallelism
npm.cmd run build
```

Expected: 页面测试、全部前端测试和生产构建 PASS；自动模式保持 `700ms`、skip、计分、重试和退出行为。

- [ ] **Step 9: 提交页面集成**

```powershell
git add frontend/src/pages/ChallengePage.tsx frontend/src/ChallengePage.test.tsx frontend/src/styles.css
git commit -m "feat: add guided detective investigation mode"
```

---

### Task 5: 响应式、减少动态效果、文档和浏览器验收

**Files:**
- Modify: `frontend/src/styles.css`
- Modify: `docs/token-detective-challenge.md`
- Verify: `frontend/src/pages/ChallengePage.tsx`
- Verify: `frontend/src/pages/AnalyzePage.tsx`
- Verify: `frontend/src/pages/LabPage.tsx`

**Interfaces:**
- Consumes: Task 4 的最终互动 DOM、`data-role-state`、中央证据台和两种模式。
- Produces: 390px 移动端布局、完整 reduced-motion 降级、更新后的使用和验收说明。

- [ ] **Step 1: 增加移动端结构断言**

在 `ChallengePage.test.tsx` 的互动流程测试中保留以下结构断言，防止响应式样式依赖卸载角色或移动证据内容：

```tsx
expect(screen.getAllByRole("figure")).toHaveLength(3);
expect(screen.getByRole("region", { name: "中央证据台" })).toBeInTheDocument();
expect(screen.getByRole("region", { name: "中央证据台" }))
  .not.toContainElement(screen.getByRole("region", { name: "本关线索" }));
```

- [ ] **Step 2: 完成移动端和 reduced-motion CSS**

在 `max-width: 760px` 中增加：

```css
.challenge-investigation-facts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.challenge-investigation-facts > div:nth-child(2n) { border-right: 0; }
.challenge-investigation-facts > div:nth-child(-n + 2) { border-bottom: 1px solid var(--line); }
.challenge-investigation-desk { padding: 14px; }
```

在现有 reduced-motion 规则中确认以下选择器存在：

```css
@media (prefers-reduced-motion: reduce) {
  .challenge-mascot,
  .challenge-mascot-image-wrap,
  .challenge-mascot-control,
  .challenge-investigation-desk {
    animation: none !important;
    transition: none !important;
    transform: none !important;
  }
}
```

不得用 `display: none` 隐藏角色、证据台或状态文字。

- [ ] **Step 3: 更新中文使用说明**

修改 `docs/token-detective-challenge.md`：

- “如何使用”增加进入挑战前选择“互动调查 / 自动演示”；
- “侦探小队与回放”拆成互动三步与 `700ms` 自动回放；
- 明确队长只总结证据关系，提交前不展示系统动作；
- 明确 `LabRunResult` 当前不包含 Prompt 或 Token 文本，受保护样本继续只展示 ID 和数值；
- 增加“互动调查是结构化证据展示，不等于已完成 SuperAgent 自主闭环”；
- 在验证记录中写入本次实际测试数、构建结果、桌面/手机和 reduced-motion 验收结果，不保留旧的 `92 passed` 数字。

- [ ] **Step 4: 执行静态和自动化验证**

Run sequentially:

```powershell
git diff --check
cd frontend
npm.cmd test -- --no-file-parallelism
npm.cmd run build
```

Expected: 无 whitespace error，全部测试 PASS，构建成功。

- [ ] **Step 5: 执行桌面浏览器验收**

在 `1440x900` 打开 `http://127.0.0.1:5174/challenge`，使用合成样本完成：

```text
1. 设置页默认“互动调查”，可切换“自动演示”。
2. 互动模式中只有语义侦探可先点击。
3. 三名角色依次汇报，中央证据台字段与 API 返回一致。
4. 回看语义侦探时队长仍保持解锁，且不重播完整 approach。
5. 队长完成前无“本关线索”，完成后答题可提交。
6. 自动模式仍出现五阶段回放，可跳过。
7. 控制台无 error；document.documentElement.scrollWidth <= window.innerWidth + 1。
```

截图只使用合成无害样本或受保护样本 ID，不包含攻击原文。

- [ ] **Step 6: 执行手机与 reduced-motion 验收**

在 `390x844` 重复互动三步，并验证：

```text
1. 三个角色、标签和模式控制完整可见。
2. 中央证据台位于角色下方，不覆盖按钮或答题区。
3. 信号曲线只在自身容器横向滚动。
4. 页面无全局横向溢出。
5. prefers-reduced-motion=reduce 下 mascot、image-wrap、control、desk 的 animation-name 为 none，transition-duration 为 0s，transform 为 none。
6. reduced-motion 下仍可用键盘完成 guard -> cpd -> agent 并解锁答题。
```

同时访问 `/analyze` 和 `/lab`，确认没有新增控制台错误或相较基线增加横向溢出。

- [ ] **Step 7: 提交响应式和文档**

```powershell
git add frontend/src/styles.css frontend/src/ChallengePage.test.tsx docs/token-detective-challenge.md
git commit -m "docs: verify interactive detective workflow"
```

- [ ] **Step 8: 最终分支验证**

Run:

```powershell
git status --short
git log -6 --oneline
git diff --check HEAD~5..HEAD
```

Expected: 工作树干净；最近提交只覆盖设计文档、调查状态、证据台、公仔交互、页面集成、响应式和挑战说明，没有后端、API、评分、样本或其他页面行为改动。
