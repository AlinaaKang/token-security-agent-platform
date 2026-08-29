# 可审计 ReAct 推理链视觉化 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 `/super-agent` 的事件日志升级为五阶段可审计 ReAct 因果链，支持真实事件自动回放、手动复盘和响应式展示。

**Architecture:** 使用独立纯函数把现有 `SuperAgentTraceEvent[]` 确定性映射为五个展示阶段，再由独立 React 组件负责回放进度、节点选择和结构化详情。页面只消费现有公开字段，不修改 API、后端状态机、检测结论或工具执行。

**Tech Stack:** React 19、TypeScript 5.8、Vitest 3、Testing Library、Lucide React、现有 CSS、Playwright

## Global Constraints

- 只读取 `sequence`、`phase`、`actor`、`status`、`summary`、`evidence_codes` 和 `tool_id`。
- 不展示或派生原始 Prompt、攻击 suffix、Token 文本、模型词表 Token ID、检索词、模型原始输出或隐藏 CoT。
- 不新增模型调用、自由文本推理、后端接口或运行时依赖。
- 安全任务允许零工具闭环，不得创建虚假工具动作。
- `replan` 是唯一琥珀色重点；失败或降级使用红色，成功使用墨绿，等待使用中性灰。
- 桌面端使用横向五阶段线路，`max-width: 760px` 下改为纵向线路，页面不得横向溢出。
- `prefers-reduced-motion: reduce` 下关闭回放入场和连线动画。
- `/analyze`、`/lab`、`/challenge` 的现有行为和测试必须保持不变。

---

### Task 1: 确定性事件映射

**Files:**
- Create: `frontend/src/superagent/reasoningChain.ts`
- Create: `frontend/src/superagent/reasoningChain.test.ts`

**Interfaces:**
- Consumes: `SuperAgentTraceEvent` from `frontend/src/types.ts`.
- Produces: `ReasoningStageId`, `ReasoningStage`, `REASONING_STAGE_ORDER`, `reasoningStageIdFor`, `buildReasoningStages`, `partitionEvidenceCodes`.

- [ ] **Step 1: 写失败测试，固定五阶段顺序和映射规则**

```ts
import { describe, expect, it } from "vitest";
import type { SuperAgentTraceEvent } from "../types";
import {
  buildReasoningStages,
  partitionEvidenceCodes,
  reasoningStageIdFor,
} from "./reasoningChain";

const event = (partial: Partial<SuperAgentTraceEvent>): SuperAgentTraceEvent => ({
  sequence: 1,
  phase: "observe",
  actor: "semantic_analyst",
  status: "succeeded",
  summary: "公开摘要",
  evidence_codes: [],
  tool_id: null,
  ...partial,
});

describe("reasoning chain mapping", () => {
  it("maps every public event to exactly one visual stage", () => {
    expect(reasoningStageIdFor(event({ phase: "plan", actor: "coordinator" }))).toBe("rule");
    expect(reasoningStageIdFor(event({ phase: "act", actor: "coordinator" }))).toBe("observe");
    expect(reasoningStageIdFor(event({ phase: "observe", actor: "token_analyst" }))).toBe("observe");
    expect(reasoningStageIdFor(event({ phase: "replan", actor: "coordinator" }))).toBe("replan");
    expect(reasoningStageIdFor(event({ phase: "act", actor: "response_operator", tool_id: "security_case" }))).toBe("act");
    expect(reasoningStageIdFor(event({ phase: "observe", actor: "response_operator" }))).toBe("verify");
    expect(reasoningStageIdFor(event({ phase: "complete", actor: "coordinator" }))).toBe("verify");
  });

  it("sorts events by sequence and keeps empty stages", () => {
    const stages = buildReasoningStages([
      event({ sequence: 3, phase: "replan" }),
      event({ sequence: 1, phase: "observe" }),
    ]);
    expect(stages.map((stage) => stage.id)).toEqual(["observe", "rule", "replan", "act", "verify"]);
    expect(stages.find((stage) => stage.id === "observe")?.events[0].sequence).toBe(1);
    expect(stages.find((stage) => stage.id === "act")?.state).toBe("waiting");
  });

  it("separates public policy codes from observed evidence", () => {
    expect(partitionEvidenceCodes(["semantic:unsafe", "policy:bounded-react-v1", "base_action:block"]))
      .toEqual({ observations: ["semantic:unsafe"], rules: ["policy:bounded-react-v1", "base_action:block"] });
  });
});
```

- [ ] **Step 2: 运行测试并确认因模块不存在而失败**

Run from `frontend`: `npm.cmd test -- --run src/superagent/reasoningChain.test.ts`

Expected: FAIL，提示无法解析 `./reasoningChain`。

- [ ] **Step 3: 实现最小纯映射模块**

```ts
import type { SuperAgentEventStatus, SuperAgentTraceEvent } from "../types";

export type ReasoningStageId = "observe" | "rule" | "replan" | "act" | "verify";
export type ReasoningStageState = "waiting" | SuperAgentEventStatus;

export interface ReasoningStage {
  id: ReasoningStageId;
  label: string;
  events: SuperAgentTraceEvent[];
  state: ReasoningStageState;
  latestSequence: number | null;
}

export const REASONING_STAGE_ORDER: ReadonlyArray<{ id: ReasoningStageId; label: string }> = [
  { id: "observe", label: "观察证据" },
  { id: "rule", label: "应用规则" },
  { id: "replan", label: "调整计划" },
  { id: "act", label: "执行动作" },
  { id: "verify", label: "验证结果" },
];

export function reasoningStageIdFor(event: SuperAgentTraceEvent): ReasoningStageId {
  if (event.phase === "complete") return "verify";
  if (event.phase === "replan") return "replan";
  if (event.phase === "act" && event.tool_id) return "act";
  if (event.phase === "plan") return "rule";
  if (event.phase === "observe" && event.actor === "response_operator") return "verify";
  return "observe";
}

function stateFor(events: SuperAgentTraceEvent[]): ReasoningStageState {
  if (!events.length) return "waiting";
  if (events.some((item) => item.status === "failed")) return "failed";
  return events.at(-1)?.status ?? "waiting";
}

export function buildReasoningStages(events: SuperAgentTraceEvent[]): ReasoningStage[] {
  const ordered = [...events].sort((left, right) => left.sequence - right.sequence);
  return REASONING_STAGE_ORDER.map(({ id, label }) => {
    const stageEvents = ordered.filter((item) => reasoningStageIdFor(item) === id);
    return {
      id,
      label,
      events: stageEvents,
      state: stateFor(stageEvents),
      latestSequence: stageEvents.at(-1)?.sequence ?? null,
    };
  });
}

export function partitionEvidenceCodes(codes: string[]) {
  return codes.reduce<{ observations: string[]; rules: string[] }>((result, code) => {
    const target = code.startsWith("policy:") || code.startsWith("base_action:") ? result.rules : result.observations;
    target.push(code);
    return result;
  }, { observations: [], rules: [] });
}
```

- [ ] **Step 4: 运行映射测试并确认通过**

Run from `frontend`: `npm.cmd test -- --run src/superagent/reasoningChain.test.ts`

Expected: PASS，3 个测试全部通过。

- [ ] **Step 5: 提交纯映射模块**

```powershell
git add frontend/src/superagent/reasoningChain.ts frontend/src/superagent/reasoningChain.test.ts
git commit -m "feat: map superagent events to reasoning stages"
```

### Task 2: 可审计推理链组件与交互

**Files:**
- Create: `frontend/src/components/AuditableReasoningChain.tsx`
- Create: `frontend/src/components/AuditableReasoningChain.test.tsx`
- Create: `frontend/src/superagent/labels.ts`

**Interfaces:**
- Consumes: `events: SuperAgentTraceEvent[]`; mapping helpers from Task 1.
- Produces: `AuditableReasoningChain({ events, playbackIntervalMs? })` React component and shared `superAgentActorLabels`, `superAgentPhaseLabels`, `superAgentToolLabels`, `superAgentEvidenceLabel`. `playbackIntervalMs` defaults to `220` and exists to make timer behavior deterministic in tests.

- [ ] **Step 1: 写失败测试，覆盖回放、复盘和零工具任务**

```tsx
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { SuperAgentTraceEvent } from "../types";
import { AuditableReasoningChain } from "./AuditableReasoningChain";

const events: SuperAgentTraceEvent[] = [
  { sequence: 1, phase: "plan", actor: "coordinator", status: "succeeded", summary: "建立有界计划。", evidence_codes: ["policy:bounded-react-v1"], tool_id: null },
  { sequence: 2, phase: "observe", actor: "semantic_analyst", status: "succeeded", summary: "语义证据为 unsafe。", evidence_codes: ["semantic:unsafe"], tool_id: null },
  { sequence: 3, phase: "replan", actor: "coordinator", status: "succeeded", summary: "保持基础阻断动作。", evidence_codes: ["base_action:block"], tool_id: null },
  { sequence: 4, phase: "act", actor: "response_operator", status: "succeeded", summary: "内部网关执行成功。", evidence_codes: ["tool:gateway_enforcement"], tool_id: "gateway_enforcement" },
  { sequence: 5, phase: "complete", actor: "coordinator", status: "succeeded", summary: "任务闭环。", evidence_codes: ["final_status:contained"], tool_id: null },
];

afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("AuditableReasoningChain", () => {
  it("automatically follows returned events and then supports manual review", async () => {
    vi.useFakeTimers();
    render(<AuditableReasoningChain events={events} playbackIntervalMs={10} />);
    expect(screen.getByRole("region", { name: "可审计推理链" })).toBeInTheDocument();
    await act(async () => { await vi.runAllTimersAsync(); });
    expect(screen.getByText("任务闭环。")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /观察证据/ }));
    expect(screen.getByText("语义证据为 unsafe。")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "跟随最新进度" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "跟随最新进度" }));
    expect(screen.getByText("任务闭环。")).toBeInTheDocument();
  });

  it("does not invent an action for a zero-tool safe trace", () => {
    render(<AuditableReasoningChain events={events.filter((item) => item.tool_id === null)} playbackIntervalMs={0} />);
    const chain = screen.getByRole("region", { name: "可审计推理链" });
    expect(within(chain).getByRole("button", { name: /执行动作.*等待证据/ })).toBeDisabled();
    expect(within(chain).queryByText("gateway_enforcement")).not.toBeInTheDocument();
  });

  it("shows failed evidence without rendering a successful closure", () => {
    const failed = events.map((item) => item.sequence === 4
      ? { ...item, status: "failed" as const, summary: "内部网关执行失败。" }
      : item).filter((item) => item.phase !== "complete");
    render(<AuditableReasoningChain events={failed} playbackIntervalMs={0} />);
    expect(screen.getByRole("button", { name: /执行动作.*失败/ })).toBeInTheDocument();
    expect(screen.getByText("内部网关执行失败。")).toBeInTheDocument();
    expect(screen.queryByText("任务闭环。")).not.toBeInTheDocument();
  });
});
```

- [ ] **Step 2: 运行组件测试并确认组件不存在**

Run from `frontend`: `npm.cmd test -- --run src/components/AuditableReasoningChain.test.tsx`

Expected: FAIL，提示无法解析 `AuditableReasoningChain`。

- [ ] **Step 3: 实现可审计组件的状态边界**

组件必须使用以下状态和选择规则：

```tsx
interface AuditableReasoningChainProps {
  events: SuperAgentTraceEvent[];
  playbackIntervalMs?: number;
}

export function AuditableReasoningChain({ events, playbackIntervalMs = 220 }: AuditableReasoningChainProps) {
  const orderedEvents = useMemo(
    () => [...events].sort((left, right) => left.sequence - right.sequence),
    [events],
  );
  const prefersReducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  const effectiveIntervalMs = prefersReducedMotion ? 0 : playbackIntervalMs;
  const [visibleCount, setVisibleCount] = useState(effectiveIntervalMs === 0 ? orderedEvents.length : 1);
  const [following, setFollowing] = useState(true);
  const [selectedStageId, setSelectedStageId] = useState<ReasoningStageId>(
    orderedEvents[0] ? reasoningStageIdFor(orderedEvents[0]) : "observe",
  );

  // 每次接收新任务都从第一条已返回事件开始回放；只回放现有数据，不生成中间状态。
  useEffect(() => {
    setFollowing(true);
    setVisibleCount(effectiveIntervalMs === 0 ? orderedEvents.length : Math.min(1, orderedEvents.length));
  }, [effectiveIntervalMs, orderedEvents]);

  useEffect(() => {
    if (effectiveIntervalMs === 0 || visibleCount >= orderedEvents.length) return;
    const timer = window.setTimeout(() => setVisibleCount((count) => count + 1), effectiveIntervalMs);
    return () => window.clearTimeout(timer);
  }, [effectiveIntervalMs, orderedEvents.length, visibleCount]);

  const visibleEvents = orderedEvents.slice(0, visibleCount);
  const stages = buildReasoningStages(visibleEvents);
  const latestStageId = visibleEvents.length
    ? reasoningStageIdFor(visibleEvents.at(-1)!)
    : "observe";
  const activeStageId = following ? latestStageId : selectedStageId;
```

节点使用原生 `button`，等待节点设置 `disabled`。点击已有节点时执行 `setFollowing(false)` 和 `setSelectedStageId(stage.id)`。“跟随最新进度”执行 `setFollowing(true)`。详情区必须包含固定标题“执行角色”“观察证据”“适用规则”“结论或动作”“工具与回执”；无内容时显示“暂无可公开证据”或“无工具调用”。

创建唯一共享标签模块，组件和页面都必须从该文件导入，不得保留第二套映射：

```ts
import type { LabToolId, SuperAgentActor, SuperAgentTracePhase } from "../types";

export const superAgentActorLabels: Record<SuperAgentActor, string> = {
  coordinator: "任务协调员",
  semantic_analyst: "语义分析员",
  token_analyst: "曲线分析员",
  knowledge_analyst: "知识分析员",
  response_operator: "响应执行员",
};

export const superAgentPhaseLabels: Record<SuperAgentTracePhase, string> = {
  plan: "PLAN",
  act: "ACT",
  observe: "OBSERVE",
  replan: "REPLAN",
  complete: "COMPLETE",
};

export const superAgentToolLabels: Record<LabToolId, string> = {
  gateway_enforcement: "内部网关状态",
  security_case: "脱敏安全案件",
  evidence_bundle: "证据归档包",
};

export function superAgentEvidenceLabel(code: string) {
  const prefix = "knowledge_id:";
  return code.startsWith(prefix) ? code.slice(prefix.length) : code;
}
```

- [ ] **Step 4: 运行组件测试并修正 React timer 警告**

Run from `frontend`: `npm.cmd test -- --run src/components/AuditableReasoningChain.test.tsx`

Expected: PASS，控制台没有未包裹 `act(...)` 的警告。

- [ ] **Step 5: 提交组件和测试**

```powershell
git add frontend/src/components/AuditableReasoningChain.tsx frontend/src/components/AuditableReasoningChain.test.tsx frontend/src/superagent/labels.ts
git commit -m "feat: add auditable react reasoning chain"
```

### Task 3: 接入 SuperAgent 页面并完成响应式样式

**Files:**
- Modify: `frontend/src/pages/SuperAgentPage.tsx:1-310`
- Modify: `frontend/src/SuperAgentPage.test.tsx:110-132`
- Modify: `frontend/src/styles.css:1984-2150`

**Interfaces:**
- Consumes: `AuditableReasoningChain` from Task 2 and `mission.events` from the existing mission response.
- Produces: `/super-agent` page region named `可审计推理链`; no API changes.

- [ ] **Step 1: 先更新页面测试，使旧命令轨道实现失败**

将原测试中的 `自主任务轨迹`、`PLAN`、`OBSERVE`、`REPLAN`、`COMPLETE` 断言替换为：

```tsx
const chain = screen.getByRole("region", { name: "可审计推理链" });
expect(within(chain).getByRole("button", { name: /观察证据/ })).toBeInTheDocument();
expect(within(chain).getByRole("button", { name: /应用规则/ })).toBeInTheDocument();
expect(within(chain).getByRole("button", { name: /调整计划/ })).toBeInTheDocument();
expect(within(chain).getByRole("button", { name: /执行动作/ })).toBeInTheDocument();
expect(within(chain).getByRole("button", { name: /验证结果/ })).toBeInTheDocument();
expect(within(chain).getByText("结构化审计轨迹，不包含隐藏思维链")).toBeInTheDocument();
```

保留工具回执、真实 `knowledge_id`、sessionStorage 和隐私 sentinel 断言。

- [ ] **Step 2: 运行页面测试并确认旧页面不满足新区域名称**

Run from `frontend`: `npm.cmd test -- --run src/SuperAgentPage.test.tsx`

Expected: FAIL，找不到名为“可审计推理链”的 region。

- [ ] **Step 3: 替换页面中的 `MissionTrace`**

在 `SuperAgentPage.tsx` 导入组件：

```tsx
import { AuditableReasoningChain } from "../components/AuditableReasoningChain";
```

删除旧 `MissionTrace` 函数和不再使用的 `Activity` 轨迹内容，在 workspace 中替换为：

```tsx
{mission ? <AuditableReasoningChain events={mission.events} /> : (
  <section className="superagent-empty">
    <Workflow size={30} />
    <strong>可审计推理链等待任务</strong>
    <span>启动冻结场景后展示结构化审计轨迹，不包含隐藏思维链。</span>
  </section>
)}
```

保留页头 readiness 使用的 `Activity` 图标，不得误删该 import。
同时删除页面内的 `actorLabels`、`phaseLabels`、`toolLabels` 和 `evidenceLabel` 定义，改为从 `frontend/src/superagent/labels.ts` 导入共享名称。`RoleBoard` 与 `ClosurePanel` 必须继续显示原有中文文案。

- [ ] **Step 4: 实现五阶段线路和详情区样式**

在 `styles.css` 中删除只服务于旧 `.superagent-trace ol/li` 的规则，新增以下类族：

```css
.superagent-reasoning-chain { min-width: 0; border: 1px solid var(--line); border-top: 2px solid var(--ink); background: var(--surface); }
.superagent-reasoning-overview { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); padding: 16px; }
.superagent-reasoning-node { position: relative; min-width: 0; min-height: 78px; border: 1px solid var(--line); background: var(--surface); }
.superagent-reasoning-node.is-replan { border-color: #d6ad6d; background: var(--review-soft); }
.superagent-reasoning-node.is-failed { border-color: #d7a4a6; color: var(--blocked); background: var(--blocked-soft); }
.superagent-reasoning-node[aria-pressed="true"] { outline: 2px solid var(--trusted); outline-offset: 2px; }
.superagent-reasoning-detail { border-top: 1px solid var(--line); padding: 14px 16px; }
.superagent-reasoning-detail-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px 16px; }
```

连接线使用 CSS pseudo-element，不能使用手绘 SVG。`max-width: 760px` 下将 overview 改为单列并把连接线改为纵向；详情改为单列。所有文本容器设置 `min-width: 0` 和 `overflow-wrap: anywhere`。在既有 reduced-motion media query 中关闭推理节点及连接线动画。

- [ ] **Step 5: 运行组件和页面测试**

Run from `frontend`: `npm.cmd test -- --run src/superagent/reasoningChain.test.ts src/components/AuditableReasoningChain.test.tsx src/SuperAgentPage.test.tsx`

Expected: PASS，所有推理链相关测试通过。

- [ ] **Step 6: 提交页面集成和样式**

```powershell
git add frontend/src/pages/SuperAgentPage.tsx frontend/src/SuperAgentPage.test.tsx frontend/src/styles.css
git commit -m "feat: visualize superagent reasoning flow"
```

### Task 4: 全量回归与浏览器验收

**Files:**
- Create: `tmp/task11-reasoning-chain.spec.ts`（临时验收脚本，不提交）
- Create: `tmp/playwright-task11.config.ts`（临时配置，不提交）
- Verify: `frontend/src/pages/SuperAgentPage.tsx`
- Verify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: running frontend at `http://127.0.0.1:5175` and backend API configured by the existing project.
- Produces: test output and screenshots under `tmp/`; no production API or data changes.

- [ ] **Step 1: 运行完整前端测试和构建**

Run from `frontend`:

```powershell
npm.cmd test
npm.cmd run build
```

Expected: 全部 Vitest 测试通过；TypeScript 与 Vite build 成功。

- [ ] **Step 2: 运行完整后端回归**

Run from repository root: `pytest -q`

Expected: 全部非 GPU 测试通过；已有显式 skip 可以保留，但不得新增失败。

- [ ] **Step 3: 编写浏览器验收脚本**

`tmp/playwright-task11.config.ts` 使用以下完整配置：

```ts
export default {
  testDir: ".",
  testMatch: "task11-reasoning-chain.spec.ts",
  use: { browserName: "chromium", headless: true },
};
```

脚本必须：

```ts
import { expect, test } from "playwright/test";

const baseUrl = "http://127.0.0.1:5175";

test("auditable reasoning chain is responsive and reviewable", async ({ page }) => {
  const errors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${baseUrl}/super-agent`);
  await expect(page.getByText("自主链路已就绪")).toBeVisible({ timeout: 30_000 });
  await page.getByLabel("任务场景").selectOption({ label: /GCG/ });
  await page.getByRole("button", { name: "启动自主任务" }).click();
  const chain = page.getByRole("region", { name: "可审计推理链" });
  await expect(chain.getByText("验证结果")).toBeVisible({ timeout: 120_000 });
  await chain.getByRole("button", { name: /观察证据/ }).click();
  await expect(chain.getByText("观察证据", { exact: true })).toBeVisible();
  await page.screenshot({ path: "../tmp/task11-superagent-desktop.png", fullPage: true });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.setViewportSize({ width: 390, height: 844 });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);
  expect(overflow).toBe(true);
  await page.screenshot({ path: "../tmp/task11-superagent-mobile.png", fullPage: true });
  expect(errors).toEqual([]);
});
```

- [ ] **Step 4: 运行 Playwright 并人工检查截图**

Run: `npx.cmd playwright test -c tmp/playwright-task11.config.ts`

Expected: PASS；桌面端为横向五阶段、移动端为纵向五阶段；没有文本遮挡、横向溢出、空白区域或控制台错误。

- [ ] **Step 5: 回归四个入口并检查隐私边界**

在同一 Playwright 脚本中依次访问 `/analyze`、`/lab`、`/challenge`、`/super-agent`，确认页面主标题和 readiness 状态可见。对 SuperAgent 页面文本执行以下断言：

```ts
const body = await page.locator("body").innerText();
expect(body).not.toContain("PRIVATE_SUPERAGENT_SENTINEL");
expect(body).not.toMatch(/完整思维链|隐藏 CoT 已展示|外部防火墙已联动/);
```

Expected: 四个入口均可用，隐私和能力边界断言通过。

- [ ] **Step 6: 提交最终验收所需的生产修正（若无修正则不创建空提交）**

若浏览器验收发现问题，只提交相关生产文件和对应测试：

```powershell
git add frontend/src/components/AuditableReasoningChain.tsx frontend/src/components/AuditableReasoningChain.test.tsx frontend/src/pages/SuperAgentPage.tsx frontend/src/SuperAgentPage.test.tsx frontend/src/styles.css
git commit -m "fix: harden reasoning chain presentation"
```

不得提交 `tmp/task11-*`、截图、测试日志或任何运行时数据。
