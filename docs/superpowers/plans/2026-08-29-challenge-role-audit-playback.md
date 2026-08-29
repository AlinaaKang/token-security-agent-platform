# 挑战任务角色式逐行审计回放 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让挑战页三名公仔固定站位、依次原地提示点击，并在首次汇报时逐行回放真实脱敏证据，完成后仍可反复回看。

**Architecture:** 保留现有 `LabRunResult` 一次性返回边界，用纯函数生成三类角色的公开审计行；调查 reducer 将“首次汇报中”和“汇报完成”分开，React 组件只负责定时展示已返回行。公仔状态消费同一 reducer，下一位原地跳动、已完成角色可回看，不新增后端接口或模型调用。

**Tech Stack:** React 19、TypeScript 5.8、Vitest 3、Testing Library、Lucide React、现有 CSS、Playwright

## Global Constraints

- 继续消费现有已完成的 `LabRunResult`，不新增 SSE、WebSocket、模型调用、后端接口、数据库或遥测。
- 逐行内容只能由现有结构化字段确定性生成，不调用 LLM 编写解释。
- 不展示或派生原始 Prompt、攻击 suffix、Token 文本、模型词表 Token ID、检索词、原始模型输出、Guard 原始输出或隐藏 CoT。
- 页面必须使用“可审计决策过程”或“检测结果回放”，并固定声明这不是实时模型推理或隐藏思维链。
- 不改变检测结果、融合动作、CPD 起点、评分规则、关卡定义或 `/analyze`、`/lab`、`/super-agent` 行为。
- 保留互动调查和自动演示；自动演示继续使用已返回的 `LabStage[]` 和服务端 `latency_ms`。
- 三名公仔不得横向移动；只有下一位角色原地短跳。已完成角色可以回看，回看不推进或倒退流程。
- `prefers-reduced-motion: reduce` 下取消跳跃、庆祝和过渡，并立即显示完整报告。

---

### Task 1: 调查状态机与角色审计行

**Files:**
- Modify: `frontend/src/challenge/investigation.ts`
- Modify: `frontend/src/challenge/investigation.test.ts`
- Create: `frontend/src/challenge/roleAuditLines.ts`
- Create: `frontend/src/challenge/roleAuditLines.test.ts`

**Interfaces:**
- Consumes: `LabRunResult` from `frontend/src/types.ts` and `InvestigationRole`.
- Produces: `RoleAuditLine`, `buildRoleAuditLines(run, role)`, `completeRolePresentation(state, role)` and updated `InvestigationState.presentingRole`.

- [ ] **Step 1: 写失败状态机测试，固定“完成后才推进”和回看不改进度**

在 `investigation.test.ts` 增加：

```ts
it("unlocks the next role only after the first report completes", () => {
  const started = inspectRole(createInvestigationState(), "guard");
  expect(started.step).toBe("semantic");
  expect(started.presentingRole).toBe("guard");
  expect(canInspectRole(started, "cpd")).toBe(false);

  const completed = completeRolePresentation(started, "guard");
  expect(completed.step).toBe("cpd");
  expect(completed.presentingRole).toBeNull();
  expect(completed.visitedRoles.has("guard")).toBe(true);
  expect(canInspectRole(completed, "cpd")).toBe(true);
});

it("reviews a completed role without changing the next role", () => {
  const guardDone = completeRolePresentation(
    inspectRole(createInvestigationState(), "guard"),
    "guard",
  );
  const review = inspectRole(guardDone, "guard");
  expect(review.step).toBe("cpd");
  expect(review.presentingRole).toBeNull();
  expect(review.selectionKind).toBe("review");
  expect(canInspectRole(review, "cpd")).toBe(true);
});
```

- [ ] **Step 2: 运行状态机测试并确认按预期失败**

Run from `frontend`: `npm.cmd test -- --run src/challenge/investigation.test.ts`

Expected: FAIL，提示 `completeRolePresentation` 未导出或 `presentingRole` 不存在。

- [ ] **Step 3: 最小修改调查状态机**

`InvestigationState` 增加：

```ts
presentingRole: InvestigationRole | null;
```

`createInvestigationState()` 将其初始化为 `null`。首次 `inspectRole` 只设置 `selectedRole`、`selectionKind: "first_visit"` 和 `presentingRole`，不更新 `step` 或 `visitedRoles`；回看只设置 `selectedRole` 和 `selectionKind: "review"`。

新增：

```ts
export function completeRolePresentation(
  state: InvestigationState,
  role: InvestigationRole,
): InvestigationState {
  if (state.presentingRole !== role || state.step === "complete" || STEP_ROLE[state.step] !== role) return state;
  const visitedRoles = new Set(state.visitedRoles);
  visitedRoles.add(role);
  return {
    ...state,
    step: NEXT_STEP[role],
    presentingRole: null,
    visitedRoles,
  };
}
```

`canInspectRole` 在 `presentingRole !== null` 时对全部角色返回 `false`，避免切换角色后卸载当前回放并使流程卡住；汇报完成后恢复已完成角色回看和下一位点击。`roleStateFor` 对 `presentingRole === role` 返回 `presenting`，之后按 `visited`、`ready`、`locked` 判断。

- [ ] **Step 4: 运行状态机测试并确认通过**

Run: `npm.cmd test -- --run src/challenge/investigation.test.ts`

Expected: PASS，现有顺序、禁用和回看测试一起通过。

- [ ] **Step 5: 写失败审计行测试，使用手工期望值锁定公开字段**

在 `roleAuditLines.test.ts` 用完整 `LabRunResult` fixture 覆盖：

```ts
expect(buildRoleAuditLines(runResult, "guard").map((line) => line.value)).toEqual([
  "语义检测已完成",
  "语义安全",
  "未命中风险类别",
  "guard-model / 1.0 · 4.0 ms",
]);

expect(buildRoleAuditLines(runResult, "cpd").map((line) => line.value)).toEqual([
  "Token 观测已完成",
  "发现分布异常候选",
  "2.40 / 1.80",
  "Token 2",
  "分布异常只代表候选信号，不单独证明恶意",
]);

expect(buildRoleAuditLines(runResult, "agent").map((line) => line.value)).toEqual([
  "已收到语义与 CPD 两路公开证据",
  "两路证据存在分歧",
  "提交研判前不展示系统动作",
  "调查证据已汇总，可以进入玩家研判",
]);
```

另加不可用语义、无类别、无起点、阈值缺失和耗时缺失用例；遍历序列化结果，断言不包含 `prompt`、`suffix`、`token_text`、`token_id`、`raw_output`、`guard_raw_output` 或“隐藏 CoT 已展示”。

- [ ] **Step 6: 运行审计行测试并确认模块不存在**

Run: `npm.cmd test -- --run src/challenge/roleAuditLines.test.ts`

Expected: FAIL，提示无法解析 `./roleAuditLines`。

- [ ] **Step 7: 实现最小纯映射模块**

定义：

```ts
export interface RoleAuditLine {
  id: string;
  label: string;
  value: string;
}

export function buildRoleAuditLines(
  run: LabRunResult,
  role: InvestigationRole,
): RoleAuditLine[];
```

使用 `expectedEvidenceRelation(run)` 生成队长关系，复用挑战页既有中文标签语义。所有小数使用 `toFixed(2)`，耗时使用 `toFixed(1)`；缺失值输出“不可用”或“不适用”，不得拼接异常正文。

- [ ] **Step 8: 运行 Task 1 两组测试并提交**

Run: `npm.cmd test -- --run src/challenge/investigation.test.ts src/challenge/roleAuditLines.test.ts`

Expected: PASS。

```powershell
git add frontend/src/challenge/investigation.ts frontend/src/challenge/investigation.test.ts frontend/src/challenge/roleAuditLines.ts frontend/src/challenge/roleAuditLines.test.ts
git commit -m "feat: model challenge role audit playback"
```

### Task 2: 逐行角色报告组件

**Files:**
- Create: `frontend/src/components/RoleAuditPlayback.tsx`
- Create: `frontend/src/components/RoleAuditPlayback.test.tsx`
- Modify: `frontend/src/components/InvestigationDesk.tsx`
- Modify: `frontend/src/components/InvestigationDesk.test.tsx`

**Interfaces:**
- Consumes: `RoleAuditLine[]`, `role`, `playbackKey`, `animate`, `onComplete`.
- Produces: `RoleAuditPlayback` and upgraded `InvestigationDesk({ run, role, mode, playbackKey, onPresentationComplete })`.

- [ ] **Step 1: 写失败组件测试，固定逐行、跳过、回看和计时器清理**

目标 API：

```tsx
<RoleAuditPlayback
  lines={lines}
  playbackKey="round-1:guard"
  animate
  intervalMs={20}
  onComplete={onComplete}
/>
```

测试必须使用 fake timers 并断言：初始只显示第一行；`19ms` 不增加；`20ms` 增加一行；全部完成时 `onComplete` 恰好一次；点击“立即显示完整汇报”同步显示全部行并清空 timer；`playbackKey` 替换、组件卸载和 `animate={false}` 都不留下 timer；回看模式初始显示全部行且不调用 `onComplete`。

- [ ] **Step 2: 运行组件测试并确认组件不存在**

Run: `npm.cmd test -- --run src/components/RoleAuditPlayback.test.tsx`

Expected: FAIL，提示无法解析 `RoleAuditPlayback`。

- [ ] **Step 3: 实现逐行组件的最小状态边界**

Props：

```ts
interface RoleAuditPlaybackProps {
  lines: RoleAuditLine[];
  playbackKey: string;
  animate: boolean;
  intervalMs?: number;
  onComplete?: () => void;
}
```

默认间隔为 `420`。`prefers-reduced-motion: reduce` 时有效间隔为 `0`。新 `playbackKey` 重置可见行；仅在首次动画完整结束或跳过时调用一次 `onComplete`。渲染命名区域“可审计决策过程”、有序列表、`aria-live="polite"` 和固定边界文案：

```text
这是已返回检测结果的逐行回放，不代表模型正在实时推理，也不包含隐藏思维链。
```

- [ ] **Step 4: 运行逐行组件测试并确认通过且无 act 警告**

Run: `npm.cmd test -- --run src/components/RoleAuditPlayback.test.tsx`

Expected: PASS，控制台无未包裹 `act(...)` 警告。

- [ ] **Step 5: 写失败 InvestigationDesk 集成测试**

测试首次语义汇报只逐行展示，完成回调后才调用 `onPresentationComplete("guard")`；CPD 完成前不显示曲线，完成后显示只读曲线；`mode="review"` 立即显示完整报告和曲线且不调用完成回调。

- [ ] **Step 6: 最小接入 InvestigationDesk**

Props：

```ts
interface InvestigationDeskProps {
  run: LabRunResult;
  role: InvestigationRole;
  mode: "first_visit" | "review";
  playbackKey: string;
  onPresentationComplete: (role: InvestigationRole) => void;
}
```

用 `buildRoleAuditLines` 和 `RoleAuditPlayback` 替换会提前泄露全部字段的静态事实网格。CPD 只读曲线在当前报告完整可见后渲染；队长仍不得在玩家提交前展示系统动作。

- [ ] **Step 7: 运行 Task 2 测试并提交**

Run: `npm.cmd test -- --run src/components/RoleAuditPlayback.test.tsx src/components/InvestigationDesk.test.tsx`

Expected: PASS。

```powershell
git add frontend/src/components/RoleAuditPlayback.tsx frontend/src/components/RoleAuditPlayback.test.tsx frontend/src/components/InvestigationDesk.tsx frontend/src/components/InvestigationDesk.test.tsx
git commit -m "feat: replay role evidence line by line"
```

### Task 3: 公仔原地提示与可回看状态

**Files:**
- Modify: `frontend/src/components/MascotTeam.tsx`
- Modify: `frontend/src/components/MascotTeam.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: updated `InvestigationState` and existing automatic `replayStageId`.
- Produces: stationary mascot motions `idle | hop | conflict | celebrate`, next-role guidance and selected review styling.

- [ ] **Step 1: 更新测试并确认旧横向动作失败**

测试必须断言：

- 初始语义角色 `data-motion="hop"`，其余为 `idle`。
- 语义首次汇报中三名角色都不提前进入 `hop` 且按钮全部禁用；完成回调后 Guard 恢复可回看、CPD 变为可点击的 `hop`。
- 已完成 Guard 保持 enabled，点击回看时 `aria-pressed="true"`；CPD 仍是下一位。
- 自动模式的 semantic/token/fusion 阶段只映射为当前角色 `hop`，不存在 `approach`、`inspect`、`conclude`。
- 只有 ready 角色显示包含“下一步：点击”的引导，且引导使用可访问文字。

Run: `npm.cmd test -- --run src/components/MascotTeam.test.tsx`

Expected: FAIL，旧实现仍返回横向动作名并缺少引导。

- [ ] **Step 2: 实现固定站位动作与引导**

将 `MascotMotion` 收敛为：

```ts
type MascotMotion = "idle" | "hop" | "conflict" | "celebrate";
```

自动模式 `activeRole(replayStageId)` 返回的角色使用 `hop`；互动模式仅 `roleState === "ready"` 使用 `hop`。在 ready 角色按钮上方渲染 `ArrowDown` 和 `下一步：点击${shortName}`。presenting 角色显示“正在逐行汇报”，visited selected 显示“正在回看”，visited unselected 显示“已汇报，可回看”。

- [ ] **Step 3: 删除横向位移并增加稳定原地跳跃样式**

删除 `--mascot-travel-x`、`.challenge-mascot.active` 与 presenting 的 `translateX`、`challenge-mascot-approach`。新增 `.challenge-mascot[data-motion="hop"] .challenge-mascot-image-wrap` 的原地双跳 keyframes，仅改变 `translateY`，角色外层网格尺寸不变。新增下一步提示、已完成勾选和 selected 描边样式；不创建浮动卡片或遮挡公仔。

`prefers-reduced-motion` 规则覆盖 hop、提示脉冲、庆祝与相关 transition，保留静态提示和 focus-visible。

- [ ] **Step 4: 运行公仔测试并提交**

Run: `npm.cmd test -- --run src/components/MascotTeam.test.tsx`

Expected: PASS。

```powershell
git add frontend/src/components/MascotTeam.tsx frontend/src/components/MascotTeam.test.tsx frontend/src/styles.css
git commit -m "feat: guide stationary challenge mascots"
```

### Task 4: 挑战页流程集成与回归

**Files:**
- Modify: `frontend/src/pages/ChallengePage.tsx`
- Modify: `frontend/src/ChallengePage.test.tsx`
- Modify: `frontend/src/styles.css`
- Modify: `docs/token-detective-challenge.md`

**Interfaces:**
- Consumes: `completeRolePresentation`, upgraded `InvestigationDesk`, updated `MascotTeam`.
- Produces: end-to-end interactive role playback without API changes.

- [ ] **Step 1: 写失败页面测试，固定完整互动流程**

用 fake timers 驱动以下行为：

1. 请求返回后 Guard 提示点击，CPD 与队长 disabled。
2. 点击 Guard 后出现“可审计决策过程”，CPD 仍 disabled。
3. 推进全部 Guard 行后 CPD enabled 且原地提示；Guard 可点击回看。
4. 点击 Guard 回看立即显示完整 Guard 报告，CPD 提示仍存在。
5. 依次完成 CPD 与队长后才出现“本关线索”和答题区。
6. 点击“立即显示完整汇报”可以逐角色快速完成且所有 timer 清零。
7. retry、next round、exit 与 result replacement 清除旧回放。
8. 可见页面不包含隐私禁止字段、`完整思维链`、`隐藏 CoT 已展示` 或实时推理宣称。

Run: `npm.cmd test -- --run src/ChallengePage.test.tsx`

Expected: FAIL，旧页面在首次点击时立即推进且没有逐行区域。

- [ ] **Step 2: 接入完成回调并保持答题解锁边界**

`ChallengePage` 传给 `InvestigationDesk`：

```tsx
<InvestigationDesk
  run={run}
  role={investigation.selectedRole}
  mode={investigation.selectionKind === "review" ? "review" : "first_visit"}
  playbackKey={`${session.roundIndex}:${session.rounds[session.roundIndex]?.scenarioId}:${investigation.selectedRole}`}
  onPresentationComplete={(role) => setInvestigation((current) => completeRolePresentation(current, role))}
/>
```

`investigationComplete` 继续只由 `investigation.step === "complete"` 决定。重试、下一关、退出复用 `resetInvestigation()`，组件 key 与 reducer 一起防止旧 timer 写入新轮次。

- [ ] **Step 3: 完成逐行区域和移动端样式**

为审计行、行状态、跳过按钮、边界说明设置稳定的 grid/list 尺寸、`min-width: 0` 和 `overflow-wrap: anywhere`。桌面与移动均不得产生横向溢出；紧凑面板标题不得使用 hero 字号。

- [ ] **Step 4: 更新挑战文档的真实能力表述**

将互动调查说明更新为首次点击逐行回放、完成后解锁下一位、已完成角色可回看；明确所有行来自已返回 `LabRunResult`，`420ms` 为展示间隔，不是模型耗时或隐藏 CoT。自动演示 `700ms` 边界保持不变。

- [ ] **Step 5: 运行相关与全量前端测试、构建并提交**

Run from `frontend`:

```powershell
npm.cmd test -- --run src/challenge/investigation.test.ts src/challenge/roleAuditLines.test.ts src/components/RoleAuditPlayback.test.tsx src/components/InvestigationDesk.test.tsx src/components/MascotTeam.test.tsx src/ChallengePage.test.tsx
npm.cmd test
npm.cmd run build
```

Expected: 全部通过，控制台无 React act 警告。

```powershell
git add frontend/src/pages/ChallengePage.tsx frontend/src/ChallengePage.test.tsx frontend/src/styles.css docs/token-detective-challenge.md
git commit -m "feat: integrate challenge audit walkthrough"
```

### Task 5: 真实浏览器验收

**Files:**
- Create: `tmp/challenge-role-audit.spec.ts`（临时，不提交）
- Create: `tmp/playwright-challenge-role-audit.config.ts`（临时，不提交）
- Verify: `frontend/src/pages/ChallengePage.tsx`
- Verify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: frontend `http://127.0.0.1:5175` and backend proxy `http://127.0.0.1:18000`.
- Produces: temporary screenshots and acceptance output only.

- [ ] **Step 1: 确认真实服务 ready**

检查 `/health`、`/api/v1/lab/scenarios` 和 `/challenge` 均为 HTTP 200；模型、lab 与 demo ready。若服务不可用，记录环境 blocker，不用 mock 替代真实浏览器验收。

- [ ] **Step 2: 编写并运行桌面互动验收**

在三关速战第一关执行：进入互动调查；记录三名公仔中心坐标；点击 Guard 并观察逐行增加；完成后确认 CPD 提示；回看 Guard；完成 CPD 与队长；确认答题区解锁。每个阶段重新测量三名公仔中心横坐标，绝对偏差不得超过 `1px`。

- [ ] **Step 3: 运行移动与减少动态效果验收**

在 `390x844` 重复三角色流程，确认页面无横向溢出、提示不遮挡公仔或相邻文字。设置 `reducedMotion: "reduce"` 后确认 mascot、image wrapper、提示和报告行 computed animation 均为 `none`，报告直接完整显示且仍可键盘回看。

- [ ] **Step 4: 回归自动演示、隐私和其他入口**

确认自动演示仍按返回阶段工作且可跳过；访问 `/analyze`、`/lab`、`/challenge`、`/super-agent`，四入口 ready，无 console error。页面 body 不得包含受保护原文、隐私禁止字段或隐藏 CoT 能力宣称。

- [ ] **Step 5: 运行完整后端回归并整理验收报告**

Run from repository root:

```powershell
$env:PYTHONPATH=(Resolve-Path 'backend').Path
E:\Codex\token-security-agent-platform\.venv\Scripts\python.exe -m pytest -q
```

Expected: 既有非 GPU 后端测试全部通过；显式 GPU 模型 skip 可以保留，不得新增失败。

将命令、结果、截图尺寸、控制台错误数、坐标测量和隐私断言写入任务报告。不得提交 `tmp/`、截图、Playwright 结果或运行时数据；若验收无需生产修正，不创建空提交。
