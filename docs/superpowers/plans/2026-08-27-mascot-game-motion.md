# Token 侦探公仔游戏化动效 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 让 `/challenge` 的三名侦探按已返回的检测阶段走近证据台、观察、归队并在通关时短暂庆祝，同时保持答题、计分和基础页面稳定。

**Architecture:** `ChallengePage` 继续拥有会话和回放计时，`MascotTeam` 只把 `phase + replayStageId + evidenceConflict` 映射成确定性的动作状态，CSS 负责所有视觉运动。三名公仔始终挂载且占位不变；动画不发起请求、不改变检测结果，也不表示模型实时推理。

**Tech Stack:** React 19、TypeScript 5.8、Vitest、Testing Library、CSS keyframes、Playwright 浏览器验收。

## Global Constraints

- 只修改挑战模式前端表现，不修改 `/lab`、检测算法、后端接口、AutoDL 模型服务、挑战样本、计分规则或数据存储。
- 继续使用 `frontend/public/mascots/*.webp`，不新增角色图片、SVG 角色、Canvas 引擎或动画依赖。
- 公仔始终占用固定空间，动画不得覆盖题目、按钮、Token 选择器或结果区域，不得产生全局横向滚动。
- 页面统一称为“检测结果回放”，不得描述为实时推理、思维链、并行执行或因果证明。
- `prefers-reduced-motion: reduce` 下取消入场、走位、倾斜、呼吸和庆祝，仅保留静态文字、颜色与图标状态。
- 回放展示间隔固定为 `700ms`；服务端 `latency_ms` 仍是唯一展示的检测耗时，用户可随时跳过回放。
- 不增加声音、闪烁、快速重复缩放、遥测、持久化或排行榜。

---

### Task 1: 公仔动作状态与固定证据台

**Files:**
- Modify: `frontend/src/components/MascotTeam.tsx`
- Modify: `frontend/src/components/MascotTeam.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `ChallengePhase`、`LabStage["stage_id"]`、现有 `MascotTeamProps`。
- Produces: `MascotMotion = "idle" | "approach" | "inspect" | "conclude" | "conflict" | "celebrate"`，以及每个 `figure` 上稳定的 `data-motion` 属性。

- [ ] **Step 1: 写失败测试，锁定阶段到动作的映射**

在 `MascotTeam.test.tsx` 增加以下用例。测试要求非回放阶段保持安静，回放阶段只让正确角色运动，分歧和完成阶段使用独立动作：

```tsx
it.each([
  ["semantic_guard", "Guard 语义侦探", "approach"],
  ["token_observation", "CPD 曲线侦探", "approach"],
  ["entropy_cpd", "CPD 曲线侦探", "inspect"],
  ["fixed_fusion", "Agent 小队队长", "approach"],
  ["knowledge_retrieval", "Agent 小队队长", "conclude"],
] as const)("maps %s to %s motion", (stageId, roleName, motion) => {
  render(<MascotTeam phase="investigating" replayStageId={stageId} evidenceConflict={false} />);
  expect(screen.getByRole("img", { name: roleName }).closest("figure"))
    .toHaveAttribute("data-motion", motion);
  expect(screen.getAllByRole("figure").filter((figure) => figure.dataset.motion !== "idle"))
    .toHaveLength(1);
});

it("returns every mascot to quiet idle while the player answers", () => {
  render(<MascotTeam phase="guessing" replayStageId="entropy_cpd" evidenceConflict={false} />);
  screen.getAllByRole("figure").forEach((figure) => {
    expect(figure).toHaveAttribute("data-motion", "idle");
    expect(figure).not.toHaveClass("active");
  });
});

it("uses conflict only for the captain and renders a decorative evidence desk", () => {
  const { container } = render(
    <MascotTeam phase="revealed" replayStageId="fixed_fusion" evidenceConflict />,
  );
  expect(screen.getByRole("img", { name: "Agent 小队队长" }).closest("figure"))
    .toHaveAttribute("data-motion", "conflict");
  expect(container.querySelector("[data-evidence-desk]"))
    .toHaveAttribute("aria-hidden", "true");
});

it("marks all three mascots for a one-shot completion celebration", () => {
  render(<MascotTeam phase="complete" replayStageId={null} evidenceConflict={false} />);
  expect(screen.getAllByRole("figure")).toHaveLength(3);
  screen.getAllByRole("figure").forEach((figure) => {
    expect(figure).toHaveAttribute("data-motion", "celebrate");
  });
});
```

- [ ] **Step 2: 运行组件测试，确认新断言失败**

Run:

```powershell
cd frontend
npm.cmd test -- src/components/MascotTeam.test.tsx
```

Expected: FAIL，因为当前组件没有 `data-motion` 和 `[data-evidence-desk]`，且答题阶段仍把 CPD 标记为活动角色。

- [ ] **Step 3: 实现确定性动作映射**

在 `MascotTeam.tsx` 从 `lucide-react` 的现有导入中增加 `ScanSearch`，再增加以下类型和纯函数；只有 `investigating` 阶段可按 `stage_id` 激活角色：

```tsx
type MascotMotion = "idle" | "approach" | "inspect" | "conclude" | "conflict" | "celebrate";

function motionFor(
  role: MascotRole,
  phase: ChallengePhase,
  stageId: LabStage["stage_id"] | null,
  evidenceConflict: boolean,
): MascotMotion {
  if (phase === "complete") return "celebrate";
  if (phase === "revealed" && evidenceConflict && role === "agent") return "conflict";
  if (phase !== "investigating" || activeRole(stageId) !== role) return "idle";
  if (stageId === "entropy_cpd") return "inspect";
  if (stageId === "knowledge_retrieval") return "conclude";
  return "approach";
}
```

把现有 `<section className="challenge-mascot-team" aria-label="侦探学院调查小队">` 开始标签替换为：

```tsx
<section
  className="challenge-mascot-team"
  aria-label="侦探学院调查小队"
  data-phase={phase}
  data-stage={replayStageId ?? undefined}
>
```

紧接现有 `challenge-mascot-status` 元素之后、`challenge-mascot-lineup` 之前插入：

```tsx
<div className="challenge-evidence-desk" data-evidence-desk aria-hidden="true">
  <ScanSearch size={22} strokeWidth={2} />
</div>
```

在 `MASCOTS.map` 回调第一行计算 `const motion = motionFor(role, phase, replayStageId, evidenceConflict);`，给 `figure` 增加 `data-motion={motion}`。把活动类条件从 `active === role` 改为 `phase === "investigating" && active === role`。保留现有 `conflict`、`evidence` 和 `celebration` 类，避免破坏旧选择器。

- [ ] **Step 4: 添加固定尺寸、低干扰的游戏式 CSS 动画**

在 `styles.css` 的公仔区加入以下状态结构：

```css
.challenge-evidence-desk {
  position: absolute;
  z-index: 0;
  left: 50%;
  bottom: 48px;
  display: grid;
  place-items: center;
  width: 52px;
  height: 34px;
  color: #526273;
  border: 1px solid #bdc8d2;
  border-radius: 6px;
  background: #e5eaee;
  transform: translateX(-50%);
}

.challenge-mascot-lineup {
  position: relative;
  z-index: 1;
}

.challenge-mascot-guard { --mascot-travel-x: 56%; --mascot-delay: 0ms; }
.challenge-mascot-cpd { --mascot-travel-x: 0%; --mascot-delay: 90ms; }
.challenge-mascot-agent { --mascot-travel-x: -56%; --mascot-delay: 180ms; }

.challenge-mascot-team[data-phase="setup"] .challenge-mascot {
  animation: challenge-mascot-enter 440ms ease-out both;
  animation-delay: var(--mascot-delay);
}

.challenge-mascot-team[data-phase="setup"] .challenge-mascot-image-wrap,
.challenge-mascot-team[data-phase="guessing"] .challenge-mascot-image-wrap {
  animation: challenge-mascot-idle 2800ms ease-in-out infinite;
  animation-delay: var(--mascot-delay);
}

.challenge-mascot[data-motion="approach"] {
  animation: challenge-mascot-approach 620ms cubic-bezier(.2, .75, .25, 1) both;
}

.challenge-mascot[data-motion="inspect"],
.challenge-mascot[data-motion="conclude"] {
  transform: translateX(var(--mascot-travel-x)) translateY(-6px);
}

.challenge-mascot[data-motion="inspect"] .challenge-mascot-image-wrap {
  animation: challenge-mascot-inspect 620ms ease-in-out both;
}

.challenge-mascot[data-motion="conclude"] .challenge-mascot-image-wrap {
  animation: challenge-mascot-conclude 620ms ease-out both;
}

.challenge-mascot[data-motion="conflict"] .challenge-mascot-image-wrap {
  animation: challenge-mascot-conflict 520ms ease-in-out 1;
}

.challenge-mascot[data-motion="celebrate"] .challenge-mascot-image-wrap {
  animation: challenge-mascot-celebrate 560ms ease-out 1 both;
  animation-delay: var(--mascot-delay);
}
```

同区定义完整关键帧。幅度固定为：入场最多 `12px`，待机最多 `2px/1deg`，观察最多 `4deg`，冲突左右最多 `4px`，庆祝上移最多 `10px`；庆祝和冲突只运行一次：

```css
@keyframes challenge-mascot-enter {
  from { opacity: 0; transform: translateY(12px); }
  to { opacity: .58; transform: translateY(6px); }
}

@keyframes challenge-mascot-idle {
  0%, 100% { transform: translateY(0) rotate(0); }
  50% { transform: translateY(-2px) rotate(1deg); }
}

@keyframes challenge-mascot-approach {
  from { transform: translateX(0) translateY(6px); }
  to { transform: translateX(var(--mascot-travel-x)) translateY(-6px); }
}

@keyframes challenge-mascot-inspect {
  0%, 100% { transform: rotate(0); }
  55% { transform: rotate(4deg) translateY(1px); }
}

@keyframes challenge-mascot-conclude {
  0% { transform: translateY(0) rotate(0); }
  45% { transform: translateY(-3px) rotate(-2deg); }
  100% { transform: translateY(0) rotate(0); }
}

@keyframes challenge-mascot-conflict {
  0%, 100% { transform: translateX(0); }
  30% { transform: translateX(-4px) rotate(-2deg); }
  70% { transform: translateX(4px) rotate(2deg); }
}

@keyframes challenge-mascot-celebrate {
  0%, 100% { transform: translateY(0) rotate(0); }
  45% { transform: translateY(-10px) rotate(-2deg); }
  70% { transform: translateY(-3px) rotate(2deg); }
}
```

- [ ] **Step 5: 运行组件测试和构建**

Run:

```powershell
cd frontend
npm.cmd test -- src/components/MascotTeam.test.tsx
npm.cmd run build
```

Expected: `MascotTeam.test.tsx` 全部 PASS，TypeScript 和 Vite build 成功。

- [ ] **Step 6: 提交动作状态与场景**

```powershell
git add frontend/src/components/MascotTeam.tsx frontend/src/components/MascotTeam.test.tsx frontend/src/styles.css
git commit -m "feat: animate challenge mascot team"
```

---

### Task 2: 700ms 检测结果回放与真实通关庆祝

**Files:**
- Modify: `frontend/src/pages/ChallengePage.tsx`
- Modify: `frontend/src/ChallengePage.test.tsx`
- Modify: `docs/token-detective-challenge.md`

**Interfaces:**
- Consumes: Task 1 的 `MascotTeam` 动作状态；现有 `ChallengeSessionState` 和 `LabStage[]`。
- Produces: `REPLAY_PRESENTATION_MS = 700`，完成页中真实挂载的 `MascotTeam phase="complete"`，统一的“检测结果回放”文案。

- [ ] **Step 1: 写失败测试，锁定 700ms 节奏和回放文案**

修改现有名称为 `replays returned stages at a presentation interval and preserves server latency` 的测试：

```tsx
expect(screen.getByRole("region", { name: "检测结果回放" })).toBeInTheDocument();
expect(screen.getByRole("img", { name: "Guard 语义侦探" }).closest("figure"))
  .toHaveAttribute("data-motion", "approach");

await act(async () => { await vi.advanceTimersByTimeAsync(699); });
expect(screen.getByRole("img", { name: "Guard 语义侦探" }).closest("figure"))
  .toHaveAttribute("data-motion", "approach");

await act(async () => { await vi.advanceTimersByTimeAsync(1); });
expect(screen.getByRole("img", { name: "CPD 曲线侦探" }).closest("figure"))
  .toHaveAttribute("data-motion", "approach");
```

保留“跳过回放”后的答题区断言，证明放慢展示不阻塞跳过功能。

- [ ] **Step 2: 写失败测试，证明完成页真的显示庆祝公仔**

在现有三关完整流程测试中，点击“查看总分”后加入：

```tsx
expect(screen.getByRole("region", { name: "挑战总结" })).toHaveTextContent("总分 100");
const celebrationTeam = screen.getByRole("region", { name: "侦探学院调查小队" });
expect(within(celebrationTeam).getAllByRole("figure")).toHaveLength(3);
within(celebrationTeam).getAllByRole("figure").forEach((figure) => {
  expect(figure).toHaveAttribute("data-motion", "celebrate");
});
```

- [ ] **Step 3: 运行页面测试，确认两类断言失败**

Run:

```powershell
cd frontend
npm.cmd test -- src/ChallengePage.test.tsx
```

Expected: FAIL，因为当前间隔仍为 350ms、回放区域仍叫“调查过程回放”，完成页也未渲染 `MascotTeam`。

- [ ] **Step 4: 实现固定展示间隔和统一文案**

在 `ChallengePage.tsx` 顶层常量区增加：

```tsx
const REPLAY_PRESENTATION_MS = 700;
```

把回放 effect 中 `window.setTimeout` 调用结尾的 `}, 350);` 改为 `}, REPLAY_PRESENTATION_MS);`。将回放区域的 `aria-label` 改为“检测结果回放”，将阶段计数改为 `检测结果回放 · {replayStageIndex! + 1} / {run!.stages.length}`，将揭晓区的摘要标题也改为“检测结果回放”。保留以下声明：

```tsx
<p>这是已返回检测结果的界面回放，不代表模型正在实时推理。</p>
```

- [ ] **Step 5: 在完成页挂载一次庆祝状态**

把完成分支改为一个不增加交互状态的片段：

```tsx
{session.phase === "complete" ? (
  <>
    <MascotTeam phase="complete" replayStageId={null} evidenceConflict={false} />
    <section className="challenge-summary" aria-label="挑战总结">
      <Trophy size={34} aria-hidden="true" />
      <span>挑战完成</span>
      <strong>总分 {session.totalScore}</strong>
      <p>共完成 {session.completedScores.length} 关；分数为各关百分制结果的算术平均值。</p>
      <button type="button" onClick={exitChallenge}>退出挑战</button>
    </section>
  </>
) : null}
```

不抽取新组件。`MascotTeam` 随完成分支首次挂载，因此 CSS 的非循环庆祝只执行一次。

- [ ] **Step 6: 更新中文使用说明**

在 `docs/token-detective-challenge.md` 的“侦探小队与回放”中把 `350ms` 改为 `700ms`，把“录制回放”统一为“检测结果回放”，并补充：答题阶段公仔归队进入低幅度待机，完成挑战时进行一次短暂庆祝；这些动作仍只表示已返回阶段。

- [ ] **Step 7: 运行页面测试、全量前端测试和构建**

Run:

```powershell
cd frontend
npm.cmd test -- src/ChallengePage.test.tsx
npm.cmd test
npm.cmd run build
```

Expected: 页面测试和全量前端测试全部 PASS，构建成功；跳过、答题、计分、重试和退出行为保持不变。

- [ ] **Step 8: 提交回放集成**

```powershell
git add frontend/src/pages/ChallengePage.tsx frontend/src/ChallengePage.test.tsx docs/token-detective-challenge.md
git commit -m "feat: replay mascot investigation motion"
```

---

### Task 3: 移动端、减少动态效果与浏览器验收

**Files:**
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/components/MascotTeam.test.tsx`
- Verify: `frontend/src/pages/ChallengePage.tsx`
- Verify: `frontend/src/pages/LabPage.tsx`
- Verify: `frontend/src/pages/AnalyzePage.tsx`

**Interfaces:**
- Consumes: Task 1 的 `data-phase`、`data-motion` 和 CSS 自定义属性。
- Produces: 390px 移动端收敛走位和完整的减少动态效果降级规则。

- [ ] **Step 1: 补充结构测试，确保动画不靠卸载角色实现**

在 `MascotTeam.test.tsx` 增加重渲染测试：

```tsx
it("keeps the same three figures mounted across replay and guessing states", () => {
  const { rerender } = render(
    <MascotTeam phase="investigating" replayStageId="semantic_guard" evidenceConflict={false} />,
  );
  const figures = screen.getAllByRole("figure");

  rerender(<MascotTeam phase="guessing" replayStageId={null} evidenceConflict={false} />);

  expect(screen.getAllByRole("figure")).toHaveLength(3);
  expect(screen.getAllByRole("figure")).toEqual(figures);
});
```

- [ ] **Step 2: 运行组件测试并确认现有实现满足挂载约束**

Run:

```powershell
cd frontend
npm.cmd test -- src/components/MascotTeam.test.tsx
```

Expected: PASS。此回归测试记录结构约束，后续只通过 CSS 改动响应式与降级表现。

- [ ] **Step 3: 收敛移动端走位并完善减少动态效果**

在现有 `@media (max-width: 760px)` 中加入：

```css
.challenge-mascot-guard { --mascot-travel-x: 34%; }
.challenge-mascot-agent { --mascot-travel-x: -34%; }
.challenge-evidence-desk { bottom: 44px; width: 46px; }
```

把现有减少动态效果规则扩展为：

```css
@media (prefers-reduced-motion: reduce) {
  .challenge-mascot,
  .challenge-mascot-image-wrap {
    animation: none !important;
    transition: none !important;
    transform: none !important;
  }

  .challenge-stage-replay,
  .challenge-stage-replay * {
    animation: none !important;
    transition: none !important;
  }
}
```

- [ ] **Step 4: 运行静态验证**

Run:

```powershell
git diff --check
cd frontend
npm.cmd test
npm.cmd run build
```

Expected: 无空白错误，全部前端测试 PASS，生产构建成功。

- [ ] **Step 5: 在桌面和移动端执行浏览器验收**

保持现有 Vite `http://127.0.0.1:5174` 和 AutoDL 隧道可用，使用 Playwright 分别检查 `1440x900` 与 `390x844`：

```text
1. 设置页：三名公仔和证据台可见，入场后进入低幅度待机。
2. 回放页：Guard、CPD、Agent 按返回阶段依次获得 approach/inspect/conclude，跳过按钮始终可操作。
3. 答题页：三名公仔均为 idle，题目、按钮和 Token 曲线不被覆盖。
4. 完成页：三名公仔均为 celebrate，动画只运行一次，总分和退出按钮可操作。
5. 两个视口：document.documentElement.scrollWidth <= window.innerWidth + 1，无控制台错误。
6. 移动端：三名公仔和标签完整可见，局部曲线滚动不扩散到页面。
7. reducedMotion=reduce：公仔 computed animation-name 为 none、transition-duration 为 0s、transform 为 none。
8. /analyze 与 /lab：页面无全局横向溢出和控制台错误。
```

分别保存设置、回放、答题和完成状态截图；截图只使用合成无害场景或受保护样本 ID，不包含攻击 Prompt、suffix 或 Token 文本。

- [ ] **Step 6: 提交响应式和降级规则**

```powershell
git add frontend/src/styles.css frontend/src/components/MascotTeam.test.tsx
git commit -m "fix: constrain challenge mascot motion"
```

- [ ] **Step 7: 最终复核提交范围**

Run:

```powershell
git status --short
git log -4 --oneline
```

Expected: 工作树干净；最近提交依次包含设计文档、动作状态、回放集成和响应式降级，且没有后端、模型、数据集或 `/lab` 行为改动。
