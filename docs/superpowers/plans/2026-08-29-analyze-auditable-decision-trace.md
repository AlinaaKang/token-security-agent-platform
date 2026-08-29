# 安全分析页可审计决策轨迹 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `/analyze` 成功检测结果中增加六阶段、可回看、隐私有界的结构化决策轨迹。

**Architecture:** 用纯函数将现有 `AnalysisResult` 映射为六个公开阶段，再由独立 React 组件按固定界面间隔播放。`AnalyzePage` 只负责把成功结果接入组件；不新增请求、后端接口或模型调用，检测与处置结果保持不变。

**Tech Stack:** React 19、TypeScript 5.8、Vitest 3、Testing Library、现有 CSS、Playwright

## Global Constraints

- 只消费现有分析接口已经返回的结构化结果，不新增后端接口、模型调用、SSE、WebSocket、数据库或遥测。
- 不改变语义等级、CPD 分数、异常起点、融合原因、风险分数或处置动作。
- 不显示原始 Prompt、攻击 suffix、Token 文本、词表 Token ID、原始模型输出、私有路径、检索词或隐藏 CoT。
- 固定显示“结构化决策轨迹，不包含隐藏思维链”；界面播放间隔不表示模型耗时。
- 不改变 `/lab`、`/challenge` 和 `/super-agent` 的行为。
- `prefers-reduced-motion: reduce` 下立即显示全部阶段并取消进入动画。

---

### Task 1: 公开阶段映射与模型路径脱敏

**Files:**
- Create: `frontend/src/analyze/decisionTrace.ts`
- Create: `frontend/src/analyze/decisionTrace.test.ts`

**Interfaces:**
- Consumes: `AnalysisResult` from `frontend/src/types.ts`.
- Produces: `AnalyzeDecisionStageId`, `AnalyzeDecisionStage`, `buildAnalyzeDecisionTrace(result)` and `publicModelName(modelId)`.

- [ ] **Step 1: 写失败测试，锁定六阶段顺序与公开证据**

创建 `decisionTrace.test.ts`，用完整 `AnalysisResult` fixture 断言：

```ts
expect(buildAnalyzeDecisionTrace(result).map((stage) => stage.id)).toEqual([
  "ingest",
  "semantic",
  "token",
  "cpd",
  "fusion",
  "decision",
]);

expect(buildAnalyzeDecisionTrace(result).map((stage) => stage.label)).toEqual([
  "脱敏接收",
  "语义检测",
  "Token 观测",
  "CPD 判断",
  "证据融合",
  "处置决策",
]);
```

手工断言对应摘要包含“语义危险”“2 个数值信号”“未发现分布异常候选”“语义安全策略拦截”“拦截”，并断言 CPD 证据使用 `detector_score.toFixed(3)`、阈值 `h` 与“异常起点不适用”。

- [ ] **Step 2: 写失败隐私与缺失值测试**

增加以下断言：

```ts
expect(publicModelName("/root/autodl-tmp/models/Qwen3Guard-Gen-0.6B"))
  .toBe("Qwen3Guard-Gen-0.6B");
expect(publicModelName("C:\\models\\Qwen3Guard-Gen-0.6B"))
  .toBe("Qwen3Guard-Gen-0.6B");

const serialized = JSON.stringify(buildAnalyzeDecisionTrace(result)).toLowerCase();
for (const forbidden of [
  "prompt", "suffix", "token_text", "token_id", "guard_raw_output",
  "raw_output", "/root/", "autodl-tmp", "隐藏 cot 已展示",
]) expect(serialized).not.toContain(forbidden);
```

另用 `semantic_severity: "unavailable"`、空 `signals`、空阈值和 `suspicious_span: null` 的 fixture 断言显示“不可用”“0 个数值信号”和“不适用”，不得补写证据。

- [ ] **Step 3: 运行测试并确认模块不存在**

Run from `frontend`:

```powershell
npm.cmd test -- --run src/analyze/decisionTrace.test.ts
```

Expected: FAIL，提示无法解析 `./decisionTrace`。

- [ ] **Step 4: 实现最小映射模块**

定义：

```ts
export type AnalyzeDecisionStageId =
  | "ingest"
  | "semantic"
  | "token"
  | "cpd"
  | "fusion"
  | "decision";

export interface AnalyzeDecisionStage {
  id: AnalyzeDecisionStageId;
  label: string;
  status: "completed" | "candidate" | "unavailable";
  summary: string;
  evidence: string[];
}

export function publicModelName(modelId: string): string {
  return modelId.split(/[\\/]/).filter(Boolean).at(-1) ?? "模型不可用";
}

export function buildAnalyzeDecisionTrace(
  result: AnalysisResult,
): AnalyzeDecisionStage[];
```

实现必须直接使用 `AnalysisResult` 的公开数值和枚举进行确定性中文映射。语义阶段只显示等级、类别、公开模型名和服务端语义耗时；Token 阶段只显示 `signals.length`，不读取 `token_text` 或 `token_id`；CPD 阶段显示候选状态、分数、`h` 和起点；融合与决策阶段使用固定标签，不读取 `guard_raw_output`、`evidence[].summary` 或 `actions`。

- [ ] **Step 5: 运行 Task 1 测试并提交**

Run:

```powershell
npm.cmd test -- --run src/analyze/decisionTrace.test.ts
```

Expected: PASS。

```powershell
git add frontend/src/analyze/decisionTrace.ts frontend/src/analyze/decisionTrace.test.ts
git commit -m "feat: map public analyze decision stages"
```

### Task 2: 紧凑逐阶段回放组件

**Files:**
- Create: `frontend/src/components/AnalyzeDecisionTrace.tsx`
- Create: `frontend/src/components/AnalyzeDecisionTrace.test.tsx`

**Interfaces:**
- Consumes: `AnalyzeDecisionStage[]`, `playbackKey`, optional `intervalMs`.
- Produces: `AnalyzeDecisionTrace({ stages, playbackKey, intervalMs? })`.

- [ ] **Step 1: 写失败播放与回看测试**

使用 fake timers 和六个手工阶段渲染：

```tsx
<AnalyzeDecisionTrace
  stages={stages}
  playbackKey="request-1"
  intervalMs={20}
/>
```

断言初始只出现“脱敏接收”；`19ms` 不增加；`20ms` 后出现“语义检测”并成为选中阶段；已出现的“脱敏接收”可点击回看且 `aria-pressed="true"`；未出现阶段不渲染为可点击按钮。固定区域名为“可审计决策轨迹”，固定边界文案为“结构化决策轨迹，不包含隐藏思维链；播放间隔不代表模型耗时。”

- [ ] **Step 2: 写失败替换、卸载与减少动态效果测试**

断言：

- `playbackKey` 从 `request-1` 变为 `request-2` 时重新从第一阶段开始，旧 timer 清零；
- 组件卸载后 `vi.getTimerCount()` 为 0；
- `matchMedia(...).matches === true` 时一次显示全部六阶段且 timer 为 0；
- 空 `stages` 时显示“暂无可审计阶段”，不创建 timer。

- [ ] **Step 3: 运行测试并确认组件不存在**

Run:

```powershell
npm.cmd test -- --run src/components/AnalyzeDecisionTrace.test.tsx
```

Expected: FAIL，提示无法解析 `AnalyzeDecisionTrace`。

- [ ] **Step 4: 实现最小组件状态机**

Props：

```ts
interface AnalyzeDecisionTraceProps {
  stages: AnalyzeDecisionStage[];
  playbackKey: string;
  intervalMs?: number;
}
```

默认 `intervalMs = 240`。状态只包含当前 key、可见数量和选中 ID。首次播放自动跟随最新阶段；玩家点击已出现阶段后只改变选中详情，下一次新阶段到达时恢复跟随最新阶段。每次只保持一个 `setTimeout`，依赖变化和卸载时清理。

DOM 结构：

```tsx
<section aria-label="可审计决策轨迹">
  <header>
    <strong>可审计决策轨迹</strong>
    <span>结构化决策轨迹，不包含隐藏思维链</span>
  </header>
  <ol>{/* 已出现阶段按钮 */}</ol>
  <div aria-live="polite">{/* 当前阶段摘要与 evidence */}</div>
  <p>结构化决策轨迹，不包含隐藏思维链；播放间隔不代表模型耗时。</p>
</section>
```

阶段按钮使用 `aria-pressed`，状态图标使用 Lucide `CircleCheck`、`CircleAlert` 或 `CircleDashed` 并设置 `aria-hidden="true"`。不使用横向滚动容器或装饰性卡片嵌套。

- [ ] **Step 5: 运行 Task 2 测试并提交**

Run:

```powershell
npm.cmd test -- --run src/components/AnalyzeDecisionTrace.test.tsx
```

Expected: PASS，且控制台无 React `act(...)` 警告。

```powershell
git add frontend/src/components/AnalyzeDecisionTrace.tsx frontend/src/components/AnalyzeDecisionTrace.test.tsx
git commit -m "feat: replay analyze decision trace"
```

### Task 3: 分析页接入、响应式样式与说明

**Files:**
- Modify: `frontend/src/pages/AnalyzePage.tsx`
- Modify: `frontend/src/App.test.tsx`
- Modify: `frontend/src/styles.css`
- Create: `docs/analyze-decision-trace.md`

**Interfaces:**
- Consumes: `buildAnalyzeDecisionTrace`, `publicModelName`, `AnalyzeDecisionTrace`.
- Produces: 成功分析后可见的六阶段轨迹；现有分析 API 请求与结果不变。

- [ ] **Step 1: 写失败页面集成测试**

在 `App.test.tsx` 增加测试：检测前查询不到“可审计决策轨迹”；提交一次分析后区域出现，初始包含“脱敏接收”和固定边界文案；`fetch` 中 `/api/v1/analyze` 仍只有一次调用；原有“拦截”“语义危险”“未发现 Token 异常”保持不变。

另增加隐私断言：真实式 `semantic_model_id: "/root/autodl-tmp/models/Qwen3Guard-Gen-0.6B"` 最终页面包含 `Qwen3Guard-Gen-0.6B`，但 `document.body.textContent` 不包含 `/root/` 或 `autodl-tmp`。

- [ ] **Step 2: 运行页面测试并确认区域不存在**

Run:

```powershell
npm.cmd test -- --run src/App.test.tsx -t "renders the auditable analyze decision trace"
```

Expected: FAIL，提示找不到“可审计决策轨迹”。

- [ ] **Step 3: 最小接入分析结果**

在 `ResultPanel` 成功结果分支的 `.evidence-chain` 与 `.result-grid` 之间加入：

```tsx
<AnalyzeDecisionTrace
  stages={buildAnalyzeDecisionTrace(result)}
  playbackKey={result.request_id}
/>
```

将详细指标中的：

```tsx
<dd>{result.semantic_model_id}</dd>
```

替换为：

```tsx
<dd>{publicModelName(result.semantic_model_id)}</dd>
```

不得更改 `submitAnalysis`、`runDemo`、`api.analyze` 或 `api.analyzeDemo` 调用。

- [ ] **Step 4: 增加稳定桌面与移动端样式**

新增 `.analyze-decision-trace`、`.analyze-trace-stages`、`.analyze-trace-stage` 和 `.analyze-trace-detail`：桌面阶段列表为 `repeat(6, minmax(0, 1fr))`；每个按钮设置稳定最小高度、`min-width: 0` 和 `overflow-wrap: anywhere`；选中阶段使用现有 `--focus`/`--trusted` 色系，不引入新主色。

`@media (max-width: 760px)` 下阶段列表改为单列纵向顺序；详情证据允许换行且不得造成全局横向溢出。`prefers-reduced-motion: reduce` 下轨迹阶段和详情 `animation: none`、`transition: none`。

- [ ] **Step 5: 更新能力说明**

创建 `docs/analyze-decision-trace.md`，记录六阶段字段来源、240ms 只是界面间隔、回看不重新检测、减少动态效果与隐私禁止字段。明确它是结构化审计轨迹，不是隐藏 CoT，也不代表外部安全设备联动。

- [ ] **Step 6: 运行相关测试与构建并提交**

Run:

```powershell
npm.cmd test -- --run src/analyze/decisionTrace.test.ts src/components/AnalyzeDecisionTrace.test.tsx src/App.test.tsx
npm.cmd run build
```

Expected: 全部通过，构建退出码为 0。

```powershell
git add frontend/src/pages/AnalyzePage.tsx frontend/src/App.test.tsx frontend/src/styles.css docs/analyze-decision-trace.md
git commit -m "feat: integrate analyze decision trace"
```

### Task 4: 全量回归与真实浏览器验收

**Files:**
- Create: `tmp/analyze-decision-trace.spec.ts`（临时，不提交）
- Create: `tmp/playwright-analyze-decision-trace.config.ts`（临时，不提交）
- Verify: `frontend/src/pages/AnalyzePage.tsx`
- Verify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `http://127.0.0.1:5175/analyze` and existing AutoDL proxy.
- Produces: 验收输出与临时截图，不产生产品数据或提交文件。

- [ ] **Step 1: 运行完整前端与后端回归**

Run from `frontend`:

```powershell
npm.cmd test
npm.cmd run build
```

Run from repository root:

```powershell
$env:PYTHONPATH=(Resolve-Path 'backend').Path
E:\Codex\token-security-agent-platform\.venv\Scripts\python.exe -m pytest -q
```

Expected: 前端零失败、构建成功；后端既有非 GPU 测试零失败，显式 GPU 模型测试可保持 skip。

- [ ] **Step 2: 桌面真实检测验收**

在 `1440x900` 打开 `/analyze`，确认“检测服务已连接”，输入无害测试文本并点击“开始检测”。等待真实结果后断言轨迹从第一阶段逐项增加到六阶段；点击早期阶段后详情切换但 `/api/v1/analyze` 请求数不增加；最终处置、风险分数和现有证据仍可见；控制台错误为 0。

- [ ] **Step 3: 移动端与减少动态效果验收**

在 `390x844` 重复真实检测，确认阶段纵向排列、无全局横向溢出、文字不遮挡。设置 `reducedMotion: "reduce"` 后重新检测，断言六阶段立即全部可见，轨迹按钮和详情的 computed animation 为 `none`。

- [ ] **Step 4: 隐私与其他入口回归**

断言分析页 body 不包含 `/root/`、`autodl-tmp`、`guard_raw_output`、`token_text`、`token_id`、`完整思维链` 或 `隐藏 CoT 已展示`。访问 `/lab`、`/challenge` 与 `/super-agent`，确认既有 ready 文案和关键区域仍存在且无 console error。

- [ ] **Step 5: 清理临时结果并记录证据**

删除 Playwright 自动生成的未跟踪 `test-results/`，不得提交 `tmp/`、截图或运行时数据。将测试数量、构建结果、浏览器尺寸、请求计数、溢出测量和控制台错误数写入 `docs/analyze-decision-trace.md`；若只修改文档，提交：

```powershell
git add docs/analyze-decision-trace.md
git commit -m "docs: record analyze trace verification"
```
