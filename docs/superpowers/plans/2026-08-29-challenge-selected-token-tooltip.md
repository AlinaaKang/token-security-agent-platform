# 挑战旗帜 Token 序号提示 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 `/challenge` 曲线中，仅为玩家选中的旗帜提供可悬停、可键盘聚焦的真实 Token 曲线位置序号提示。

**Architecture:** 继续使用 `ChallengeSignalPicker` 已绑定的 `signal.index`，仅给选中按钮渲染一个 `role="tooltip"` 的提示元素并通过 `aria-describedby` 关联。CSS 控制提示只在选中旗帜悬停或聚焦时可见，不修改选择、计分、提交或 CPD 数据。

**Tech Stack:** React 19、TypeScript 5.8、Vitest 3、Testing Library、现有 CSS

## Global Constraints

- `signal.index` 是曲线位置序号，不是模型词表 Token ID。
- 只显示 `Token #<signal.index>`，不得显示 Token 文本或模型内部信息。
- 未选中的旗帜不渲染可视 Token 序号提示。
- 鼠标和键盘用户必须获得同等信息。
- 提示不得移动旗帜、改变起点选择、改变计分或遮挡主要曲线。
- read-only 模式继续不渲染旗帜控制。

---

### Task 1: 选中旗帜的可访问 Tooltip

**Files:**
- Modify: `frontend/src/components/ChallengeSignalPicker.tsx:1-120`
- Modify: `frontend/src/components/ChallengeSignalPicker.test.tsx:1-73`
- Modify: `frontend/src/styles.css:512-539`

**Interfaces:**
- Consumes: existing `selectedIndex: number | null` and each `LabPublicSignal.index`.
- Produces: selected button `aria-describedby` and one `.challenge-signal-token-tooltip[role="tooltip"]`.

- [ ] **Step 1: 写失败测试，固定“只为选中旗帜渲染提示”**

```tsx
it("describes only the selected flag with its real Token position", () => {
  render(<ChallengeSignalPicker signals={signals} selectedIndex={20} onSelect={() => undefined} />);
  const selected = screen.getByRole("button", { name: "选择 Token 20" });
  const unselected = screen.getByRole("button", { name: "选择 Token 10" });
  const tooltip = screen.getByRole("tooltip", { name: "Token #20" });
  expect(selected).toHaveAttribute("aria-describedby", tooltip.id);
  expect(selected).toContainElement(tooltip);
  expect(unselected).not.toHaveAttribute("aria-describedby");
  expect(screen.queryByRole("tooltip", { name: "Token #10" })).not.toBeInTheDocument();
});
```

保留现有稀疏序号、键盘移动、read-only 和密集曲线测试。

- [ ] **Step 2: 运行测试并确认提示尚不存在**

Run from `frontend`: `npm.cmd test -- --run src/components/ChallengeSignalPicker.test.tsx`

Expected: FAIL，找不到 `role="tooltip"`。

- [ ] **Step 3: 实现唯一且可访问的提示关联**

在组件中引入 `useId`：

```tsx
import { useId, useRef } from "react";

const tooltipPrefix = useId();
```

在 `signals.map` 中使用：

```tsx
const selected = signal.index === selectedIndex;
const tooltipId = `${tooltipPrefix}-token-${signal.index}`;

return (
  <button
    type="button"
    className={selected ? "selected" : ""}
    aria-label={`选择 Token ${signal.index}`}
    aria-describedby={selected ? tooltipId : undefined}
    key={signal.index}
    // 保留现有 style、ref、onClick 和 onKeyDown
  >
    <Flag size={13} aria-hidden="true" />
    {selected ? (
      <span className="challenge-signal-token-tooltip" id={tooltipId} role="tooltip">
        Token #{signal.index}
      </span>
    ) : null}
  </button>
);
```

删除所有旗帜按钮的原生 `title`，否则未选中旗帜仍会在悬停时显示序号。保留 `aria-label`，屏幕阅读器仍能识别每个选择目标。

- [ ] **Step 4: 添加不改变布局的 hover/focus 样式**

```css
.challenge-signal-targets button.selected { z-index: 2; }
.challenge-signal-token-tooltip {
  position: absolute;
  left: 50%;
  top: calc(100% + 5px);
  width: max-content;
  max-width: 110px;
  padding: 4px 6px;
  border: 1px solid var(--line-strong);
  border-radius: 3px;
  color: var(--surface);
  background: var(--ink);
  font: 800 9px/1.3 Consolas, monospace;
  white-space: nowrap;
  pointer-events: none;
  opacity: 0;
  transform: translate(-50%, -3px);
  transition: opacity 120ms ease, transform 120ms ease;
}
.challenge-signal-targets button.selected:hover .challenge-signal-token-tooltip,
.challenge-signal-targets button.selected:focus-visible .challenge-signal-token-tooltip {
  opacity: 1;
  transform: translate(-50%, 0);
}
@media (prefers-reduced-motion: reduce) {
  .challenge-signal-token-tooltip { transition: none; }
}
```

- [ ] **Step 5: 运行组件测试和完整前端测试**

Run from `frontend`:

```powershell
npm.cmd test -- --run src/components/ChallengeSignalPicker.test.tsx
npm.cmd test
npm.cmd run build
```

Expected: 目标测试、完整 Vitest 和 Vite build 全部通过。

- [ ] **Step 6: 在浏览器中验证鼠标和键盘行为**

访问 `http://127.0.0.1:5175/challenge`，进入一关并打开 CPD 曲线侦探：

1. 未选择时，任何旗帜都不常驻显示序号；
2. 选择一个旗帜后，只有该旗帜在 hover 时显示 `Token #序号`；
3. 使用 Tab 聚焦选中旗帜时显示相同提示；
4. 曲线、旗帜和提示均不改变位置；
5. 在 `390x844` 下提示不造成页面横向溢出。

- [ ] **Step 7: 提交 Tooltip 实现**

```powershell
git add frontend/src/components/ChallengeSignalPicker.tsx frontend/src/components/ChallengeSignalPicker.test.tsx frontend/src/styles.css
git commit -m "feat: label selected challenge token flag"
```
