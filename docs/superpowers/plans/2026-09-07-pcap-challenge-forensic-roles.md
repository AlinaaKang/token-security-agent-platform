# PCAP Challenge Forensic Roles Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a three-role icon-based forensic workflow to the PCAP detective challenge that is visually and semantically distinct from the Token mascot challenge.

**Architecture:** Keep the existing sanitized, deterministic PCAP challenge cases and scoring unchanged. Add a presentational role rail whose three roles correspond one-to-one with the three answer stages; use Lucide icons and CSS state styling without importing mascot assets or animation behavior.

**Tech Stack:** React, TypeScript, Lucide React, CSS, Vitest, Testing Library.

## Global Constraints

- Use exactly three roles: 包解析员, 流量关联员, 攻击研判员.
- Use exactly the `ScanSearch`, `Network`, and `ShieldAlert` Lucide icons in that order.
- Keep the existing Packet evidence, three sanitized cases, scoring, and explanations unchanged.
- Do not import character images, mascot role names, speech balloons, or hopping animations.
- Use the existing blue PCAP evidence palette.
- Render horizontally on desktop and vertically on mobile without text clipping or overlap.
- Preserve unrelated dirty-worktree changes.

---

### Task 1: Three-role Forensic Rail

**Files:**
- Create: `frontend/src/components/PcapForensicRoles.tsx`
- Create: `frontend/src/components/PcapForensicRoles.test.tsx`
- Modify: `frontend/src/pages/PcapChallengePage.tsx`
- Modify: `frontend/src/PcapChallengePage.test.tsx`

**Interfaces:**
- Produces: `PcapForensicRoles({ activeStage }: { activeStage: 1 | 2 | 3 })`.
- Consumes no challenge answers and performs no scoring.

- [ ] **Step 1: Write failing role semantics tests**

```tsx
render(<PcapForensicRoles activeStage={1} />);
const rail = screen.getByRole("region", { name: "PCAP 三角色取证流程" });
expect(within(rail).getByText("包解析员")).toBeVisible();
expect(within(rail).getByText("流量关联员")).toBeVisible();
expect(within(rail).getByText("攻击研判员")).toBeVisible();
expect(rail.querySelectorAll("svg")).toHaveLength(3);
expect(rail.querySelector("img")).not.toBeInTheDocument();
expect(rail).not.toHaveTextContent("语义侦探|曲线侦探|小队队长");
```

- [ ] **Step 2: Run tests and verify failure**

Run: `npm.cmd test -- components/PcapForensicRoles.test.tsx PcapChallengePage.test.tsx`

Expected: FAIL because the role component does not exist.

- [ ] **Step 3: Implement the fixed role model and accessible markup**

```tsx
const roles = [
  { stage: 1, title: "包解析员", detail: "查看协议、方向、时间与脱敏包内容", Icon: ScanSearch },
  { stage: 2, title: "流量关联员", detail: "比较正常基线并定位首次异常", Icon: Network },
  { stage: 3, title: "攻击研判员", detail: "判断攻击类型、目的与影响", Icon: ShieldAlert },
] as const;
```

Render an ordered list inside `aria-label="PCAP 三角色取证流程"`. Mark the active item with `aria-current="step"`; icons are decorative because the adjacent text supplies the same meaning.

- [ ] **Step 4: Insert the rail above the evidence table**

Show the rail after challenge start and before “先看证据，再作判断”. Derive `activeStage` from the first incomplete answer: no Packet selection means 1, Packet selected without attack means 2, otherwise 3. Submission leaves stage 3 active so the result does not cause layout movement.

- [ ] **Step 5: Run component tests green and commit**

Run: `npm.cmd test -- components/PcapForensicRoles.test.tsx PcapChallengePage.test.tsx`

```bash
git add frontend/src/components/PcapForensicRoles.tsx frontend/src/components/PcapForensicRoles.test.tsx frontend/src/pages/PcapChallengePage.tsx frontend/src/PcapChallengePage.test.tsx
git commit -m "feat: add pcap forensic challenge roles"
```

### Task 2: Responsive Blue Forensic Styling

**Files:**
- Modify: `frontend/src/styles.css`
- Modify: `frontend/src/components/PcapForensicRoles.test.tsx`

**Interfaces:**
- Consumes: `.pcap-forensic-roles`, `.pcap-forensic-role`, and `[aria-current="step"]` from Task 1.
- Produces a stable desktop three-column rail and mobile one-column sequence.

- [ ] **Step 1: Add failing structural style assertions**

```ts
expect(styles).toMatch(/\.pcap-forensic-roles[^}]*grid-template-columns:\s*repeat\(3,/);
expect(styles).toMatch(/@media \(max-width: 760px\)[\s\S]*\.pcap-forensic-roles[^}]*grid-template-columns:\s*1fr/);
expect(styles).not.toMatch(/\.pcap-forensic-role[^}]*animation:/);
```

- [ ] **Step 2: Run tests and verify failure**

Run: `npm.cmd test -- components/PcapForensicRoles.test.tsx`

Expected: FAIL because the forensic rail has no styles.

- [ ] **Step 3: Add stable blue rail styling**

Use three equal `minmax(0, 1fr)` tracks, 42px fixed icon wells, an 8px maximum border radius, visible focus treatment, and an active-state blue border/background. Use a thin connector line behind the icon wells on desktop and suppress it on mobile. Keep letter spacing at zero and use fixed font sizes rather than viewport scaling.

- [ ] **Step 4: Add the mobile stack**

At `max-width: 760px`, switch to one column, keep each role at a stable minimum height, and prevent the description from overlapping the icon or next item. Do not add horizontal scrolling.

- [ ] **Step 5: Run tests and production build green, then commit**

Run: `npm.cmd test -- components/PcapForensicRoles.test.tsx PcapChallengePage.test.tsx styles.test.ts`

Run: `npm.cmd run build`

```bash
git add frontend/src/styles.css frontend/src/components/PcapForensicRoles.test.tsx
git commit -m "style: distinguish pcap forensic roles"
```

### Task 3: Visual and Regression Verification

**Files:**
- Modify only files required by defects discovered in this bounded verification pass.

**Interfaces:**
- Verifies the complete PCAP challenge without changing its data or scoring contract.

- [ ] **Step 1: Run all challenge tests**

Run: `npm.cmd test -- PcapChallengePage.test.tsx ChallengePage.test.tsx components/PcapForensicRoles.test.tsx`

Expected: PASS.

- [ ] **Step 2: Run the full frontend test suite**

Run: `npm.cmd test`

Expected: PASS.

- [ ] **Step 3: Capture desktop and mobile screenshots**

Open `/pcap-challenge`, start the first round, and capture 1440x900 and 390x844. Confirm all three roles are visible, the active stage is recognizable without color alone, the evidence table remains readable, and no Token mascot asset or role name appears.

- [ ] **Step 4: Check the final diff**

Run: `git diff --check`

If verification finds no defect, create no commit. If it finds a defect, return to Task 1 or Task 2, add the failing regression test there, apply that task's explicit file list, and rerun this verification task from Step 1.
