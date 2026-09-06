# SuperAgent PCAP Interactive Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SuperAgent batch-triage replay explain one PCAP capture at a time with PCAP-specific roles, and restore anomaly-detection missions after PCAP tab switches or page refreshes.

**Architecture:** Keep the existing backend contracts and task boundaries. Add restoration to `PcapDetectionWorkspace` using its existing session key and mission endpoint; reshape the frontend-only PCAP investigation model to consume one public `PcapCaptureEvidence`; then update the PCAP-only mascot UI with a capture selector while leaving `ChallengePage` and `MascotTeam` untouched.

**Tech Stack:** React 19, TypeScript, Vitest, Testing Library, CSS, existing REST API and session storage.

**Command working directory:** Run `npm.cmd` commands from `frontend`; run `git` commands from the repository root.

## Global Constraints

- Keep the labels `批量分诊`, `数据勘察`, and `异常检测` unchanged.
- Keep the maximum batch size at 20 and do not add automatic all-file processing or automatic authorization.
- Do not modify PCAP detection rules, thresholds, Docker isolation, authorization flow, or concurrency.
- Do not display filenames, paths, IP addresses, ports, payloads, raw requests, or content summaries.
- Do not modify Prompt detection, analysis/gateway behavior, Lab behavior, `ChallengePage`, `MascotTeam`, Token detective roles, challenge ordering, scoring, or results.
- Batch triage must never claim that an attack was found or ruled out; attack candidates remain the responsibility of `异常检测`.
- A PCAP tab switch must never call a cancellation endpoint; only an explicit cancel button may cancel anomaly detection.
- Reuse the three existing mascot assets without modifying them.

---

### Task 1: Restore anomaly-detection missions after remount

**Files:**
- Modify: `frontend/src/pages/PcapDetectionWorkspace.tsx`
- Test: `frontend/src/pages/PcapDetectionWorkspace.test.tsx`

**Interfaces:**
- Consumes: `api.getPcapMission(id): Promise<SuperAgentStoredMission>` and the existing session key value `token-security-superagent-pcap-detection-id`.
- Produces: remount/refresh restoration for only missions whose `objective === "detect_pcap_anomalies"`; existing polling consumes the restored `PcapDetectionMissionResult`.

- [ ] **Step 1: Add failing restoration tests**

Add storage cleanup to test setup and tests equivalent to:

```tsx
beforeEach(() => {
  window.sessionStorage.clear();
  // keep the existing fetch stub setup
});

it("restores a saved running anomaly mission and resumes polling", async () => {
  window.sessionStorage.setItem(
    "token-security-superagent-pcap-detection-id",
    "detection_0123456789abcdef0123456789abcdef",
  );
  let missionReads = 0;
  vi.stubGlobal("fetch", vi.fn((url: string) => {
    if (url.includes("/overview")) return Promise.resolve(overviewResponse());
    missionReads += 1;
    return Promise.resolve(new Response(JSON.stringify(
      detectionResult(missionReads === 1 ? "running" : "completed"),
    ), { status: 200 }));
  }));

  render(<PcapDetectionWorkspace />);
  expect(await screen.findByText("检测运行中")).toBeInTheDocument();
  expect(await screen.findByText("检测完成")).toBeInTheDocument();
});

it("clears an expired saved mission without authorizing a new task", async () => {
  window.sessionStorage.setItem(
    "token-security-superagent-pcap-detection-id",
    "detection_0123456789abcdef0123456789abcdef",
  );
  const fetchMock = vi.fn((url: string) => url.includes("/overview")
    ? Promise.resolve(overviewResponse())
    : Promise.resolve(new Response(JSON.stringify({ detail: "gone" }), { status: 410 })));
  vi.stubGlobal("fetch", fetchMock);

  render(<PcapDetectionWorkspace />);
  expect(await screen.findByRole("button", { name: /准备异常检测/ })).toBeEnabled();
  expect(window.sessionStorage.getItem("token-security-superagent-pcap-detection-id")).toBeNull();
  expect(fetchMock).not.toHaveBeenCalledWith(
    expect.stringContaining("authorizations"),
    expect.anything(),
  );
});
```

Also cover a transient restore failure retaining the ID and showing `无法恢复异常检测任务，请重试` and an objective mismatch clearing the ID without rendering that mission.
For the transient case, click a `重试恢复` button, return the saved mission from the next GET, and assert the mission renders without a new authorization request.

- [ ] **Step 2: Run the focused test and confirm the failure**

Run:

```powershell
npm.cmd test -- --run src/pages/PcapDetectionWorkspace.test.tsx
```

Expected: the restoration assertions fail because the component never reads the saved ID.

- [ ] **Step 3: Add storage helpers and restore during initialization**

Add private helpers in `PcapDetectionWorkspace.tsx`:

```ts
function readDetectionMissionId(): string | null {
  try { return window.sessionStorage.getItem(DETECTION_MISSION_KEY); }
  catch { return null; }
}

function rememberDetectionMissionId(id: string | null) {
  try {
    if (id) window.sessionStorage.setItem(DETECTION_MISSION_KEY, id);
    else window.sessionStorage.removeItem(DETECTION_MISSION_KEY);
  } catch {
    // Session persistence is optional; the mounted task remains usable.
  }
}
```

Replace the overview-only mount effect with one that starts `api.pcapDetectionOverview()` and, when a saved ID exists, `api.getPcapMission(savedId)` concurrently. Apply these exact rules:

```ts
if (restored?.objective === "detect_pcap_anomalies") setMission(restored);
else if (restored) rememberDetectionMissionId(null);
```

For a rejected restore, inspect `(error as Error & { status?: number }).status`. Clear the key for `404` or `410`; retain it and set `无法恢复异常检测任务，请重试` for other failures. An overview failure still sets `PCAP 异常检测暂不可用`. Use a mounted flag so late results cannot update an unmounted component.

Track transient restoration failure separately from general availability errors. Render a `重试恢复` button only for that state; clicking it clears the transient error and increments a restore revision so the saved ID is queried again. The retry must not authorize or create a mission.

Replace the direct `sessionStorage.setItem` in `start()` with `rememberDetectionMissionId(result.detection_id)`. Do not clear the ID merely because the mission reached a terminal state: terminal results must survive refresh.

- [ ] **Step 4: Run focused tests**

Run:

```powershell
npm.cmd test -- --run src/pages/PcapDetectionWorkspace.test.tsx
```

Expected: all tests in the file pass, including running, terminal, expired, mismatch, and transient restoration cases.

- [ ] **Step 5: Commit**

```powershell
git add frontend/src/pages/PcapDetectionWorkspace.tsx frontend/src/pages/PcapDetectionWorkspace.test.tsx
git commit -m "fix: restore PCAP anomaly missions"
```

---

### Task 2: Model PCAP-specific evidence for one capture

**Files:**
- Modify: `frontend/src/pcap/investigation.ts`
- Test: `frontend/src/pcap/investigation.test.ts`

**Interfaces:**
- Consumes: one existing `PcapCaptureEvidence` from `mission.summary.captures`.
- Produces: `PcapInvestigationRole = "parser" | "traffic" | "captain"` and `buildPcapRoleLines(capture, role): PcapEvidenceLine[]` for the PCAP replay UI.

- [ ] **Step 1: Replace aggregate/Prompt-oriented expectations with failing per-capture tests**

Add fixtures for succeeded plaintext, succeeded encrypted, failed, skipped, and insufficient-evidence captures. Assert exact outcomes such as:

```ts
expect(buildPcapRoleLines(plaintextCapture, "parser")).toEqual([
  { section: "evidence", text: "检查成功；已验证 12 个数据包" },
]);

expect(buildPcapRoleLines(plaintextCapture, "traffic")).toEqual([
  { section: "evidence", text: "协议计数：HTTP 12" },
  { section: "evidence", text: "明文应用协议可见" },
  { section: "evidence", text: "证据能力：可继续进行应用层检测；不证明存在 LLM 流量或攻击" },
]);

expect(buildPcapRoleLines(failedCapture, "captain")).toEqual([
  { section: "confirmed", text: "未形成可验证检查结果" },
  { section: "candidate", text: "暂无可复核网络证据" },
  { section: "unknown", text: "失败原因：inspector_failed" },
  { section: "recommendation", text: "建议重试该文件" },
]);
```

Also assert:

- protocol names are sorted before formatting;
- `traffic_only` says only network evidence is available;
- `insufficient_evidence` does not claim safety;
- no line contains `Prompt`, `CPD`, `Token 异常`, `SQL 注入`, or an attack verdict.

- [ ] **Step 2: Run the pure-state tests and confirm the failure**

Run:

```powershell
npm.cmd test -- --run src/pcap/investigation.test.ts
```

Expected: type and assertion failures because roles and builders still describe aggregate Guard/CPD evidence.

- [ ] **Step 3: Implement the three-role per-capture builder**

Change the public types to:

```ts
export type PcapInvestigationRole = "parser" | "traffic" | "captain";
export type PcapEvidenceSection =
  | "evidence"
  | "confirmed"
  | "candidate"
  | "unknown"
  | "recommendation";

const ROLE_ORDER: PcapInvestigationRole[] = ["parser", "traffic", "captain"];

export function buildPcapRoleLines(
  capture: PcapCaptureEvidence,
  role: PcapInvestigationRole,
): PcapEvidenceLine[];
```

Implement deterministic, sanitized mappings:

- `parser`: status label plus packet count; failed status includes only `error_code ?? "未提供错误代码"`.
- `traffic`: sorted `protocol_counts`, visibility, and capability boundary. Empty protocols render `协议计数：无可用协议计数`.
- `captain`: four sections. A successful `token_eligible` capture recommends `建议进入异常检测继续研判`; `traffic_only` recommends `建议保留网络元数据供人工复核`; `insufficient_evidence` recommends `建议补充可见流量后重试`; failed recommends retry; skipped states that no new result was formed.

Keep `initialPcapInvestigationState`, `roleStateForPcap`, `selectPcapRole`, and `finishPcapRole` behavior unchanged apart from the new role names.

- [ ] **Step 4: Run pure-state tests**

Run:

```powershell
npm.cmd test -- --run src/pcap/investigation.test.ts
```

Expected: all investigation state and evidence-line tests pass.

- [ ] **Step 5: Commit**

```powershell
git add frontend/src/pcap/investigation.ts frontend/src/pcap/investigation.test.ts
git commit -m "refactor: explain per-capture PCAP evidence"
```

---

### Task 3: Build the batch-triage interactive replay and protect other workflows

**Files:**
- Modify: `frontend/src/components/PcapMascotTeam.tsx`
- Modify: `frontend/src/components/PcapEvidenceDesk.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/components/PcapMascotTeam.test.tsx`
- Test: `frontend/src/components/PcapEvidenceDesk.test.tsx`
- Test: `frontend/src/PcapSuperAgentWorkspace.test.tsx`
- Test: `frontend/src/ChallengePage.test.tsx`

**Interfaces:**
- Consumes: Task 2's `buildPcapRoleLines(capture, role)` and the existing `mission.summary.captures` array.
- Produces: a PCAP-only `批量分诊互动复盘` region with capture selection and sequential role playback; no changes to the shared Token `MascotTeam`.

- [ ] **Step 1: Write failing component and integration tests**

Update PCAP component fixtures and assert:

```tsx
expect(screen.getByRole("region", { name: "批量分诊互动复盘" })).toBeVisible();
expect(screen.getByRole("button", { name: "回放捕获 1" })).toHaveAttribute("aria-pressed", "true");
expect(screen.getByRole("button", { name: "文件解析员" })).toBeEnabled();
expect(screen.getByRole("button", { name: "流量分析员" })).toBeDisabled();
expect(screen.getByRole("button", { name: "分诊队长" })).toBeDisabled();
```

After completing the first role, switch to `回放捕获 2` and assert the role sequence resets, the evidence desk shows capture 2's TLS evidence, and capture 1's HTTP count is absent. Add an empty-summary test asserting `本批次没有可回放文件` and no mascot buttons.

Add a `PcapSuperAgentWorkspace` integration test that starts a running anomaly mission, switches to `批量分诊`, switches back to `异常检测`, and asserts the same detection ID is fetched while no URL ending in `/cancel` was requested.

Keep or strengthen one `ChallengePage` assertion that the existing buttons `Guard 语义侦探`, `CPD 曲线侦探`, and `Agent 小队队长` are still present and ordered as before.

- [ ] **Step 2: Run the focused UI tests and confirm the failure**

Run:

```powershell
npm.cmd test -- --run src/components/PcapMascotTeam.test.tsx src/components/PcapEvidenceDesk.test.tsx src/PcapSuperAgentWorkspace.test.tsx src/ChallengePage.test.tsx
```

Expected: PCAP-specific labels, capture switching, and restored-tab assertions fail before implementation; existing Challenge behavior remains green.

- [ ] **Step 3: Update the PCAP-only mascot team**

Keep the existing image paths but change only the PCAP component metadata:

```ts
const MASCOTS = [
  { role: "parser", name: "文件解析员", image: "/mascots/guard-detective.webp", Icon: ShieldCheck },
  { role: "traffic", name: "流量分析员", image: "/mascots/cpd-detective.webp", Icon: Activity },
  { role: "captain", name: "分诊队长", image: "/mascots/agent-captain.webp", Icon: BadgeCheck },
] as const;
```

In `PcapMascotTeam`, derive `captures = mission.summary?.captures ?? []`, store `selectedCaptureIndex`, and render capture controls labeled `捕获 01`, `捕获 02`, etc. Their accessible names must be `回放捕获 1`, `回放捕获 2`, etc., and `aria-pressed` identifies the current item. On selection, set both the index and `initialPcapInvestigationState()`.

Change the region name and visible heading to `批量分诊互动复盘`; add supporting text `逐份解释当前批次的公开 PCAP 证据`. If `captures.length === 0`, render `本批次没有可回放文件` and no role controls.

- [ ] **Step 4: Make the evidence desk consume only the selected capture**

Change the props and playback identity:

```ts
interface PcapEvidenceDeskProps {
  missionId: string;
  capture: PcapCaptureEvidence;
  role: PcapInvestigationRole;
  replay: boolean;
  onComplete: () => void;
}

const lines = useMemo(
  () => buildPcapRoleLines(capture, role),
  [capture, role],
);
const playbackId = `${missionId}:${capture.capture_id}:${role}:${replay ? "replay" : "first"}`;
```

Use PCAP-only role labels `文件解析员`, `流量分析员`, and `分诊队长`. Add `recommendation: "建议动作"` to the captain grid. Preserve the reduced-motion and timer cleanup behavior.

- [ ] **Step 5: Add compact responsive styling**

Add styles for a horizontal, scrollable capture selector above the mascot lineup. Use fixed minimum control dimensions, visible focus states, and existing semantic variables. On narrow screens, keep capture buttons horizontally scrollable and change the three-column mascot lineup only if its existing responsive rule does not prevent overflow. Do not change `.challenge-*` or generic `.mascot-*` selectors.

- [ ] **Step 6: Run focused tests**

Run:

```powershell
npm.cmd test -- --run src/components/PcapMascotTeam.test.tsx src/components/PcapEvidenceDesk.test.tsx src/PcapSuperAgentWorkspace.test.tsx src/ChallengePage.test.tsx
```

Expected: all focused tests pass and the Token challenge regression retains its original role labels and order.

- [ ] **Step 7: Run full frontend verification**

Run:

```powershell
npm.cmd test -- --run
npm.cmd run build
```

Expected: the complete frontend test suite passes and Vite completes a production build without TypeScript errors.

- [ ] **Step 8: Verify desktop and mobile behavior in the browser**

Start the existing demo server and inspect `/super-agent` at `1440x900` and `390x844`. Verify:

- PCAP tabs keep their original names;
- the batch replay clearly says it is reviewing one capture from the current batch;
- switching captures never leaks the prior capture's evidence;
- switching away from a running anomaly task and returning restores the same task;
- no horizontal overflow, text overlap, console errors, or failed network requests other than intentionally mocked failure cases;
- `/challenge` retains its original Token detective interface.

- [ ] **Step 9: Commit**

```powershell
git add frontend/src/components/PcapMascotTeam.tsx frontend/src/components/PcapEvidenceDesk.tsx frontend/src/styles.css frontend/src/components/PcapMascotTeam.test.tsx frontend/src/components/PcapEvidenceDesk.test.tsx frontend/src/PcapSuperAgentWorkspace.test.tsx frontend/src/ChallengePage.test.tsx
git commit -m "feat: add interactive PCAP batch replay"
```
