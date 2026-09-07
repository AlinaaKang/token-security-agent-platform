# Agent PCAP Upload And Specialized Inspectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SuperAgent composer upload a selected PCAP through the existing local isolated-detection API and render task-specific Prompt, PCAP, and cross-domain inspectors.

**Architecture:** Browser-selected PCAP files stay local until a dedicated confirmation is accepted, then use the existing `/pcap-api` authorization, upload, polling, and cancellation calls. The active PCAP mission is owned by the application shell so inspector navigation cannot cancel it, while the workspace renders the existing public `PcapDetectionResult`; the inspector selects a view model from either the Agent task or PCAP mission.

**Tech Stack:** React 19, TypeScript, React Router, Vitest, Testing Library, existing PCAP REST client and mission types.

## Global Constraints

- PCAP bytes, original filenames, addresses, ports, and payloads must never be sent to AutoDL or the Agent task API.
- PCAP bytes may only enter the existing local `/pcap-api` isolated Docker path after explicit confirmation.
- Selecting inspector tabs must never cancel an active PCAP mission; only an explicit cancel command may cancel it.
- Token detective challenge behavior and frozen detection algorithms or thresholds must not change.
- Red means detected risk, green means success or no hit, amber means failure, degraded, awaiting authorization, or review, and blue means identity, navigation, running state, and audit structure.

---

### Task 1: PCAP Selection And Confirmation

**Files:**
- Create: `frontend/src/agent/pcapUpload.ts`
- Test: `frontend/src/agent/pcapUpload.test.ts`
- Modify: `frontend/src/components/AgentComposer.tsx`
- Test: `frontend/src/components/AgentComposer.test.tsx`

**Interfaces:**
- Produces: `validatePcapSelection(file: File, maxBytes?: number): string | null` and `formatPcapFileSize(bytes: number): string`.
- Produces: `AgentComposer` props `selectedPcap`, `pcapCapability`, `onFile`, and `onClearFile`.

- [ ] **Step 1: Write failing validation and composer tests**

```tsx
expect(validatePcapSelection(new File([], "empty.pcap"))).toBe("文件为空，请重新选择。");
fireEvent.change(screen.getByLabelText("选择 PCAP 文件"), { target: { files: [file] } });
expect(screen.getByText("sample.pcap")).toBeVisible();
expect(onSubmit).not.toHaveBeenCalled();
```

- [ ] **Step 2: Run tests and verify failure because the selection summary and validators do not exist**

Run: `npm.cmd test -- frontend/src/agent/pcapUpload.test.ts frontend/src/components/AgentComposer.test.tsx`

- [ ] **Step 3: Implement extension, empty-file, and size validation plus a removable file summary**

```ts
export function validatePcapSelection(file: File, maxBytes = 0) {
  const extension = file.name.split(".").pop()?.toLowerCase();
  if (!extension || !["pcap", "pcapng"].includes(extension)) return "请选择 .pcap 或 .pcapng 文件。";
  if (file.size < 1) return "文件为空，请重新选择。";
  if (maxBytes > 0 && file.size > maxBytes) return "文件超过当前允许的上传大小。";
  return null;
}
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `npm.cmd test -- frontend/src/agent/pcapUpload.test.ts frontend/src/components/AgentComposer.test.tsx`

### Task 2: Local Upload Mission Lifecycle

**Files:**
- Create: `frontend/src/components/AgentPcapUploadDialog.tsx`
- Test: `frontend/src/components/AgentPcapUploadDialog.test.tsx`
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Test: `frontend/src/AgentWorkspacePage.test.tsx`
- Modify: `frontend/src/App.tsx`

**Interfaces:**
- Produces: `AgentPcapUploadDialog({ file, busy, onCancel, onConfirm })`.
- Produces: `AgentWorkspacePage` props `pcapMission` and `onPcapMissionChange`.
- Consumes: `api.pcapUploadCapability`, `api.authorizePcapUpload`, `api.uploadPcapForDetection`, `api.getPcapMission`, and `api.cancelPcapDetectionMission`.

- [ ] **Step 1: Write failing workspace tests for confirm-before-upload, local-only calls, progress, polling, retryable error, and explicit cancellation**

```tsx
fireEvent.click(screen.getByRole("button", { name: "发送" }));
expect(await screen.findByRole("dialog", { name: "确认 PCAP 上传检测" })).toBeVisible();
expect(api.createAgentTask).not.toHaveBeenCalled();
fireEvent.click(screen.getByRole("button", { name: "确认上传并检测" }));
await waitFor(() => expect(api.uploadPcapForDetection).toHaveBeenCalledWith(file, expect.any(String), expect.any(Function)));
```

- [ ] **Step 2: Run the focused workspace tests and verify the expected failures**

Run: `npm.cmd test -- frontend/src/AgentWorkspacePage.test.tsx frontend/src/components/AgentPcapUploadDialog.test.tsx`

- [ ] **Step 3: Implement confirmation, local authorization/upload, bounded polling retries, preserved selection on recoverable errors, and explicit cancellation**

```ts
const receipt = await api.authorizePcapUpload(file.size);
const started = await api.uploadPcapForDetection(file, receipt.authorization_id, setPcapProgress);
onPcapMissionChange(started);
```

- [ ] **Step 4: Lift the mission into `App.tsx` and prove inspector/tab state changes cannot call cancellation**

```tsx
const [pcapMission, setPcapMission] = useState<PcapDetectionMissionResult | null>(null);
<AgentWorkspacePage pcapMission={pcapMission} onPcapMissionChange={setPcapMission} />
<AgentInspectorShell task={agentTask} pcapMission={pcapMission} />
```

- [ ] **Step 5: Run the focused lifecycle tests and verify they pass**

Run: `npm.cmd test -- frontend/src/AgentWorkspacePage.test.tsx frontend/src/components/AgentPcapUploadDialog.test.tsx`

### Task 3: PCAP Results In The Agent Workspace

**Files:**
- Modify: `frontend/src/pages/AgentWorkspacePage.tsx`
- Test: `frontend/src/AgentWorkspacePage.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `PcapDetectionResult` with the active `PcapDetectionMissionResult`.
- Produces: visible readiness, upload progress, mission result, cancellation, and explicit result-boundary copy.

- [ ] **Step 1: Write failing result-state tests for running, completed-no-hit, anomaly, degraded, and unavailable API states**

```tsx
render(<AgentWorkspacePage pcapMission={mission("completed")} onPcapMissionChange={vi.fn()} />);
expect(screen.getByText("未发现可定位异常")).toBeVisible();
expect(screen.getByText(/不等于文件全部安全/)).toBeVisible();
```

- [ ] **Step 2: Run the result tests and verify failure because the workspace does not render PCAP missions**

Run: `npm.cmd test -- frontend/src/AgentWorkspacePage.test.tsx`

- [ ] **Step 3: Render `PcapDetectionResult`, progress, and recovery actions without exposing protected raw fields**

```tsx
{pcapMission ? <PcapDetectionResult mission={pcapMission} sampleLabel={() => "上传样本"} onCancel={cancelPcapMission} busy={pcapBusy} /> : null}
```

- [ ] **Step 4: Run the focused tests and verify they pass**

Run: `npm.cmd test -- frontend/src/AgentWorkspacePage.test.tsx frontend/src/components/PcapDetectionResult.test.tsx`

### Task 4: Task-Specific Inspectors

**Files:**
- Create: `frontend/src/agent/inspectorMode.ts`
- Test: `frontend/src/agent/inspectorMode.test.ts`
- Create: `frontend/src/components/AgentPromptInspector.tsx`
- Create: `frontend/src/components/AgentPcapInspector.tsx`
- Modify: `frontend/src/components/AgentInspectorShell.tsx`
- Test: `frontend/src/components/AgentInspectorShell.test.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Produces: `resolveInspectorMode(task, pcapMission): "prompt" | "pcap" | "cross-domain" | "knowledge"`.
- Produces: Prompt tabs `Guard`, `Token`, `复核`, `工具`, `报告`.
- Produces: PCAP tabs `概况`, `Packet`, `解析`, `报告`.

- [ ] **Step 1: Write failing mode and rendering tests**

```tsx
expect(resolveInspectorMode(promptTask, null)).toBe("prompt");
expect(resolveInspectorMode(null, pcapMission)).toBe("pcap");
expect(screen.getByLabelText("PCAP 调查检查器")).toBeVisible();
expect(screen.getByRole("button", { name: "Packet" })).toBeVisible();
```

- [ ] **Step 2: Run the focused inspector tests and verify expected failure**

Run: `npm.cmd test -- frontend/src/agent/inspectorMode.test.ts frontend/src/components/AgentInspectorShell.test.tsx`

- [ ] **Step 3: Implement mode resolution and specialized inspector components using only public evidence and mission fields**

```ts
if (pcapMission || task?.task_type === "pcap_dataset_investigation") return "pcap";
if (task?.task_type === "prompt_investigation") return "prompt";
return task?.task_type === "knowledge_explanation" ? "knowledge" : "cross-domain";
```

- [ ] **Step 4: Add keyboard-accessible tab labels, status text, empty/error states, wrapping, and task-type-specific titles**

```tsx
<aside aria-label={mode === "pcap" ? "PCAP 调查检查器" : mode === "prompt" ? "Prompt 调查检查器" : "案件检查器"}>
```

- [ ] **Step 5: Run focused tests and verify they pass**

Run: `npm.cmd test -- frontend/src/agent/inspectorMode.test.ts frontend/src/components/AgentInspectorShell.test.tsx`

### Task 5: Regression And Visual Verification

**Files:**
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/styles.test.ts`

**Interfaces:**
- Verifies all earlier interfaces and privacy boundaries.

- [ ] **Step 1: Run the full frontend suite**

Run: `npm.cmd test`

- [ ] **Step 2: Run the production build**

Run: `npm.cmd run build`

- [ ] **Step 3: Run PCAP privacy and upload backend regressions**

Run: `..\..\.venv\Scripts\python.exe -m pytest tests -q -k "pcap and (privacy or upload or mission)"`

- [ ] **Step 4: Run whitespace and design-detector checks**

Run: `git diff --check`

Run: `node C:\Users\Graci\.codex\skills\impeccable\scripts\detect.mjs --json frontend/src/pages/AgentWorkspacePage.tsx frontend/src/components/AgentComposer.tsx frontend/src/components/AgentInspectorShell.tsx frontend/src/components/AgentPcapUploadDialog.tsx frontend/src/components/AgentPromptInspector.tsx frontend/src/components/AgentPcapInspector.tsx frontend/src/styles.css`

- [ ] **Step 5: Inspect desktop and mobile screenshots in one bounded browser pass, apply one consolidated fix batch, then confirm once**

- [ ] **Step 6: Re-read the design spec and verify every requirement has an implementation or test reference**

