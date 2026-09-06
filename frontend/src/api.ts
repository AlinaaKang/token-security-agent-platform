import type {
  AnalysisResult,
  DemoAnalysisResult,
  DemoSample,
  EvaluationSummary,
  EventPage,
  HealthResponse,
  KnowledgeMode,
  LabRunRequest,
  LabRunResult,
  LabMetrics,
  LabScenario,
  LabToolExecution,
  LabToolId,
  Mode,
  PcapAuthorizationReceipt,
  PcapAuthorizationRequest,
  PcapMissionRequest,
  PcapMissionResult,
  PcapOverview,
  PcapReconOverview,
  PcapReconAuthorizationRequest,
  PcapReconAuthorizationReceipt,
  PcapReconMissionRequest,
  PcapReconMissionResult,
  PcapDetectionOverview,
  PcapDetectionAuthorizationRequest,
  PcapDetectionMissionRequest,
  PcapDetectionMissionResult,
  PcapUploadCapability,
  SuperAgentCapabilities,
  SuperAgentMissionRequest,
  SuperAgentMissionResult,
  SuperAgentStoredMission,
} from "./types";
import type {
  AgentCapabilities,
  AgentTaskPage,
  AgentTaskSnapshot,
} from "./agent/types";

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      payload?.error?.message ??
      payload?.detail ??
      "请求失败（HTTP " + (response.status ?? "unknown") + "）";
    const error = new Error(message) as Error & { status?: number; code?: string };
    error.status = response.status;
    error.code = payload?.error?.code;
    throw error;
  }
  return payload as T;
}

const PCAP_API = "/pcap-api/v1/superagent";

function uploadPcapForDetection(
  file: File,
  authorizationId: string,
  onProgress: (percent: number) => void,
): Promise<PcapDetectionMissionResult> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", PCAP_API + "/pcap/detection/uploads");
    request.setRequestHeader("Content-Type", "application/octet-stream");
    request.setRequestHeader("X-PCAP-Authorization", authorizationId);
    request.upload.onprogress = (event) => {
      if (event.lengthComputable && event.total > 0) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    };
    request.onload = () => {
      let payload: unknown = null;
      try { payload = JSON.parse(request.responseText); } catch { /* fixed below */ }
      if (request.status >= 200 && request.status < 300) {
        resolve(payload as PcapDetectionMissionResult);
        return;
      }
      const body = payload as { error?: { code?: string; message?: string } } | null;
      const error = new Error(body?.error?.message ?? `请求失败（HTTP ${request.status || "unknown"}）`) as Error & { status?: number; code?: string };
      error.status = request.status;
      error.code = body?.error?.code;
      reject(error);
    };
    request.onerror = () => reject(Object.assign(new Error("无法连接本地 PCAP 后端"), { status: 0, code: "pcap_upload_unavailable" }));
    request.onabort = () => reject(Object.assign(new Error("上传已取消"), { status: 0, code: "pcap_upload_cancelled" }));
    request.send(file);
  });
}

export const api = {
  health: () => requestJson<HealthResponse>("/health"),
  agentCapabilities: () =>
    requestJson<AgentCapabilities>("/api/v1/agent/capabilities"),
  createAgentTask: (message: string) =>
    requestJson<AgentTaskSnapshot>("/api/v1/agent/tasks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    }),
  listAgentTasks: (limit = 20, offset = 0) =>
    requestJson<AgentTaskPage>(`/api/v1/agent/tasks?limit=${limit}&offset=${offset}`),
  getAgentTask: (taskId: string) =>
    requestJson<AgentTaskSnapshot>(`/api/v1/agent/tasks/${encodeURIComponent(taskId)}`),
  messageAgentTask: (taskId: string, message: string) =>
    requestJson<AgentTaskSnapshot>(`/api/v1/agent/tasks/${encodeURIComponent(taskId)}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    }),
  authorizeAgentTask: (taskId: string, scopes: string[]) =>
    requestJson<AgentTaskSnapshot>(`/api/v1/agent/tasks/${encodeURIComponent(taskId)}/authorizations`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirmed: true, scopes }),
    }),
  cancelAgentTask: (taskId: string) =>
    requestJson<AgentTaskSnapshot>(`/api/v1/agent/tasks/${encodeURIComponent(taskId)}/cancel`, {
      method: "POST",
    }),
  agentEventStreamUrl: (taskId: string) =>
    `/api/v1/agent/tasks/${encodeURIComponent(taskId)}/events`,
  analyze: (prompt: string, modelId: string, mode: Mode, knowledgeMode: KnowledgeMode = "off") =>
    requestJson<AnalysisResult>("/api/v1/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt, model_id: modelId, mode, knowledge_mode: knowledgeMode }),
    }),
  events: (limit = 50, offset = 0) =>
    requestJson<EventPage>("/api/v1/events?limit=" + limit + "&offset=" + offset),
  evaluation: () =>
    requestJson<EvaluationSummary>("/api/v1/evaluation/summary"),
  demoSamples: () =>
    requestJson<DemoSample[]>("/api/v1/demo-samples?limit=30"),
  analyzeDemo: (sampleId: string) =>
    requestJson<DemoAnalysisResult>(
      "/api/v1/demo-samples/" + encodeURIComponent(sampleId) + "/analyze",
      { method: "POST" },
    ),
  labScenarios: () =>
    requestJson<LabScenario[]>("/api/v1/lab/scenarios"),
  labMetrics: () =>
    requestJson<LabMetrics>("/api/v1/lab/metrics"),
  createLabRun: (payload: LabRunRequest) =>
    requestJson<LabRunResult>("/api/v1/lab/runs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getLabRun: (runId: string) =>
    requestJson<LabRunResult>(
      "/api/v1/lab/runs/" + encodeURIComponent(runId),
    ),
  dryRunLabTool: (runId: string, toolId: LabToolId, injectFailure: boolean) =>
    requestJson<LabRunResult>(
      "/api/v1/lab/runs/" + encodeURIComponent(runId) +
        "/tools/" + encodeURIComponent(toolId) + "/dry-run",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ inject_failure: injectFailure }),
      },
    ),
  executeLabTool: (runId: string, toolId: LabToolId, idempotencyKey: string) =>
    requestJson<LabToolExecution>(
      "/api/v1/lab/runs/" + encodeURIComponent(runId) +
        "/tools/" + encodeURIComponent(toolId) + "/execute",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ confirmed: true, idempotency_key: idempotencyKey }),
      },
    ),
  listLabExecutions: (runId: string) =>
    requestJson<LabToolExecution[]>(
      "/api/v1/lab/runs/" + encodeURIComponent(runId) + "/executions",
    ),
  labArtifactDownloadUrl: (artifactId: string) =>
    "/api/v1/lab/artifacts/" + encodeURIComponent(artifactId) + "/download",
  superAgentCapabilities: () =>
    requestJson<SuperAgentCapabilities>("/api/v1/superagent/capabilities"),
  createSuperAgentMission: (payload: SuperAgentMissionRequest) =>
    requestJson<SuperAgentMissionResult>("/api/v1/superagent/missions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  pcapCapabilities: () =>
    requestJson<PcapOverview>(PCAP_API + "/pcap/capabilities"),
  pcapOverview: () =>
    requestJson<PcapOverview>(PCAP_API + "/pcap/overview"),
  pcapReconOverview: () =>
    requestJson<PcapReconOverview>(PCAP_API + "/pcap/reconnaissance/overview"),
  pcapDetectionOverview: () =>
    requestJson<PcapDetectionOverview>(PCAP_API + "/pcap/detection/overview"),
  pcapUploadCapability: () =>
    requestJson<PcapUploadCapability>(PCAP_API + "/pcap/detection/upload-capability"),
  authorizePcapUpload: (byteCount: number) =>
    requestJson<PcapAuthorizationReceipt>(PCAP_API + "/pcap/detection/upload-authorizations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirmed: true, byte_count: byteCount }),
    }),
  uploadPcapForDetection,
  authorizePcapDetection: (payload: PcapDetectionAuthorizationRequest) =>
    requestJson<PcapAuthorizationReceipt>(PCAP_API + "/pcap/detection/authorizations", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    }),
  createPcapDetectionMission: (payload: PcapDetectionMissionRequest) =>
    requestJson<PcapDetectionMissionResult>(PCAP_API + "/missions", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload),
    }),
  authorizePcapRecon: (payload: PcapReconAuthorizationRequest) =>
    requestJson<PcapReconAuthorizationReceipt>(PCAP_API + "/pcap/reconnaissance/authorizations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  createPcapReconMission: (payload: PcapReconMissionRequest) =>
    requestJson<PcapReconMissionResult>(PCAP_API + "/missions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  authorizePcapBatch: (payload: PcapAuthorizationRequest) =>
    requestJson<PcapAuthorizationReceipt>(PCAP_API + "/pcap/authorizations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  createPcapMission: (payload: PcapMissionRequest) =>
    requestJson<PcapMissionResult>(PCAP_API + "/missions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getSuperAgentMission: (missionId: string) =>
    requestJson<SuperAgentStoredMission>(
      "/api/v1/superagent/missions/" + encodeURIComponent(missionId),
    ),
  getPcapMission: (missionId: string) =>
    requestJson<SuperAgentStoredMission>(
      PCAP_API + "/missions/" + encodeURIComponent(missionId),
    ),
  cancelPcapMission: (missionId: string) =>
    requestJson<PcapMissionResult>(
      PCAP_API + "/missions/" + encodeURIComponent(missionId) + "/cancel",
      { method: "POST" },
    ),
  cancelPcapDetectionMission: (missionId: string) =>
    requestJson<PcapDetectionMissionResult>(
      PCAP_API + "/missions/" + encodeURIComponent(missionId) + "/cancel",
      { method: "POST" },
    ),
};
