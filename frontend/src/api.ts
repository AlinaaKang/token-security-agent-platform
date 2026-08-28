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
} from "./types";

async function requestJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      payload?.error?.message ??
      payload?.detail ??
      "请求失败（HTTP " + (response.status ?? "unknown") + "）";
    throw new Error(message);
  }
  return payload as T;
}

export const api = {
  health: () => requestJson<HealthResponse>("/health"),
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
};
