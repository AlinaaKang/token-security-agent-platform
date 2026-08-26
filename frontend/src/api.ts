import type {
  AnalysisResult,
  DemoAnalysisResult,
  DemoSample,
  EvaluationSummary,
  EventPage,
  HealthResponse,
  KnowledgeMode,
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
};
