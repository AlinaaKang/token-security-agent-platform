export type EvidenceAuthenticity = "real" | "simulated" | "derived";
export type AgentTaskStatus =
  | "draft" | "awaiting_authorization" | "planned" | "queued" | "running"
  | "paused" | "completed" | "degraded" | "failed" | "cancelled";

export interface AgentMessage {
  message_id: string;
  role: "user" | "agent" | "system";
  kind: "message" | "status" | "question" | "result" | "warning";
  content: string;
  created_at: string;
  evidence_scope: "general" | "current_case" | "none";
  evidence_refs: string[];
}

export interface AgentSuggestedQuestion {
  question_id: string;
  label: string;
  message: string;
}

export interface AgentNextAction {
  action_id: "explain_evidence" | "suggest_prompt_repair" | "recheck_prompt"
    | "inspect_suspicious_packets" | "analyze_attack_chain"
    | "generate_response_plan" | "generate_report" | "expand_pcap_scope";
  label: string;
  action_kind: "read_only" | "state_change";
  requires_authorization: boolean;
  enabled: boolean;
  disabled_reason: string | null;
}

export interface AgentPlanStep {
  step_id: string;
  tool_id: string | null;
  status: "waiting" | "running" | "succeeded" | "failed" | "skipped";
  requires_authorization: boolean;
  summary: string;
  depends_on: string[];
  attempt: number;
}

export interface AgentObservation {
  observation_id: string;
  kind: string;
  status: "succeeded" | "failed" | "unavailable" | "degraded";
  summary: string;
  observed_at: string;
  tool_id: string | null;
  evidence_refs: string[];
  retryable: boolean;
  public_error_code: string | null;
}

export interface AgentEvidence {
  evidence_id: string;
  authenticity: EvidenceAuthenticity;
  source_type: string;
  source_ref: string;
  tool_id: string | null;
  summary: string;
  observed_at: string;
  uncertainty: string;
  metadata: Record<string, unknown>;
}

export interface AgentConfidenceChange {
  before: number;
  after: number;
  evidence_refs: string[];
  reason: string;
  changed_at: string;
}

export interface AgentHypothesis {
  hypothesis_id: string;
  title: string;
  status: "investigating" | "supported" | "weakened" | "rejected" | "inconclusive";
  confidence: number;
  supporting_evidence_refs: string[];
  opposing_evidence_refs: string[];
  confidence_changes: AgentConfidenceChange[];
  limitations: string[];
}

export interface AgentTimelineEvent {
  timeline_id: string;
  occurred_at: string;
  source_type: string;
  authenticity: EvidenceAuthenticity;
  summary: string;
  evidence_refs: string[];
}

export interface AgentEvidenceConflict {
  conflict_id: string;
  summary: string;
  evidence_refs: string[];
  resolution: string | null;
  status: "open" | "resolved";
}

export interface AgentEvent {
  task_id: string;
  sequence: number;
  phase: "understand" | "plan" | "authorize" | "act" | "observe" | "replan" | "verify" | "complete";
  kind: string;
  summary: string;
  created_at: string;
  evidence_refs: string[];
}

export interface AgentReportMetadata {
  report_id: string;
  title: string;
  format: "markdown";
  status: "ready" | "degraded" | "unavailable";
  artifact_ref: string | null;
  evidence_refs: string[];
  generated_at: string;
}

export interface AgentTaskSnapshot {
  task_id: string;
  version: number;
  task_type: string;
  workspace_mode?: "prompt" | "pcap" | null;
  status: AgentTaskStatus;
  title: string;
  objective_summary: string;
  created_at: string;
  updated_at: string;
  messages: AgentMessage[];
  suggested_questions?: AgentSuggestedQuestion[];
  next_actions?: AgentNextAction[];
  plan: AgentPlanStep[];
  observations: AgentObservation[];
  evidence: AgentEvidence[];
  hypotheses: AgentHypothesis[];
  timeline: AgentTimelineEvent[];
  conflicts: AgentEvidenceConflict[];
  events: AgentEvent[];
  replan_count: number;
  authorization_scopes: string[];
  final_status: "safe" | "risk_found" | "contained" | "inconclusive" | null;
  report: AgentReportMetadata | null;
  limitations: string[];
}

export interface AgentCapabilities {
  planner_mode: "model" | "deterministic_fallback" | "unavailable";
  tool_ids: string[];
  connector_states: Record<string, "available" | "simulated" | "degraded" | "unavailable">;
  max_plan_steps: number;
  max_concurrent_tools: number;
  max_replans: number;
  max_active_hypotheses: number;
  pcap_batch_size: number;
}

export interface AgentTaskPage {
  items: AgentTaskSnapshot[];
  limit: number;
  offset: number;
}

export interface AgentPlaybookStep {
  step_id: string;
  tool_id: string;
  requires_authorization: boolean;
  on_failure: "stop_for_review" | "retry_once" | "continue_degraded";
}

export interface AgentPlaybook {
  playbook_id: string;
  title: string;
  task_type: string;
  description: string;
  steps?: AgentPlaybookStep[];
  version?: string;
  step_count?: number;
}

export interface AgentPlaybookCatalog {
  version: string;
  playbooks: AgentPlaybook[];
}

export interface AgentConnector {
  connector_id: string;
  title: string;
  state: "available" | "simulated" | "degraded" | "unavailable";
  authenticity: EvidenceAuthenticity;
}

export interface AgentKnowledgeItem {
  knowledge_id: string;
  title: string;
  publisher: string;
  version: string;
  risk_domain: string;
}

export interface AgentKnowledgeCatalog {
  snapshot_version: string;
  card_count: number;
  items: AgentKnowledgeItem[];
}

export interface AgentReportListItem {
  task_id: string;
  task_title: string;
  final_status: AgentTaskSnapshot["final_status"];
  report_id: string;
  title: string;
  status: AgentReportMetadata["status"];
  generated_at: string;
  download_url: string;
}

export interface AgentReportCatalog { items: AgentReportListItem[]; }
