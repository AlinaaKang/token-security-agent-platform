export type Mode = "analysis" | "gateway";
export type KnowledgeMode = "off" | "evidence" | "report";
export type KnowledgeStatus = "off" | "ready" | "unavailable" | "degraded";
export type ReportStatus = "off" | "generated" | "fallback" | "unavailable";
export type KnowledgePublisher = "owasp" | "mitre" | "nist";
export type RiskDomain =
  | "prompt_injection"
  | "jailbreak"
  | "sensitive_information"
  | "excessive_agency"
  | "governance"
  | "incident_response";
export type Decision = "allow" | "review" | "block" | "sanitize_recheck";
export type DetectorStatus = "no_token_anomaly" | "token_anomaly_candidate";
export type SemanticSeverity = "safe" | "controversial" | "unsafe" | "unavailable";
export type SemanticCategory =
  | "violent"
  | "non_violent_illegal_acts"
  | "sexual_content"
  | "pii"
  | "suicide_self_harm"
  | "unethical_acts"
  | "politically_sensitive"
  | "copyright_violation"
  | "jailbreak";
export type FusionReason =
  | "semantic_unsafe"
  | "semantic_controversial"
  | "cpd_candidate"
  | "all_clear"
  | "semantic_unavailable_cpd_candidate"
  | "semantic_unavailable_gateway_fail_safe"
  | "semantic_unavailable_analysis_degraded";

export interface HealthResponse {
  status: string;
  model: { ready: boolean; model_id: string | null };
  detector: { ready: boolean; calibration_version: string | null };
  semantic_guard?: { ready: boolean; model_id: string; model_version: string };
  audit?: { ready: boolean; storage: string | null };
  evaluation?: { ready: boolean; report_version: number | null; deployment_match: boolean };
  demo?: { ready: boolean; sample_count: number };
  knowledge?: {
    ready: boolean;
    snapshot_version: string | null;
    card_count: number;
    generator_ready: boolean;
  };
}

export interface KnowledgeSource {
  publisher: KnowledgePublisher;
  title: string;
  url: string;
  version: string;
  verified_at: string;
  usage_note: string;
}

export interface KnowledgeEvidence {
  knowledge_id: string;
  title_zh: string;
  risk_domain: RiskDomain;
  summary: string;
  recommendations: string[];
  source: KnowledgeSource;
  retrieval_score: number;
  matched_tags: string[];
}

export interface GroundedReport {
  summary: string;
  evidence_ids: string[];
  handling_steps: string[];
  limitations: string[];
}

export interface TokenSignal {
  index: number;
  token_id: number;
  token_text: string;
  entropy: number;
  nll: number;
  cpd_entropy: number;
  cpd_nll: number;
  risk: number;
}

export interface AnalysisResult {
  request_id: string;
  decision: Decision;
  risk_score: number;
  detector_score: number;
  detector_status: DetectorStatus;
  semantic_severity: SemanticSeverity;
  semantic_categories: SemanticCategory[];
  semantic_model_id: string;
  semantic_model_version: string;
  semantic_latency_ms: number;
  semantic_verification: "performed" | "unavailable";
  fusion_reason: FusionReason;
  audit_persisted: boolean;
  suspicious_span: {
    token_start: number;
    token_end: number;
    char_start: number;
    char_end: number;
  } | null;
  signals: TokenSignal[];
  evidence: Array<{ source: string; summary: string }>;
  actions: string[];
  provenance: {
    model_id: string;
    tokenizer_id: string;
    system_prompt_hash: string;
    calibration_version: string;
    thresholds: Record<string, number>;
  };
  latency_ms: number;
  knowledge_status?: KnowledgeStatus;
  knowledge_snapshot_version?: string | null;
  knowledge_latency_ms?: number;
  knowledge_retrieval_latency_ms?: number;
  knowledge_report_latency_ms?: number;
  knowledge_evidence?: KnowledgeEvidence[];
  grounded_report?: GroundedReport | null;
  report_status?: ReportStatus;
}

export interface DemoSample {
  sample_id: string;
  family: string;
  split: "test";
  evaluated: boolean;
}

export interface DemoAnalysisResult {
  sample_id: string;
  family: string;
  split: "test";
  dataset_commit: string;
  result: AnalysisResult;
}

export interface SecurityEvent {
  request_id: string;
  created_at: string;
  prompt_sha256: string;
  prompt_char_count: number;
  token_count: number;
  detector_score: number;
  k: number;
  h: number;
  onset_token: number | null;
  detector_status: DetectorStatus;
  decision: Decision;
  mode: Mode;
  model_id: string;
  calibration_version: string;
  latency_ms: number;
  semantic_severity?: SemanticSeverity | null;
  semantic_categories?: SemanticCategory[] | null;
  semantic_model_id?: string | null;
  semantic_model_version?: string | null;
  semantic_latency_ms?: number | null;
  fusion_reason?: FusionReason | null;
  knowledge_snapshot_version?: string | null;
  knowledge_mode?: KnowledgeMode | null;
  knowledge_status?: KnowledgeStatus | null;
  knowledge_card_ids?: string[] | null;
  report_status?: ReportStatus | null;
  knowledge_latency_ms?: number | null;
}

export interface EventPage {
  items: SecurityEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface OperatingPoint {
  threshold: number;
  precision: number;
  recall: number;
  f1: number;
  auroc: number;
  false_positive_rate: number;
}

export interface FamilySummary {
  count: number;
  operating_points: Record<string, {
    detected: number;
    missed: number;
    recall: number;
  }>;
  score: { min: number; median: number; max: number };
}

export interface MethodSummary {
  display_name: string;
  profile: Record<string, string | number | null>;
  operating_points: {
    f1_selected: OperatingPoint;
    low_fpr_selected_on_dev: OperatingPoint;
  };
  families: Record<string, FamilySummary>;
  localization: {
    onset_mae: number;
    trigger_in_suffix_rate: number;
  } | null;
  latency_ms: { p50_ms: number; p95_ms: number };
}

export interface EvaluationSummary {
  schema_version: 2;
  counts: { total: number; attacks: number; benign: number };
  methods: Record<"global_nll" | "window_nll" | "entropy_cpd", MethodSummary>;
  not_evaluated: string[];
  provenance: { calibration_version: string; dataset_hash: string };
  deployment_match: boolean;
  knowledge?: KnowledgeEvaluation | null;
}

export interface KnowledgeEvaluation {
  schema_version: 1;
  case_count: number;
  hit_at_1: number;
  hit_at_3: number;
  mrr: number;
  citation_validity: number;
  decision_invariance: number;
  domains: Record<string, { case_count: number; hit_at_1: number; hit_at_3: number }>;
  snapshot_version: string;
  snapshot_hash: string;
  fixture_hash: string;
  retrieval_weights: Record<string, number>;
  latency_ms: { p50: number; p95: number };
  runtime_versions: Record<string, string>;
  generated_report_count: number;
  fallback_report_count: number;
}
