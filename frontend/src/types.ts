export type Mode = "analysis" | "gateway";
export type KnowledgeMode = "off" | "evidence" | "report";
export type KnowledgeStatus = "off" | "ready" | "unavailable" | "degraded";
export type ReportStatus = "off" | "generated" | "fallback" | "unavailable";
export type KnowledgePublisher = "owasp" | "mitre" | "nist" | "cac";
export type RiskDomain =
  | "prompt_injection"
  | "jailbreak"
  | "sensitive_information"
  | "excessive_agency"
  | "supply_chain"
  | "data_model_poisoning"
  | "unbounded_resource_consumption"
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
  lab?: {
    enabled: boolean;
    ready: boolean;
    reason: "disabled" | "unavailable" | "ready";
  };
  superagent?: {
    ready: boolean;
    internal_only: true;
    max_tool_calls: 3;
    max_trace_events: 12;
  };
}

export type LabToolId = "gateway_enforcement" | "security_case" | "evidence_bundle";
export type LabExecutionStatus = "succeeded" | "failed";

export interface LabToolExecution {
  execution_id: string;
  run_id: string;
  tool_id: LabToolId;
  status: LabExecutionStatus;
  effective_action: Decision;
  receipt_id: string | null;
  artifact_id: string | null;
  error_code: string | null;
  latency_ms: number;
  created_at: string;
  evidence_sha256: string | null;
}
export type LabCounterfactualInterpretation =
  | "risk_reduced"
  | "unchanged"
  | "inconclusive";

export interface LabScenario {
  scenario_id: string;
  label: string;
  scenario_kind: "synthetic" | "protected";
  attack_family: string | null;
  ready: boolean;
  public_input?: LabScenarioPublicInput;
}

export interface LabScenarioPublicInput {
  disclosure: "full" | "redacted";
  content: string;
  intent_summary: string;
  redaction_notice: string | null;
}

export interface LabStage {
  stage_id:
    | "semantic_guard"
    | "token_observation"
    | "entropy_cpd"
    | "fixed_fusion"
    | "knowledge_retrieval";
  status: "succeeded" | "unavailable";
  latency_ms: number | null;
  timing_basis: "measured" | "combined" | "unavailable";
  summary: string;
}

export interface LabPublicSignal {
  index: number;
  entropy: number;
  nll: number;
  cpd_entropy: number;
  cpd_nll: number;
  risk: number;
}

export interface LabDetectionSnapshot {
  decision: Decision;
  risk_score: number;
  detector_score: number;
  detector_status: DetectorStatus;
  semantic_severity: SemanticSeverity;
  semantic_categories: SemanticCategory[];
  semantic_model_id: string;
  semantic_model_version: string;
  semantic_latency_ms: number;
  fusion_reason: FusionReason;
  suspicious_span: AnalysisResult["suspicious_span"];
  signals: LabPublicSignal[];
  provenance: AnalysisResult["provenance"];
  latency_ms: number;
  knowledge_status: KnowledgeStatus;
  knowledge_snapshot_version: string | null;
  knowledge_latency_ms: number;
  knowledge_evidence: KnowledgeEvidence[];
  report_status: ReportStatus;
}

export interface LabCounterfactualSnapshot {
  semantic_severity: SemanticSeverity;
  detector_status: DetectorStatus;
  risk_score: number;
  detector_score: number;
  decision: Decision;
  latency_ms: number;
}

export interface LabCounterfactualResult {
  interpretation: LabCounterfactualInterpretation;
  reason:
    | "completed"
    | "no_predicted_onset"
    | "invalid_predicted_onset"
    | "provenance_mismatch"
    | "recheck_failed";
  char_start: number | null;
  calibration_version: string;
  original: LabCounterfactualSnapshot;
  rechecked: LabCounterfactualSnapshot | null;
  risk_score_delta: number | null;
  detector_score_delta: number | null;
  action_changed: boolean;
}

export interface LabToolPlan {
  tool_id: LabToolId;
  title: string;
  status: "planned";
  effective_action: Decision;
  artifact_summary: string;
  knowledge_ids: string[];
}

export interface LabToolResult {
  tool_id: LabToolId;
  status: "succeeded" | "failed";
  error_code: "simulated_tool_failure" | null;
  latency_ms: number;
  effective_action: Decision;
  artifact_summary: string;
  evidence_sha256: string | null;
}

export interface LabCaseReport {
  report_status: "deterministic" | "fallback";
  summary: string;
  evidence_ids: string[];
  handling_steps: string[];
  limitations: string[];
  tool_statuses: Partial<Record<LabToolId, "succeeded" | "failed">>;
}

export interface LabRunResult {
  run_id: string;
  status: "completed";
  scenario_id: string;
  scenario_kind: "custom" | "synthetic" | "protected";
  scenario_label: string;
  attack_family: string | null;
  mode: Mode;
  created_at: string;
  stages: LabStage[];
  detection: LabDetectionSnapshot;
  counterfactual: LabCounterfactualResult;
  tool_plans: LabToolPlan[];
  tool_results: LabToolResult[];
  case_report: LabCaseReport;
}

export interface LabMetrics {
  run_count: number;
  counterfactual_eligible_count: number;
  counterfactual_executed_count: number;
  counterfactual_execution_rate: number;
  evidence_agreement_count: number;
  evidence_conflict_count: number;
  evidence_conflict_rate: number;
  tool_success_count: number;
  tool_failure_count: number;
  tool_success_rate: number;
  report_generated_count: number;
  report_fallback_count: number;
  confirmed_execution_count: number;
  preserved_action_execution_count: number;
  action_preservation_rate: number | null;
  latency_ms: { p50: number; p95: number };
  privacy_violation_count: number;
}

export type SuperAgentObjective = "investigate_and_respond";
export type SuperAgentFinalStatus = "closed_safe" | "contained" | "review_required" | "degraded";
export type SuperAgentTracePhase = "plan" | "act" | "observe" | "replan" | "complete";
export type SuperAgentActor =
  | "coordinator"
  | "semantic_analyst"
  | "token_analyst"
  | "knowledge_analyst"
  | "response_operator";
export type SuperAgentEventStatus = "planned" | "succeeded" | "failed" | "skipped";

export interface SuperAgentCapabilities {
  ready: true;
  internal_only: true;
  objectives: SuperAgentObjective[];
  actors: SuperAgentActor[];
  max_tool_calls: 3;
  max_trace_events: 12;
  replanning_limit: 1;
}

export interface SuperAgentMissionRequest {
  objective: SuperAgentObjective;
  scenario_kind: "frozen";
  sample_id: string;
  mode: Mode;
}

export interface SuperAgentPlanStep {
  sequence: number;
  actor: SuperAgentActor;
  action_code: string;
  summary: string;
}

export interface SuperAgentTraceEvent {
  sequence: number;
  phase: SuperAgentTracePhase;
  actor: SuperAgentActor;
  status: SuperAgentEventStatus;
  summary: string;
  evidence_codes: string[];
  tool_id: LabToolId | null;
}

export interface SuperAgentExecutionReference {
  execution_id: string;
  tool_id: LabToolId;
  status: LabExecutionStatus;
  source_action: Decision;
  effective_action: Decision;
  receipt_id: string | null;
  artifact_id: string | null;
  evidence_sha256: string | null;
}

export interface SuperAgentMissionResult {
  mission_id: string;
  run_id: string;
  objective: SuperAgentObjective;
  scenario_id: string;
  scenario_label: string;
  attack_family: string | null;
  mode: Mode;
  base_action: Decision;
  final_status: SuperAgentFinalStatus;
  initial_plan: SuperAgentPlanStep[];
  final_plan: LabToolId[];
  events: SuperAgentTraceEvent[];
  executions: SuperAgentExecutionReference[];
  limitations: string[];
  created_at: string;
}

export type PcapActor =
  | "coordinator"
  | "network_evidence_analyst"
  | "knowledge_analyst"
  | "response_operator";
export type PcapMissionStatus = "queued" | "running" | "completed" | "cancelled" | "degraded";
export type PcapCapability = "token_eligible" | "traffic_only" | "insufficient_evidence";
export type PcapEventStatus = "queued" | "running" | "succeeded" | "failed" | "skipped";
export type PcapPublicNarrative =
  | "batch_triage_completed"
  | "coordinator_plan"
  | "cpd_evidence_unavailable"
  | "deterministic_response_ready"
  | "encrypted_transport_observed"
  | "evidence_level_validated"
  | "insufficient_evidence"
  | "no_packet_payload_retained"
  | "plaintext_application_protocol_observed"
  | "plaintext_application_protocol_candidate_not_proven_llm_traffic"
  | "retain_public_metadata"
  | "token_evidence_unavailable"
  | "tool_authorization_accepted"
  | "traffic_only_evidence";

export interface PcapOverview {
  enabled: boolean;
  pending_file_count: number;
  tool_id: "pcap_batch_triage";
  max_batch_size: 20;
  max_trace_events: 12;
  actors: PcapActor[];
}

export interface PcapAuthorizationRequest { confirmed: true; max_files: number; }
export interface PcapAuthorizationReceipt { authorization_id: string; max_files: number; }
export interface PcapMissionRequest {
  objective: "triage_pcap_evidence";
  authorization_id: string;
}

export interface PcapVisibility {
  plaintext_application_protocol_observed: boolean;
  encrypted_transport_observed: boolean;
  tls_observed: boolean;
  quic_observed: boolean;
}

export interface PcapCaptureEvidence {
  capture_id: string;
  status: "succeeded" | "failed" | "skipped";
  packet_count: number;
  protocol_counts: Record<string, number>;
  visibility: PcapVisibility;
  capability: PcapCapability | null;
  error_code: string | null;
}

export interface PcapBatchSummary {
  schema_version: 1;
  batch_id: string;
  selected_count: number;
  succeeded_count: number;
  failed_count: number;
  skipped_count: number;
  captures: PcapCaptureEvidence[];
}

export interface PcapTraceEvent {
  sequence: number;
  actor: PcapActor;
  status: PcapEventStatus;
  summary: PcapPublicNarrative;
  tool_id: "pcap_batch_triage" | null;
}

export interface PcapMissionReport {
  confirmed: PcapPublicNarrative[];
  candidates: PcapPublicNarrative[];
  unknowns: PcapPublicNarrative[];
  recommended_action: PcapPublicNarrative[];
}

export interface PcapMissionResult {
  mission_id: string;
  objective: "triage_pcap_evidence";
  status: PcapMissionStatus;
  batch_id: string;
  events: PcapTraceEvent[];
  summary: PcapBatchSummary | null;
  report: PcapMissionReport;
  limitations: PcapPublicNarrative[];
  created_at: string;
}

export interface PcapReconOverview {
  enabled: boolean;
  eligible_file_count: number;
  sample_limit: number;
  sampling_method: "size_quartile_v1";
}

export interface PcapReconAuthorizationRequest { confirmed: true; sample_limit: number; }
export interface PcapReconAuthorizationReceipt { authorization_id: string; max_files: number; }
export interface PcapReconMissionRequest {
  objective: "reconnoiter_pcap_dataset";
  authorization_id: string;
}

export interface PcapReconHistogram { [bucket: string]: number }
export interface PcapReconSummary {
  schema_version: 1;
  sampled_count: number;
  succeeded_count: number;
  failed_count: number;
  quartile_counts: { quartile_1: number; quartile_2: number; quartile_3: number; quartile_4: number };
  size_bucket_counts: PcapReconHistogram;
  packet_bucket_counts: PcapReconHistogram;
  duration_bucket_counts: PcapReconHistogram;
  protocol_presence_counts: Record<string, number>;
  plaintext_sample_count: number;
  encrypted_sample_count: number;
  sequence_candidate_count: number;
}

export type PcapReconNarrative = "authorization_accepted" | "quartile_sample_selected" | "isolated_full_capture_scan_running" | "aggregate_profile_validated" | "method_selection_checkpoint_ready";
export interface PcapReconTraceEvent {
  sequence: number;
  actor: PcapActor;
  status: PcapEventStatus;
  summary: PcapReconNarrative;
}
export interface PcapReconMissionResult {
  recon_id: string;
  objective: "reconnoiter_pcap_dataset";
  status: PcapMissionStatus;
  events: PcapReconTraceEvent[];
  summary: PcapReconSummary | null;
  failure_code: "tool_failed" | "tool_timeout" | "report_invalid" | null;
  created_at: string;
}

export interface PcapDetectionOverview {
  enabled: boolean;
  eligible_file_count: number;
  max_files: 20;
  localization: "request_or_packet";
}
export interface PcapDetectionAuthorizationRequest { confirmed: true; max_files: number; }
export interface PcapUploadCapability { enabled: boolean; max_bytes: number; accepted_formats: Array<"pcap" | "pcapng">; }
export interface PcapUploadAuthorizationRequest { confirmed: true; byte_count: number; }
export interface PcapDetectionMissionRequest {
  objective: "detect_pcap_anomalies";
  authorization_id: string;
  start_index?: number;
}
export type PcapDetectionGranularity = "packet" | "request" | "flow_event" | "llm_token";
export type PcapDetectionCandidate = "sql_injection" | "command_injection" | "path_traversal" | "web_injection" | "none";
export type PcapPurposeCandidate = "auth_bypass" | "data_probing" | "data_extraction" | "blind_probing" | "internal_access" | "script_execution";
export type PcapDetectionSignal = "sql_syntax_pattern" | "command_syntax_pattern" | "path_traversal_pattern" | "request_boundary" | "connection_rate_increase" | "destination_density_increase" | "change_point_detected" | "semantic_risk_detected" | "xss_pattern" | "template_injection_pattern" | "ssrf_pattern" | "http_anomaly_pattern";
export interface PcapLocalizedEvidence {
  evidence_id: string;
  granularity: PcapDetectionGranularity;
  verified_packet_count: number;
  start_packet: number;
  end_packet: number;
  start_offset_ms: number;
  end_offset_ms: number;
  attack_candidate: PcapDetectionCandidate;
  detector: "http_rule" | "behavior_anomaly" | "cpd" | "semantic_token";
  confidence: number;
  supporting_signals: PcapDetectionSignal[];
  purpose_candidates: PcapPurposeCandidate[];
}
export type PcapDetectionNarrative = "authorization_accepted" | "isolated_http_scan_running" | "localized_evidence_validated" | "deterministic_fusion_ready";
export interface PcapDetectionTraceEvent { sequence: number; actor: PcapActor; status: PcapEventStatus; summary: PcapDetectionNarrative; }
export interface PcapProcessedSample { sample_index: number; status: "succeeded" | "failed"; evidence_count: number; failure_code: "tool_failed" | "tool_timeout" | "report_invalid" | "capture_invalid" | null; }
export interface PcapDetectionSummary { schema_version: 1; analyzed_count: number; succeeded_count: number; failed_count: number; evidence: PcapLocalizedEvidence[]; processed_samples: PcapProcessedSample[]; }
export interface PcapDetectionReport { confirmed_evidence_ids: string[]; candidate_evidence_ids: string[]; unknowns: ("no_localized_attack_evidence" | "partial_file_failure")[]; recommended_actions: ("allow_no_rule_evidence" | "review_localized_requests" | "retry_failed_files")[]; }
export interface PcapDetectionMissionResult { detection_id: string; objective: "detect_pcap_anomalies"; status: PcapMissionStatus; events: PcapDetectionTraceEvent[]; summary: PcapDetectionSummary | null; report: PcapDetectionReport; failure_code: "tool_failed" | "tool_timeout" | "report_invalid" | null; created_at: string; }

export type SuperAgentStoredMission = SuperAgentMissionResult | PcapMissionResult | PcapReconMissionResult | PcapDetectionMissionResult;

export type LabRunRequest =
  | { scenario_kind: "custom"; custom_input: string; mode: Mode }
  | { scenario_kind: "frozen"; sample_id: string; mode: Mode };

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
  agent_ablation?: AgentAblationReport | null;
}

export interface PcapEvaluationMetrics {
  sample_count: number;
  true_positive: number;
  false_positive: number;
  false_negative: number;
  true_negative: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  localization_hit_rate: number;
}

export interface PcapEvaluationSummary {
  schema_version: 1;
  benchmark_version: string;
  dataset_kind: "synthetic_sanitized_regression";
  generated_at: string;
  sample_count: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  localization_hit_rate: number;
  ablations: Record<"rule_only" | "behavior_only" | "fused", PcapEvaluationMetrics>;
}

export type AblationMethod = "semantic_only" | "cpd_only" | "fusion";
export type AblationOperatingPoint = "production" | "fpr_10" | "fpr_05";
export type AblationDomain =
  | "benign_plain"
  | "benign_shift"
  | "semantic_unsafe"
  | "optimized_suffix";
export type SourceCoverageStatus = "verified" | "unverified" | "source_unavailable";

export interface AblationClassificationMetrics {
  true_positive: number;
  false_positive: number;
  true_negative: number;
  false_negative: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
}

export interface AblationDomainMetrics {
  count: number;
  detected: number;
  recall: number | null;
  false_positive_rate: number | null;
}

export interface AblationMethodReport {
  method: AblationMethod;
  operating_point: AblationOperatingPoint;
  constraint_max_fpr: number | null;
  constraint_satisfied: boolean;
  metrics: AblationClassificationMetrics;
  domain_metrics: Partial<Record<AblationDomain, AblationDomainMetrics>>;
  family_metrics: Record<string, { count: number; detected: number; recall: number }>;
  action_counts: { allow: number; review: number; block: number };
  latency: { p50_ms: number; p95_ms: number };
  localization: {
    eligible_count: number;
    predicted_count: number;
    onset_mae: number | null;
    trigger_in_suffix_rate: number;
  } | null;
}

export interface AgentAblationReport {
  schema_version: 1;
  benchmark_version: string;
  dataset_hash: string;
  requested_count: number;
  completed_count: number;
  failed_count: number;
  failure_counts: Record<string, number>;
  source_coverage: Record<string, SourceCoverageStatus>;
  coverage_gaps: string[];
  methods: AblationMethodReport[];
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
