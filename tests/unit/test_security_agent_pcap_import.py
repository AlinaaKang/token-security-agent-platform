from app.pcap.detection_models import PcapDetectionMissionResult
from app.security_agent.pcap_import import import_pcap_detection


def _mission() -> PcapDetectionMissionResult:
    return PcapDetectionMissionResult.model_validate({
        "detection_id": "detection_0123456789abcdef0123456789abcdef",
        "status": "completed",
        "events": [
            {"sequence": 1, "actor": "coordinator", "status": "succeeded", "summary": "authorization_accepted"},
            {"sequence": 2, "actor": "network_evidence_analyst", "status": "succeeded", "summary": "isolated_http_scan_running"},
            {"sequence": 3, "actor": "knowledge_analyst", "status": "succeeded", "summary": "localized_evidence_validated"},
            {"sequence": 4, "actor": "response_operator", "status": "succeeded", "summary": "deterministic_fusion_ready"},
        ],
        "summary": {
            "analyzed_count": 2, "succeeded_count": 1, "failed_count": 1,
            "evidence": [{
                "evidence_id": "evidence_0123456789abcdef0123456789abcdef",
                "granularity": "request", "verified_packet_count": 8,
                "start_packet": 4, "end_packet": 4,
                "start_offset_ms": 120, "end_offset_ms": 128,
                "attack_candidate": "sql_injection", "detector": "http_rule",
                "confidence": 0.95,
                "supporting_signals": ["sql_syntax_pattern", "request_boundary"],
                "purpose_candidates": ["data_probing"],
            }],
        },
        "report": {
            "confirmed_evidence_ids": ["evidence_0123456789abcdef0123456789abcdef"],
            "candidate_evidence_ids": [],
            "unknowns": ["partial_file_failure"],
            "recommended_actions": ["review_localized_requests", "retry_failed_files"],
        },
        "failure_code": None,
        "created_at": "2026-09-07T10:00:00Z",
    })


def test_import_maps_only_public_packet_evidence() -> None:
    imported = import_pcap_detection(_mission())

    assert imported.final_status == "risk_found"
    assert imported.degraded is True
    assert imported.evidence[0].summary == "Packet 4 检出 SQL 注入候选，置信度 95%。"
    assert imported.evidence[0].metadata["start_packet"] == 4
    assert imported.hypotheses[0].supporting_evidence_refs == (
        "evidence_0123456789abcdef0123456789abcdef",
    )


def test_imported_shape_excludes_private_network_and_file_fields() -> None:
    encoded = import_pcap_detection(_mission()).model_dump_json().lower()

    for forbidden in ("filename", "file_path", "payload", "ip_address", '"port"'):
        assert forbidden not in encoded
