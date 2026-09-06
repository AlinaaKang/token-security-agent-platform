from __future__ import annotations

import json

import pytest

from app.security_agent.playbooks import PlaybookInvalid, load_playbook_catalog
from app.security_agent.tools import build_registry


def catalog_payload() -> dict[str, object]:
    return {
        "version": "1.0.0",
        "playbooks": [{
            "playbook_id": "pcap_dataset_v1",
            "title": "PCAP 数据集调查",
            "task_type": "pcap_dataset_investigation",
            "description": "分批检查可解析性、异常候选与报告。",
            "steps": [
                {"step_id": "step_01", "tool_id": "inspect_pcap_dataset", "requires_authorization": True, "on_failure": "stop_for_review"},
                {"step_id": "step_02", "tool_id": "detect_pcap_batch", "requires_authorization": True, "on_failure": "retry_once"},
            ],
        }],
    }


def test_playbook_can_only_reference_registered_tools(tmp_path) -> None:
    payload = catalog_payload()
    payload["playbooks"][0]["steps"][0]["tool_id"] = "python_exec"  # type: ignore[index]
    path = tmp_path / "playbooks.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PlaybookInvalid, match="unknown tool"):
        load_playbook_catalog(path, build_registry({}))


def test_playbook_catalog_is_versioned_and_bounded(tmp_path) -> None:
    path = tmp_path / "playbooks.json"
    path.write_text(json.dumps(catalog_payload()), encoding="utf-8")

    catalog = load_playbook_catalog(path, build_registry({}))

    assert catalog.version == "1.0.0"
    assert catalog.playbooks[0].steps[1].on_failure == "retry_once"
    assert len(catalog.playbooks[0].steps) <= 12


def test_playbook_rejects_arbitrary_code_and_connector_urls(tmp_path) -> None:
    payload = catalog_payload()
    payload["playbooks"][0]["steps"][0]["code"] = "print('unsafe')"  # type: ignore[index]
    path = tmp_path / "playbooks.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(PlaybookInvalid):
        load_playbook_catalog(path, build_registry({}))
