from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.schemas import NonEmptyText
from app.security_agent.tools import SecurityToolRegistry


class PlaybookInvalid(ValueError):
    pass


class PlaybookStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    step_id: str = Field(pattern=r"^step_[0-9]{2}$")
    tool_id: NonEmptyText
    requires_authorization: bool = False
    on_failure: Literal["stop_for_review", "retry_once", "continue_degraded"]


class SecurityPlaybook(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    playbook_id: str = Field(pattern=r"^[a-z][a-z0-9_]{2,63}$")
    title: NonEmptyText
    task_type: Literal[
        "prompt_investigation",
        "pcap_dataset_investigation",
        "cross_domain_case",
        "report_generation",
    ]
    description: NonEmptyText
    steps: tuple[PlaybookStep, ...] = Field(min_length=1, max_length=12)


class SecurityPlaybookCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    playbooks: tuple[SecurityPlaybook, ...] = Field(min_length=1, max_length=12)


def load_playbook_catalog(
    path: Path, registry: SecurityToolRegistry
) -> SecurityPlaybookCatalog:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        catalog = SecurityPlaybookCatalog.model_validate(payload)
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        raise PlaybookInvalid("invalid security playbook catalog") from exc

    known_tools = set(registry.ids())
    seen_ids: set[str] = set()
    for playbook in catalog.playbooks:
        if playbook.playbook_id in seen_ids:
            raise PlaybookInvalid("duplicate playbook id")
        seen_ids.add(playbook.playbook_id)
        for step in playbook.steps:
            if step.tool_id not in known_tools:
                raise PlaybookInvalid(f"unknown tool in playbook: {step.tool_id}")
            spec = registry.spec(step.tool_id)
            if spec.permission_level != "read" and not step.requires_authorization:
                raise PlaybookInvalid(
                    f"authorization gate missing for tool: {step.tool_id}"
                )
    return catalog
