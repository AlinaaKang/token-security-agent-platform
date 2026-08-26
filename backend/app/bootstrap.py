from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.agent.fusion import EvidenceFusionPolicy
from app.agent.policy import BasicPolicy
from app.agent.workflow import BasicSecurityWorkflow
from app.detection.calibration import CalibrationProfile
from app.model.runtime import TransformersModelRuntime, hash_system_prompt
from app.semantic.runtime import QwenSemanticGuard, UnavailableSemanticGuard
from app.knowledge.loader import load_knowledge_snapshot
from app.knowledge.query import SafeQueryBuilder
from app.knowledge.reporting import QwenGroundedReportGenerator
from app.knowledge.retriever import LocalKnowledgeRetriever
from app.knowledge.service import KnowledgeService


DEFAULT_SYSTEM_PROMPT = "Answer requests concisely."


def lab_enabled_from_environ(environ: Mapping[str, str]) -> bool:
    value = environ.get("TOKEN_SECURITY_LAB_ENABLED", "").strip().casefold()
    return value in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class KnowledgeConfig:
    snapshot_path: Path
    max_results: int = 3
    report_max_new_tokens: int = 256
    report_max_time_seconds: float = 3.0

    def __post_init__(self) -> None:
        if not 1 <= self.max_results <= 3:
            raise ValueError("knowledge max results must be between 1 and 3")
        if not 1 <= self.report_max_new_tokens <= 512:
            raise ValueError("knowledge report token limit must be between 1 and 512")
        if self.report_max_time_seconds <= 0:
            raise ValueError("knowledge report time limit must be positive")

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> KnowledgeConfig | None:
        value = environ.get("TOKEN_SECURITY_KNOWLEDGE_SNAPSHOT_PATH", "").strip()
        if not value:
            return None
        return cls(
            snapshot_path=Path(value),
            max_results=int(
                environ.get("TOKEN_SECURITY_KNOWLEDGE_MAX_RESULTS", "3")
            ),
            report_max_new_tokens=int(
                environ.get(
                    "TOKEN_SECURITY_KNOWLEDGE_REPORT_MAX_NEW_TOKENS", "256"
                )
            ),
            report_max_time_seconds=float(
                environ.get(
                    "TOKEN_SECURITY_KNOWLEDGE_REPORT_MAX_TIME_SECONDS", "3.0"
                )
            ),
        )


@dataclass(frozen=True)
class GuardConfig:
    model_path: str
    model_version: str
    max_input_tokens: int = 4096
    max_new_tokens: int = 32

    def __post_init__(self) -> None:
        if not self.model_path.strip() or not self.model_version.strip():
            raise ValueError("Guard model path and version must not be blank")
        if not 1 <= self.max_input_tokens <= 4096:
            raise ValueError("Guard max input tokens must be between 1 and 4096")
        if not 1 <= self.max_new_tokens <= 32:
            raise ValueError("Guard max new tokens must be between 1 and 32")

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> GuardConfig | None:
        model_path = environ.get("TOKEN_SECURITY_GUARD_MODEL_PATH", "").strip()
        model_version = environ.get(
            "TOKEN_SECURITY_GUARD_MODEL_VERSION", ""
        ).strip()
        if not model_path and not model_version:
            return None
        if not model_path or not model_version:
            raise ValueError(
                "TOKEN_SECURITY_GUARD_MODEL_PATH and "
                "TOKEN_SECURITY_GUARD_MODEL_VERSION must be configured together"
            )
        return cls(
            model_path=model_path,
            model_version=model_version,
            max_input_tokens=int(
                environ.get("TOKEN_SECURITY_GUARD_MAX_INPUT_TOKENS", "4096")
            ),
            max_new_tokens=int(
                environ.get("TOKEN_SECURITY_GUARD_MAX_NEW_TOKENS", "32")
            ),
        )


def event_db_path_from_environ(environ: Mapping[str, str]) -> Path:
    value = environ.get(
        "TOKEN_SECURITY_EVENT_DB_PATH", "tmp/security-events.sqlite3"
    ).strip()
    if not value:
        raise ValueError("TOKEN_SECURITY_EVENT_DB_PATH must not be blank")
    return Path(value)


def benchmark_report_path_from_environ(
    environ: Mapping[str, str],
) -> Path | None:
    value = environ.get("TOKEN_SECURITY_BENCHMARK_REPORT_PATH", "").strip()
    return Path(value) if value else None


def knowledge_evaluation_report_path_from_environ(
    environ: Mapping[str, str],
) -> Path | None:
    value = environ.get(
        "TOKEN_SECURITY_KNOWLEDGE_EVALUATION_REPORT_PATH", ""
    ).strip()
    return Path(value) if value else None


@dataclass(frozen=True)
class AgentAblationPaths:
    manifest_path: Path
    report_path: Path


def agent_ablation_paths_from_environ(
    environ: Mapping[str, str],
) -> AgentAblationPaths | None:
    manifest = environ.get(
        "TOKEN_SECURITY_AGENT_ABLATION_MANIFEST_PATH", ""
    ).strip()
    report = environ.get("TOKEN_SECURITY_AGENT_ABLATION_REPORT_PATH", "").strip()
    if not manifest and not report:
        return None
    if not manifest or not report:
        raise ValueError(
            "TOKEN_SECURITY_AGENT_ABLATION_MANIFEST_PATH and "
            "TOKEN_SECURITY_AGENT_ABLATION_REPORT_PATH must be configured together"
        )
    return AgentAblationPaths(
        manifest_path=Path(manifest), report_path=Path(report)
    )


@dataclass(frozen=True)
class DemoSourcePaths:
    autodan_csv: Path
    advprompter_csv: Path
    gcg_csv: Path


def demo_source_paths_from_environ(
    environ: Mapping[str, str],
) -> DemoSourcePaths | None:
    names = {
        "autodan_csv": "TOKEN_SECURITY_DEMO_AUTODAN_CSV",
        "advprompter_csv": "TOKEN_SECURITY_DEMO_ADVPROMPTER_CSV",
        "gcg_csv": "TOKEN_SECURITY_DEMO_GCG_CSV",
    }
    values = {field: environ.get(name, "").strip() for field, name in names.items()}
    configured = [bool(value) for value in values.values()]
    if not any(configured):
        return None
    if not all(configured):
        raise ValueError("all TOKEN_SECURITY_DEMO_*_CSV paths must be configured")
    return DemoSourcePaths(**{field: Path(value) for field, value in values.items()})


@dataclass(frozen=True)
class ServiceConfig:
    model_path: str
    calibration_path: Path
    system_prompt: str = DEFAULT_SYSTEM_PROMPT
    max_input_tokens: int = 4096
    event_db_path: Path = Path("tmp/security-events.sqlite3")
    benchmark_report_path: Path | None = None
    guard: GuardConfig | None = None
    knowledge: KnowledgeConfig | None = None

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> ServiceConfig | None:
        guard = GuardConfig.from_environ(environ)
        knowledge = KnowledgeConfig.from_environ(environ)
        model_path = environ.get("TOKEN_SECURITY_MODEL_PATH", "").strip()
        calibration_value = environ.get("TOKEN_SECURITY_CALIBRATION_PATH", "").strip()
        if not model_path and not calibration_value:
            return None
        if not model_path or not calibration_value:
            raise ValueError(
                "TOKEN_SECURITY_MODEL_PATH and TOKEN_SECURITY_CALIBRATION_PATH "
                "must be configured together"
            )
        return cls(
            model_path=model_path,
            calibration_path=Path(calibration_value),
            system_prompt=environ.get(
                "TOKEN_SECURITY_SYSTEM_PROMPT", DEFAULT_SYSTEM_PROMPT
            ),
            max_input_tokens=int(
                environ.get("TOKEN_SECURITY_MAX_INPUT_TOKENS", "4096")
            ),
            event_db_path=event_db_path_from_environ(environ),
            benchmark_report_path=benchmark_report_path_from_environ(environ),
            guard=guard,
            knowledge=knowledge,
        )


@dataclass(frozen=True)
class ServiceBundle:
    workflow: BasicSecurityWorkflow
    health: dict[str, Any]


def load_service_bundle(
    config: ServiceConfig,
    *,
    runtime_factory: Callable[..., Any] = TransformersModelRuntime,
    guard_factory: Callable[..., Any] = QwenSemanticGuard,
) -> ServiceBundle:
    calibration = CalibrationProfile.model_validate_json(
        config.calibration_path.read_text(encoding="utf-8")
    )
    runtime = runtime_factory(
        model_id=config.model_path,
        max_input_tokens=config.max_input_tokens,
    )
    runtime.load()
    readiness = runtime.readiness()
    if not readiness.ready or readiness.tokenizer_id is None:
        raise RuntimeError("model runtime did not become ready after loading")
    calibration.ensure_compatible(
        model_id=readiness.model_id,
        tokenizer_id=readiness.tokenizer_id,
        system_prompt_hash=hash_system_prompt(config.system_prompt),
    )
    if config.guard is None:
        semantic_guard = UnavailableSemanticGuard()
    else:
        semantic_guard = guard_factory(
            model_id=config.guard.model_path,
            model_version=config.guard.model_version,
            max_input_tokens=config.guard.max_input_tokens,
            max_new_tokens=config.guard.max_new_tokens,
        )
        semantic_guard.load()
    guard_readiness = semantic_guard.readiness()
    if config.guard is not None and not guard_readiness.ready:
        raise RuntimeError("semantic Guard did not become ready after loading")
    knowledge_service = None
    knowledge_health = {
        "ready": False,
        "snapshot_version": None,
        "card_count": 0,
        "generator_ready": False,
    }
    if config.knowledge is not None:
        try:
            snapshot = load_knowledge_snapshot(config.knowledge.snapshot_path)
            retriever = LocalKnowledgeRetriever(snapshot)
            generator = QwenGroundedReportGenerator(
                runtime,
                max_new_tokens=config.knowledge.report_max_new_tokens,
                max_time_seconds=config.knowledge.report_max_time_seconds,
            )
            knowledge_service = KnowledgeService(
                snapshot_version=snapshot.manifest.snapshot_version,
                query_builder=SafeQueryBuilder(),
                retriever=retriever,
                generator=generator,
                max_results=config.knowledge.max_results,
            )
            knowledge_health = {
                "ready": True,
                "snapshot_version": snapshot.manifest.snapshot_version,
                "card_count": len(snapshot.cards),
                "generator_ready": readiness.ready,
            }
        except Exception:
            knowledge_service = None
    workflow = BasicSecurityWorkflow(
        runtime=runtime,
        calibration=calibration,
        policy=BasicPolicy(review_threshold=0.5, block_threshold=0.8),
        semantic_guard=semantic_guard,
        fusion_policy=EvidenceFusionPolicy(),
        system_prompt=config.system_prompt,
        knowledge_service=knowledge_service,
    )
    return ServiceBundle(
        workflow=workflow,
        health={
            "status": "ok" if guard_readiness.ready else "degraded",
            "api": {"ready": True},
            "model": {"ready": True, "model_id": readiness.model_id},
            "detector": {
                "ready": True,
                "calibration_version": calibration.version,
            },
            "semantic_guard": guard_readiness.model_dump(mode="json"),
            "knowledge": knowledge_health,
        },
    )
