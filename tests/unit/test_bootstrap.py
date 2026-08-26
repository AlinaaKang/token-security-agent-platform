from __future__ import annotations

from pathlib import Path

import pytest

from app.bootstrap import KnowledgeConfig, GuardConfig, ServiceConfig, load_service_bundle
from app.detection.calibration import CalibrationProfile
from app.detection.cpd import RobustBaseline
from app.model.runtime import RuntimeReadiness, hash_system_prompt
from app.semantic.runtime import SemanticGuardReadiness


class FakeRuntime:
    def __init__(self, *, model_id: str, max_input_tokens: int) -> None:
        self.model_id = model_id
        self.max_input_tokens = max_input_tokens
        self.loaded = False

    def load(self) -> None:
        self.loaded = True

    def readiness(self) -> RuntimeReadiness:
        return RuntimeReadiness(
            ready=self.loaded,
            model_id=self.model_id,
            tokenizer_id="qwen-tokenizer",
        )


class FakeGuard:
    def __init__(
        self,
        *,
        model_id: str,
        model_version: str,
        max_input_tokens: int,
        max_new_tokens: int,
    ) -> None:
        self.model_id = model_id
        self.model_version = model_version
        self.max_input_tokens = max_input_tokens
        self.max_new_tokens = max_new_tokens
        self.loaded = False

    def load(self) -> None:
        self.loaded = True

    def readiness(self) -> SemanticGuardReadiness:
        return SemanticGuardReadiness(
            ready=self.loaded,
            model_id=self.model_id,
            model_version=self.model_version,
        )


def write_calibration(path: Path, *, model_id: str) -> None:
    profile = CalibrationProfile(
        version="demo-v1",
        model_id=model_id,
        tokenizer_id="qwen-tokenizer",
        system_prompt_hash=hash_system_prompt("Answer requests concisely."),
        signal="entropy",
        baseline=RobustBaseline(median=1.0, mad_scale=0.5),
        k=0.5,
        h=5.0,
        created_at="2026-08-25T00:00:00Z",
        dataset_hash="sha256:benign-prompts",
    )
    path.write_text(profile.model_dump_json(), encoding="utf-8")


def test_service_config_requires_model_and_calibration_together() -> None:
    with pytest.raises(ValueError, match="together"):
        ServiceConfig.from_environ({"TOKEN_SECURITY_MODEL_PATH": "/models/qwen"})


def test_knowledge_config_reads_bounded_defaults() -> None:
    config = KnowledgeConfig.from_environ(
        {"TOKEN_SECURITY_KNOWLEDGE_SNAPSHOT_PATH": "knowledge/snapshots/official-v1"}
    )

    assert config is not None
    assert config.max_results == 3
    assert config.report_max_new_tokens == 256
    assert config.report_max_time_seconds == 3.0


@pytest.mark.parametrize(
    "environ",
    [
        {"TOKEN_SECURITY_GUARD_MODEL_PATH": "/models/qwen-guard"},
        {"TOKEN_SECURITY_GUARD_MODEL_VERSION": "revision-id"},
    ],
)
def test_guard_config_requires_path_and_version_together(environ) -> None:
    with pytest.raises(ValueError, match="configured together"):
        GuardConfig.from_environ(environ)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("TOKEN_SECURITY_GUARD_MAX_INPUT_TOKENS", "0"),
        ("TOKEN_SECURITY_GUARD_MAX_INPUT_TOKENS", "4097"),
        ("TOKEN_SECURITY_GUARD_MAX_NEW_TOKENS", "0"),
        ("TOKEN_SECURITY_GUARD_MAX_NEW_TOKENS", "33"),
    ],
)
def test_guard_config_rejects_token_limits_outside_bounds(
    name: str,
    value: str,
) -> None:
    environ = {
        "TOKEN_SECURITY_GUARD_MODEL_PATH": "/models/qwen-guard",
        "TOKEN_SECURITY_GUARD_MODEL_VERSION": "revision-id",
        name: value,
    }

    with pytest.raises(ValueError, match="between"):
        GuardConfig.from_environ(environ)


def test_service_bundle_loads_runtime_and_reports_ready() -> None:
    calibration_path = Path("tmp/test-bootstrap-ready.json")
    calibration_path.parent.mkdir(exist_ok=True)
    try:
        write_calibration(calibration_path, model_id="/models/qwen")
        config = ServiceConfig(
            model_path="/models/qwen",
            calibration_path=calibration_path,
            system_prompt="Answer requests concisely.",
            max_input_tokens=512,
        )

        bundle = load_service_bundle(config, runtime_factory=FakeRuntime)
    finally:
        calibration_path.unlink(missing_ok=True)

    assert bundle.workflow.runtime.loaded is True
    assert bundle.workflow.runtime.max_input_tokens == 512
    assert bundle.health == {
        "status": "degraded",
        "api": {"ready": True},
        "model": {"ready": True, "model_id": "/models/qwen"},
        "detector": {"ready": True, "calibration_version": "demo-v1"},
        "semantic_guard": {
            "ready": False,
            "model_id": "unconfigured",
            "model_version": "unconfigured",
        },
        "knowledge": {
            "ready": False,
            "snapshot_version": None,
            "card_count": 0,
            "generator_ready": False,
        },
    }


def test_service_bundle_loads_configured_semantic_guard() -> None:
    calibration_path = Path("tmp/test-bootstrap-guard-ready.json")
    calibration_path.parent.mkdir(exist_ok=True)
    try:
        write_calibration(calibration_path, model_id="/models/qwen")
        config = ServiceConfig(
            model_path="/models/qwen",
            calibration_path=calibration_path,
            guard=GuardConfig(
                model_path="/models/qwen-guard",
                model_version="revision-id",
                max_input_tokens=1024,
                max_new_tokens=16,
            ),
        )

        bundle = load_service_bundle(
            config,
            runtime_factory=FakeRuntime,
            guard_factory=FakeGuard,
        )
    finally:
        calibration_path.unlink(missing_ok=True)

    assert bundle.workflow.semantic_guard.loaded is True
    assert bundle.health["status"] == "ok"
    assert bundle.health["semantic_guard"] == {
        "ready": True,
        "model_id": "/models/qwen-guard",
        "model_version": "revision-id",
    }


def test_service_bundle_loads_optional_knowledge_snapshot() -> None:
    calibration_path = Path("tmp/test-bootstrap-knowledge-ready.json")
    calibration_path.parent.mkdir(exist_ok=True)
    try:
        write_calibration(calibration_path, model_id="/models/qwen")
        config = ServiceConfig(
            model_path="/models/qwen",
            calibration_path=calibration_path,
            knowledge=KnowledgeConfig(
                snapshot_path=Path("knowledge/snapshots/official-v1")
            ),
        )
        bundle = load_service_bundle(config, runtime_factory=FakeRuntime)
    finally:
        calibration_path.unlink(missing_ok=True)

    assert bundle.health["knowledge"] == {
        "ready": True,
        "snapshot_version": "official-v1",
        "card_count": 12,
        "generator_ready": True,
    }


def test_invalid_knowledge_snapshot_does_not_block_basic_bundle() -> None:
    calibration_path = Path("tmp/test-bootstrap-knowledge-missing.json")
    calibration_path.parent.mkdir(exist_ok=True)
    try:
        write_calibration(calibration_path, model_id="/models/qwen")
        config = ServiceConfig(
            model_path="/models/qwen",
            calibration_path=calibration_path,
            knowledge=KnowledgeConfig(snapshot_path=Path("tmp/missing-snapshot")),
        )
        bundle = load_service_bundle(config, runtime_factory=FakeRuntime)
    finally:
        calibration_path.unlink(missing_ok=True)

    assert bundle.health["model"]["ready"] is True
    assert bundle.health["knowledge"]["ready"] is False


def test_service_bundle_rejects_calibration_for_other_system_prompt() -> None:
    calibration_path = Path("tmp/test-bootstrap-mismatch.json")
    calibration_path.parent.mkdir(exist_ok=True)
    try:
        write_calibration(calibration_path, model_id="/models/qwen")
        config = ServiceConfig(
            model_path="/models/qwen",
            calibration_path=calibration_path,
            system_prompt="A different system prompt.",
            max_input_tokens=512,
        )

        with pytest.raises(RuntimeError, match="system_prompt_hash"):
            load_service_bundle(config, runtime_factory=FakeRuntime)
    finally:
        calibration_path.unlink(missing_ok=True)
