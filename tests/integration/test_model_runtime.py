from __future__ import annotations

import hashlib
import os
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

import app.model.runtime as model_runtime
from app.model.runtime import (
    ModelObservation,
    ModelUnavailableError,
    TransformersModelRuntime,
    hash_system_prompt,
)


def test_system_prompt_hash_is_stable_and_does_not_expose_prompt() -> None:
    system_prompt = "You are a concise assistant."

    digest = hash_system_prompt(system_prompt)

    assert digest == "sha256:" + hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
    assert system_prompt not in digest


def test_checkpoint_fingerprint_is_path_independent_and_content_bound(
    tmp_path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root in (first, second):
        (root / "weights").mkdir(parents=True)
        (root / "config.json").write_bytes(b'{"model":"fixed"}')
        (root / "weights" / "model.safetensors").write_bytes(b"weights-v1")

    first_fingerprint = model_runtime.fingerprint_checkpoint(first)
    second_fingerprint = model_runtime.fingerprint_checkpoint(second)
    (second / "weights" / "model.safetensors").write_bytes(b"weights-v2")

    assert first_fingerprint == second_fingerprint
    assert model_runtime.fingerprint_checkpoint(second) != first_fingerprint
    assert str(first) not in first_fingerprint
    assert str(second) not in second_fingerprint


def test_checkpoint_fingerprint_accepts_relative_and_absolute_directories(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checkpoint = tmp_path / "checkpoint"
    checkpoint.mkdir()
    (checkpoint / "model.safetensors").write_bytes(b"fixed-weights")
    monkeypatch.chdir(tmp_path)

    relative_fingerprint = model_runtime.fingerprint_checkpoint(
        Path("checkpoint")
    )
    absolute_fingerprint = model_runtime.fingerprint_checkpoint(
        checkpoint.resolve()
    )

    assert relative_fingerprint == absolute_fingerprint
    assert relative_fingerprint.startswith("sha256:")


def test_unloaded_runtime_reports_identity_and_not_ready() -> None:
    runtime = TransformersModelRuntime(model_id="Qwen/Qwen2.5-7B-Instruct")

    assert runtime.readiness().model_dump() == {
        "ready": False,
        "model_id": "Qwen/Qwen2.5-7B-Instruct",
        "tokenizer_id": None,
        "checkpoint_fingerprint": None,
    }
    with pytest.raises(ModelUnavailableError, match="not loaded"):
        runtime.score_prompt("System policy", "Summarize this report.")
    with pytest.raises(ModelUnavailableError, match="not loaded"):
        runtime.score_system_prompt("System policy")


def test_blank_prompt_is_rejected_before_model_availability_check() -> None:
    runtime = TransformersModelRuntime(model_id="Qwen/Qwen2.5-7B-Instruct")

    with pytest.raises(ValueError, match="blank"):
        runtime.score_prompt("System policy", "   ")


def test_model_observation_requires_system_entropy_evidence() -> None:
    with pytest.raises(ValidationError, match="system_entropies"):
        ModelObservation(
            model_id="model",
            tokenizer_id="tokenizer",
            system_prompt_hash="sha256:system",
            user_tokens=(),
            latency_ms=1.0,
        )


class StructuredFakeTensor:
    def __init__(self, values: list[list[int]]) -> None:
        self.values = values

    def __getitem__(self, index: int) -> list[int]:
        return self.values[index]

    def to(self, device: str) -> StructuredFakeTensor:
        return self


class StructuredFakeTokenizer:
    name_or_path = "fake-tokenizer"

    def __init__(self) -> None:
        self.decode_calls: list[list[int]] = []

    def apply_chat_template(self, messages: list[dict[str, str]], **kwargs: Any) -> str:
        return "FORMATTED_STRUCTURED_INPUT"

    def __call__(self, text: str, **kwargs: Any) -> dict[str, StructuredFakeTensor]:
        return {"input_ids": StructuredFakeTensor([[11, 12, 13]])}

    def decode(self, token_ids: list[int], **kwargs: Any) -> str:
        self.decode_calls.append(list(token_ids))
        return '{"summary":"safe"}'


class StructuredFakeModel:
    def __init__(self) -> None:
        self.generate_kwargs: dict[str, Any] | None = None

    def parameters(self):
        yield SimpleNamespace(device="cuda:0")

    def generate(self, **kwargs: Any) -> list[list[int]]:
        self.generate_kwargs = kwargs
        return [[11, 12, 13, 91, 92]]


class DeadlineAwareFakeModel(StructuredFakeModel):
    def __init__(self) -> None:
        super().__init__()
        self.deadline_result: Any | None = None

    def generate(self, **kwargs: Any) -> list[list[int]]:
        self.generate_kwargs = kwargs
        criterion = kwargs["stopping_criteria"][0]
        self.deadline_result = criterion(
            SimpleNamespace(shape=(1, 4), device="cuda:0"),
            None,
        )
        return [[11, 12, 13, 91, 92]]


class StructuredFakeTorch:
    @staticmethod
    def inference_mode():
        return nullcontext()


class SequenceClock:
    def __init__(self, values: list[float]) -> None:
        self._values = iter(values)

    def __call__(self) -> float:
        return next(self._values)


def test_structured_generation_is_bounded_and_decodes_only_continuation() -> None:
    runtime = TransformersModelRuntime(model_id="fake-model")
    tokenizer = StructuredFakeTokenizer()
    model = StructuredFakeModel()
    runtime._tokenizer = tokenizer
    runtime._model = model
    runtime._torch = StructuredFakeTorch()

    raw = runtime.generate_structured(
        [{"role": "system", "content": "fixed schema"}],
        max_new_tokens=256,
        max_time_seconds=3.0,
    )

    assert raw == '{"summary":"safe"}'
    assert tokenizer.decode_calls == [[91, 92]]
    assert model.generate_kwargs is not None
    assert model.generate_kwargs["do_sample"] is False
    assert model.generate_kwargs["max_new_tokens"] == 256
    assert model.generate_kwargs["max_time"] == 3.0


def test_structured_generation_classifies_deadline_return_as_timeout() -> None:
    runtime = TransformersModelRuntime(model_id="fake-model")
    tokenizer = StructuredFakeTokenizer()
    runtime._tokenizer = tokenizer
    runtime._model = StructuredFakeModel()
    runtime._torch = StructuredFakeTorch()
    runtime._clock = SequenceClock([10.0, 13.1])

    with pytest.raises(TimeoutError, match="structured generation timed out"):
        runtime.generate_structured(
            [{"role": "system", "content": "fixed schema"}],
            max_new_tokens=256,
            max_time_seconds=3.0,
        )

    assert tokenizer.decode_calls == []


def test_structured_generation_uses_token_step_deadline_before_decoding() -> None:
    runtime = TransformersModelRuntime(model_id="fake-model")
    tokenizer = StructuredFakeTokenizer()
    model = DeadlineAwareFakeModel()
    runtime._tokenizer = tokenizer
    runtime._model = model
    runtime._torch = StructuredFakeTorch()
    runtime._clock = SequenceClock([10.0, 13.1, 13.1])

    with pytest.raises(TimeoutError, match="structured generation timed out"):
        runtime.generate_structured(
            [{"role": "system", "content": "fixed schema"}],
            max_new_tokens=256,
            max_time_seconds=3.0,
        )

    assert model.deadline_result is True
    assert tokenizer.decode_calls == []


def test_structured_generation_requires_loaded_runtime() -> None:
    runtime = TransformersModelRuntime(model_id="fake-model")

    with pytest.raises(ModelUnavailableError, match="not loaded"):
        runtime.generate_structured(
            [{"role": "system", "content": "fixed schema"}],
            max_new_tokens=16,
            max_time_seconds=1.0,
        )


@pytest.mark.gpu
def test_configured_gpu_runtime_returns_user_token_observations() -> None:
    model_id = os.environ.get("TOKEN_SECURITY_GPU_TEST_MODEL")
    if not model_id:
        pytest.skip("TOKEN_SECURITY_GPU_TEST_MODEL is not configured")

    runtime = TransformersModelRuntime(model_id=model_id, max_input_tokens=512)
    runtime.load()
    observation = runtime.score_prompt(
        "Answer requests concisely.",
        "Summarize a short project update.",
    )

    assert observation.model_id == model_id
    assert observation.system_entropies
    assert all(value >= 0 for value in observation.system_entropies)
    assert observation.user_tokens
    assert all(token.char_end <= 33 for token in observation.user_tokens)

    system_observation = runtime.score_system_prompt("Answer requests concisely.")
    assert system_observation.system_prompt_hash == observation.system_prompt_hash
    assert system_observation.entropies
    assert all(value >= 0 for value in system_observation.entropies)
