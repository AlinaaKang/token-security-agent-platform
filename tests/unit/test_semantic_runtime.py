from __future__ import annotations

from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any

import pytest

from app.semantic.runtime import (
    GuardInputTooLong,
    QwenSemanticGuard,
    UnavailableSemanticGuard,
)


class FakeTensor:
    def __init__(self, rows: list[list[int]]) -> None:
        self.rows = rows
        self.shape = (len(rows), len(rows[0]))

    def __getitem__(self, index: int) -> list[int]:
        return self.rows[index]

    def to(self, device: str) -> FakeTensor:
        return self


class FakeTokenizer:
    name_or_path = "guard-tokenizer"

    def __init__(self, *, raw_output: str) -> None:
        self.raw_output = raw_output
        self.template_calls: list[tuple[list[dict[str, str]], dict[str, Any]]] = []
        self.decode_calls: list[list[int]] = []

    def apply_chat_template(
        self,
        messages: list[dict[str, str]],
        **kwargs: Any,
    ) -> str:
        self.template_calls.append((messages, kwargs))
        return "FORMATTED_SAFE_PLACEHOLDER"

    def __call__(self, text: str, **kwargs: Any) -> dict[str, FakeTensor]:
        return {"input_ids": FakeTensor([[11, 12, 13]])}

    def decode(self, token_ids: list[int], **kwargs: Any) -> str:
        self.decode_calls.append(list(token_ids))
        return self.raw_output


class FakeModel:
    def __init__(self, *, error: Exception | None = None) -> None:
        self.error = error
        self.generate_kwargs: dict[str, Any] | None = None
        self.eval_called = False

    def eval(self) -> FakeModel:
        self.eval_called = True
        return self

    def parameters(self):
        yield SimpleNamespace(device="cuda:0")

    def generate(self, **kwargs: Any) -> list[list[int]]:
        self.generate_kwargs = kwargs
        if self.error is not None:
            raise self.error
        return [[11, 12, 13, 91, 92]]


class FakeTorch:
    @staticmethod
    def inference_mode():
        return nullcontext()


def make_loaded_guard(
    *,
    raw_output: str = "Safety: Safe\nCategories: None",
    max_input_tokens: int = 16,
    model_error: Exception | None = None,
) -> tuple[QwenSemanticGuard, FakeTokenizer, FakeModel]:
    tokenizer = FakeTokenizer(raw_output=raw_output)
    model = FakeModel(error=model_error)
    guard = QwenSemanticGuard(
        model_id="guard-model",
        model_version="guard-v1",
        max_input_tokens=max_input_tokens,
        max_new_tokens=7,
        tokenizer_factory=lambda *args, **kwargs: tokenizer,
        model_factory=lambda *args, **kwargs: model,
        torch_module=FakeTorch(),
    )
    guard.load()
    return guard, tokenizer, model


def test_guard_uses_chat_template_and_decodes_only_generated_tokens() -> None:
    guard, tokenizer, model = make_loaded_guard()

    result = guard.assess("SAFE_PLACEHOLDER")

    assert result.severity == "safe"
    assert tokenizer.template_calls == [
        (
            [{"role": "user", "content": "SAFE_PLACEHOLDER"}],
            {"tokenize": False, "add_generation_prompt": True},
        )
    ]
    assert tokenizer.decode_calls == [[91, 92]]
    assert model.generate_kwargs is not None
    assert model.generate_kwargs["do_sample"] is False
    assert model.generate_kwargs["max_new_tokens"] == 7


def test_guard_rejects_input_above_configured_token_limit() -> None:
    guard, _, _ = make_loaded_guard(max_input_tokens=2)

    with pytest.raises(GuardInputTooLong, match="token limit"):
        guard.assess("SAFE_PLACEHOLDER")


@pytest.mark.parametrize(
    ("raw_output", "model_error"),
    [
        ("Safety: Unknown\nCategories: None", None),
        ("Safety: Safe\nCategories: None", RuntimeError("private runtime detail")),
    ],
)
def test_guard_failures_return_unavailable_without_raw_output(
    raw_output: str,
    model_error: Exception | None,
) -> None:
    guard, _, _ = make_loaded_guard(
        raw_output=raw_output,
        model_error=model_error,
    )

    result = guard.assess("SAFE_PLACEHOLDER")
    serialized = result.model_dump_json()

    assert result.severity == "unavailable"
    assert result.categories == []
    assert raw_output not in serialized
    assert "private runtime detail" not in serialized


def test_unavailable_guard_has_explicit_unconfigured_identity() -> None:
    result = UnavailableSemanticGuard().assess("SAFE_PLACEHOLDER")

    assert result.model_dump(mode="json") == {
        "severity": "unavailable",
        "categories": [],
        "model_id": "unconfigured",
        "model_version": "unconfigured",
        "latency_ms": 0.0,
    }
