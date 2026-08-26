from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel

from app.semantic.models import SemanticAssessment
from app.semantic.parser import parse_guard_output


class GuardDependencyError(RuntimeError):
    pass


class GuardInputTooLong(ValueError):
    pass


class SemanticGuardReadiness(BaseModel):
    ready: bool
    model_id: str
    model_version: str


class UnavailableSemanticGuard:
    def readiness(self) -> SemanticGuardReadiness:
        return SemanticGuardReadiness(
            ready=False,
            model_id="unconfigured",
            model_version="unconfigured",
        )

    def assess(self, prompt: str) -> SemanticAssessment:
        return SemanticAssessment(
            severity="unavailable",
            categories=[],
            model_id="unconfigured",
            model_version="unconfigured",
            latency_ms=0.0,
        )


class QwenSemanticGuard:
    def __init__(
        self,
        *,
        model_id: str,
        model_version: str,
        max_input_tokens: int = 4096,
        max_new_tokens: int = 32,
        tokenizer_factory: Callable[..., Any] | None = None,
        model_factory: Callable[..., Any] | None = None,
        torch_module: Any | None = None,
    ) -> None:
        if not model_id.strip():
            raise ValueError("model_id must not be blank")
        if not model_version.strip():
            raise ValueError("model_version must not be blank")
        if not 1 <= max_input_tokens <= 4096:
            raise ValueError("max_input_tokens must be between 1 and 4096")
        if not 1 <= max_new_tokens <= 32:
            raise ValueError("max_new_tokens must be between 1 and 32")
        self.model_id = model_id
        self.model_version = model_version
        self.max_input_tokens = max_input_tokens
        self.max_new_tokens = max_new_tokens
        self._tokenizer_factory = tokenizer_factory
        self._model_factory = model_factory
        self._torch = torch_module
        self._tokenizer: Any | None = None
        self._model: Any | None = None

    def readiness(self) -> SemanticGuardReadiness:
        return SemanticGuardReadiness(
            ready=self._model is not None and self._tokenizer is not None,
            model_id=self.model_id,
            model_version=self.model_version,
        )

    def load(self) -> None:
        tokenizer_factory = self._tokenizer_factory
        model_factory = self._model_factory
        if tokenizer_factory is None or model_factory is None or self._torch is None:
            try:
                import torch
                from transformers import AutoModelForCausalLM, AutoTokenizer
            except ImportError as exc:
                raise GuardDependencyError(
                    "semantic Guard dependencies are unavailable"
                ) from exc
            tokenizer_factory = AutoTokenizer.from_pretrained
            model_factory = AutoModelForCausalLM.from_pretrained
            self._torch = torch

        tokenizer = tokenizer_factory(
            self.model_id,
            trust_remote_code=False,
        )
        model = model_factory(
            self.model_id,
            torch_dtype="auto",
            device_map="auto",
            trust_remote_code=False,
        )
        model.eval()
        self._tokenizer = tokenizer
        self._model = model

    def assess(self, prompt: str) -> SemanticAssessment:
        if not prompt.strip():
            raise ValueError("prompt must not be blank")
        started = time.perf_counter()
        if self._model is None or self._tokenizer is None or self._torch is None:
            return self._unavailable(started)

        try:
            formatted_prompt = self._tokenizer.apply_chat_template(
                [{"role": "user", "content": prompt}],
                tokenize=False,
                add_generation_prompt=True,
            )
            encoded = self._tokenizer(
                formatted_prompt,
                add_special_tokens=False,
                return_tensors="pt",
                truncation=False,
            )
            input_length = len(encoded["input_ids"][0])
        except Exception:
            return self._unavailable(started)

        if input_length > self.max_input_tokens:
            raise GuardInputTooLong(
                "formatted semantic Guard input exceeds token limit"
            )

        try:
            device = next(self._model.parameters()).device
            model_inputs = {
                name: tensor.to(device) for name, tensor in encoded.items()
            }
            with self._torch.inference_mode():
                generated = self._model.generate(
                    **model_inputs,
                    do_sample=False,
                    max_new_tokens=self.max_new_tokens,
                )
            continuation = generated[0][input_length:]
            raw_output = self._tokenizer.decode(
                continuation,
                skip_special_tokens=True,
                clean_up_tokenization_spaces=False,
            )
            return parse_guard_output(
                raw_output,
                model_id=self.model_id,
                model_version=self.model_version,
                latency_ms=(time.perf_counter() - started) * 1000,
            )
        except Exception:
            return self._unavailable(started)

    def _unavailable(self, started: float) -> SemanticAssessment:
        return SemanticAssessment(
            severity="unavailable",
            categories=[],
            model_id=self.model_id,
            model_version=self.model_version,
            latency_ms=(time.perf_counter() - started) * 1000,
        )
