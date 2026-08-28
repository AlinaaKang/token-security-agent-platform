from __future__ import annotations

import hashlib
import time
from typing import Any

from pydantic import BaseModel, Field

from app.model.token_stats import (
    ObservedUserToken,
    TokenStatistic,
    project_span_statistics,
    project_user_tokens,
    sanitize_entropy,
)


class ModelUnavailableError(RuntimeError):
    pass


class ModelDependencyError(RuntimeError):
    pass


class PromptTooLongError(ValueError):
    pass


class ObservationAlignmentError(RuntimeError):
    pass


class RuntimeReadiness(BaseModel):
    ready: bool
    model_id: str
    tokenizer_id: str | None


class ModelObservation(BaseModel):
    model_id: str
    tokenizer_id: str
    system_prompt_hash: str
    system_entropies: tuple[float, ...] = Field(min_length=1)
    user_tokens: tuple[ObservedUserToken, ...]
    latency_ms: float = Field(ge=0)


class SystemPromptObservation(BaseModel):
    model_id: str
    tokenizer_id: str
    system_prompt_hash: str
    entropies: tuple[float, ...] = Field(min_length=1)
    latency_ms: float = Field(ge=0)


def hash_system_prompt(system_prompt: str) -> str:
    return "sha256:" + hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()


class TransformersModelRuntime:
    def __init__(
        self,
        *,
        model_id: str,
        tokenizer_id: str | None = None,
        max_input_tokens: int = 4096,
        dtype: str = "bfloat16",
        device_map: str = "auto",
    ) -> None:
        if not model_id.strip():
            raise ValueError("model_id must not be blank")
        if max_input_tokens < 2:
            raise ValueError("max_input_tokens must be at least 2")
        self.model_id = model_id
        self.configured_tokenizer_id = tokenizer_id
        self.max_input_tokens = max_input_tokens
        self.dtype = dtype
        self.device_map = device_map
        self._model: Any | None = None
        self._tokenizer: Any | None = None
        self._torch: Any | None = None
        self._clock = time.perf_counter

    def readiness(self) -> RuntimeReadiness:
        tokenizer_id = None
        if self._tokenizer is not None:
            tokenizer_id = str(
                getattr(
                    self._tokenizer,
                    "name_or_path",
                    self.configured_tokenizer_id or self.model_id,
                )
            )
        return RuntimeReadiness(
            ready=self._model is not None and self._tokenizer is not None,
            model_id=self.model_id,
            tokenizer_id=tokenizer_id,
        )

    def load(self) -> None:
        try:
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise ModelDependencyError(
                "model dependencies are unavailable; install the 'model' extra"
            ) from exc

        tokenizer_source = self.configured_tokenizer_id or self.model_id
        tokenizer = AutoTokenizer.from_pretrained(
            tokenizer_source,
            use_fast=True,
            trust_remote_code=False,
        )
        if not getattr(tokenizer, "is_fast", False):
            raise ModelDependencyError("a fast tokenizer is required for offset mapping")

        torch_dtype = getattr(torch, self.dtype, None)
        if torch_dtype is None:
            raise ModelDependencyError(f"unsupported torch dtype: {self.dtype}")
        model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype=torch_dtype,
            device_map=self.device_map,
            trust_remote_code=False,
        )
        model.eval()
        self._torch = torch
        self._tokenizer = tokenizer
        self._model = model

    def score_system_prompt(self, system_prompt: str) -> SystemPromptObservation:
        if not system_prompt.strip():
            raise ValueError("system prompt must not be blank")
        if self._model is None or self._tokenizer is None or self._torch is None:
            raise ModelUnavailableError("model runtime is not loaded")

        started = time.perf_counter()
        formatted_prompt = self._tokenizer.apply_chat_template(
            [{"role": "system", "content": system_prompt}],
            tokenize=False,
            add_generation_prompt=False,
        )
        system_start = formatted_prompt.find(system_prompt)
        system_end = system_start + len(system_prompt)
        if system_start < 0 or formatted_prompt.find(system_prompt, system_end) >= 0:
            raise ObservationAlignmentError(
                "chat template did not preserve a unique system prompt span"
            )

        encoded = self._tokenizer(
            formatted_prompt,
            add_special_tokens=False,
            return_offsets_mapping=True,
            return_tensors="pt",
            truncation=False,
        )
        offsets = [tuple(pair) for pair in encoded.pop("offset_mapping")[0].tolist()]
        if len(encoded["input_ids"][0]) > self.max_input_tokens:
            raise PromptTooLongError("formatted system prompt exceeds token limit")

        device = next(self._model.parameters()).device
        model_inputs = {name: tensor.to(device) for name, tensor in encoded.items()}
        with self._torch.inference_mode():
            output = self._model(
                **model_inputs,
                use_cache=False,
                output_hidden_states=False,
            )
            prediction_logits = output.logits[0, :-1, :].float()
            targets = model_inputs["input_ids"][0, 1:]
            statistics = self._compute_statistics(prediction_logits, targets)

        system_statistics = project_span_statistics(
            offsets=offsets,
            statistics=statistics,
            char_span=(system_start, system_end),
        )
        if not system_statistics:
            raise ObservationAlignmentError(
                "no system tokens were found in the chat template"
            )
        tokenizer_id = str(
            getattr(
                self._tokenizer,
                "name_or_path",
                self.configured_tokenizer_id or self.model_id,
            )
        )
        return SystemPromptObservation(
            model_id=self.model_id,
            tokenizer_id=tokenizer_id,
            system_prompt_hash=hash_system_prompt(system_prompt),
            entropies=tuple(item.entropy for item in system_statistics),
            latency_ms=(time.perf_counter() - started) * 1000,
        )

    def score_prompt(self, system_prompt: str, user_prompt: str) -> ModelObservation:
        if not system_prompt.strip():
            raise ValueError("system prompt must not be blank")
        if not user_prompt.strip():
            raise ValueError("user prompt must not be blank")
        if self._model is None or self._tokenizer is None or self._torch is None:
            raise ModelUnavailableError("model runtime is not loaded")

        started = time.perf_counter()
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        formatted_prompt = self._tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=False,
        )
        user_start = formatted_prompt.rfind(user_prompt)
        if user_start < 0:
            raise ObservationAlignmentError(
                "chat template did not preserve the user prompt verbatim"
            )
        user_span = (user_start, user_start + len(user_prompt))
        system_start = formatted_prompt.find(system_prompt)
        system_end = system_start + len(system_prompt)
        if system_start < 0 or system_end > user_start:
            raise ObservationAlignmentError(
                "chat template did not preserve the system prompt verbatim"
            )
        if formatted_prompt.find(system_prompt, system_end, user_start) >= 0:
            raise ObservationAlignmentError(
                "chat template contains an ambiguous system prompt span"
            )
        system_span = (system_start, system_end)

        encoded = self._tokenizer(
            formatted_prompt,
            add_special_tokens=False,
            return_offsets_mapping=True,
            return_tensors="pt",
            truncation=False,
        )
        offsets = [tuple(pair) for pair in encoded.pop("offset_mapping")[0].tolist()]
        input_ids_cpu = encoded["input_ids"][0]
        if len(input_ids_cpu) > self.max_input_tokens:
            raise PromptTooLongError(
                f"formatted prompt has {len(input_ids_cpu)} tokens; limit is {self.max_input_tokens}"
            )

        device = next(self._model.parameters()).device
        model_inputs = {name: tensor.to(device) for name, tensor in encoded.items()}
        with self._torch.inference_mode():
            output = self._model(
                **model_inputs,
                use_cache=False,
                output_hidden_states=False,
            )
            prediction_logits = output.logits[0, :-1, :].float()
            targets = model_inputs["input_ids"][0, 1:]
            statistics = self._compute_statistics(prediction_logits, targets)

        system_statistics = project_span_statistics(
            offsets=offsets,
            statistics=statistics,
            char_span=system_span,
        )
        if not system_statistics:
            raise ObservationAlignmentError(
                "no system tokens were found in the chat template"
            )

        token_ids = [int(token_id) for token_id in input_ids_cpu.tolist()]
        token_texts = [
            self._tokenizer.decode(
                [token_id],
                skip_special_tokens=False,
                clean_up_tokenization_spaces=False,
            )
            for token_id in token_ids
        ]
        user_tokens = project_user_tokens(
            token_ids=token_ids,
            token_texts=token_texts,
            offsets=offsets,
            statistics=statistics,
            user_char_span=user_span,
        )
        if not user_tokens:
            raise ObservationAlignmentError("no user tokens were found in the chat template")

        tokenizer_id = str(
            getattr(
                self._tokenizer,
                "name_or_path",
                self.configured_tokenizer_id or self.model_id,
            )
        )
        return ModelObservation(
            model_id=self.model_id,
            tokenizer_id=tokenizer_id,
            system_prompt_hash=hash_system_prompt(system_prompt),
            system_entropies=tuple(item.entropy for item in system_statistics),
            user_tokens=tuple(user_tokens),
            latency_ms=(time.perf_counter() - started) * 1000,
        )

    def generate_structured(
        self,
        messages: list[dict[str, str]],
        *,
        max_new_tokens: int,
        max_time_seconds: float,
    ) -> str:
        if self._model is None or self._tokenizer is None or self._torch is None:
            raise ModelUnavailableError("model runtime is not loaded")
        if not messages or any(
            message.get("role") not in {"system", "user", "assistant"}
            or not message.get("content", "").strip()
            for message in messages
        ):
            raise ValueError("structured messages must be non-empty")
        if max_new_tokens < 1 or max_time_seconds <= 0:
            raise ValueError("structured generation limits must be positive")

        formatted = self._tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )
        encoded = self._tokenizer(
            formatted,
            add_special_tokens=False,
            return_tensors="pt",
            truncation=False,
        )
        input_length = len(encoded["input_ids"][0])
        if input_length > self.max_input_tokens:
            raise PromptTooLongError("structured input exceeds token limit")
        device = next(self._model.parameters()).device
        model_inputs = {name: tensor.to(device) for name, tensor in encoded.items()}
        generation_started = self._clock()
        with self._torch.inference_mode():
            generated = self._model.generate(
                **model_inputs,
                do_sample=False,
                max_new_tokens=max_new_tokens,
                max_time=max_time_seconds,
            )
        if self._clock() - generation_started >= max_time_seconds:
            raise TimeoutError("structured generation timed out")
        continuation = generated[0][input_length:]
        return self._tokenizer.decode(
            continuation,
            skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        )

    def _compute_statistics(self, prediction_logits: Any, targets: Any) -> list[TokenStatistic]:
        statistics: list[TokenStatistic] = []
        chunk_size = 64
        for start in range(0, prediction_logits.shape[0], chunk_size):
            chunk = prediction_logits[start : start + chunk_size]
            chunk_targets = targets[start : start + chunk_size]
            log_normalizer = self._torch.logsumexp(chunk, dim=-1)
            expected_logit = (self._torch.softmax(chunk, dim=-1) * chunk).sum(dim=-1)
            entropy = log_normalizer - expected_logit
            observed_logits = chunk.gather(1, chunk_targets.unsqueeze(1)).squeeze(1)
            nll = log_normalizer - observed_logits
            for offset, (entropy_value, nll_value) in enumerate(
                zip(entropy.tolist(), nll.tolist(), strict=True)
            ):
                statistics.append(
                    TokenStatistic(
                        full_index=start + offset + 1,
                        entropy=sanitize_entropy(float(entropy_value)),
                        nll=float(nll_value),
                    )
                )
        return statistics
