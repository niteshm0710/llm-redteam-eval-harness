"""Async OpenAI-compatible `/chat/completions` client and target adapter."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from redteam_harness.core.redaction import redact_secrets
from redteam_harness.schemas import ProviderMode, SanitizedEndpointInfo
from redteam_harness.targets.base import (
    TargetAdapter,
    TargetInvocationError,
    TargetResponse,
    validate_endpoint_url,
)

_RETRYABLE_STATUS_CODES = frozenset({408, 429, 500, 502, 503, 504})


class OpenAICompatibleClient:
    """Hardened async client for any OpenAI-compatible Chat Completions endpoint."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout_seconds: float = 30.0,
        max_retries: int = 2,
        extra_headers: dict[str, str] | None = None,
        allow_private: bool = False,
        allowed_hosts: tuple[str, ...] = (),
        transport: httpx.AsyncBaseTransport | None = None,
        retry_backoff_base: float = 0.25,
    ) -> None:
        if not model or not model.strip():
            raise ValueError("Model identifier must not be empty.")

        self.base_url = validate_endpoint_url(
            base_url,
            allow_private=allow_private,
            allowed_hosts=allowed_hosts,
        )
        self.model = model.strip()
        self._api_key = api_key.strip() if api_key and api_key.strip() else None
        self._max_retries = max(0, max_retries)
        self._retry_backoff_base = max(0.0, retry_backoff_base)
        self._secret_values = [self._api_key] if self._api_key else []

        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "llm-redteam-eval-harness/0.1.0",
        }
        if extra_headers:
            for key, value in extra_headers.items():
                headers[key] = value
                if any(tok in key.lower() for tok in ("auth", "key", "token", "secret")):
                    self._secret_values.append(value)
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            transport=transport,
        )

    @property
    def completions_url(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    async def chat_completion(
        self,
        *,
        messages: list[dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 512,
        json_mode: bool = False,
    ) -> TargetResponse:
        """Call `/chat/completions` with bounded retries and credential-safe errors."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        start = time.perf_counter()
        last_error: str = "Unknown transport error"

        for attempt in range(self._max_retries + 1):
            try:
                response = await self._client.post(self.completions_url, json=payload)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = redact_secrets(
                    f"{type(exc).__name__}: {exc}", extra_secrets=self._secret_values
                )
                if attempt < self._max_retries:
                    await self._sleep_backoff(attempt)
                    continue
                raise TargetInvocationError(
                    f"Request to '{self.completions_url}' failed after "
                    f"{attempt + 1} attempt(s): {last_error}"
                ) from exc

            # Graceful fallback for OpenAI-compatible servers that reject `response_format`.
            if response.status_code == 400 and json_mode and "response_format" in payload:
                body_preview = response.text[:400].lower()
                if "response_format" in body_preview or "json_object" in body_preview:
                    payload.pop("response_format", None)
                    response = await self._client.post(self.completions_url, json=payload)

            if response.status_code in _RETRYABLE_STATUS_CODES:
                snippet = redact_secrets(response.text[:300], extra_secrets=self._secret_values)
                last_error = f"HTTP {response.status_code}: {snippet}"
                if attempt < self._max_retries:
                    await self._sleep_backoff(attempt)
                    continue
                raise TargetInvocationError(
                    f"Endpoint '{self.completions_url}' returned retryable error after "
                    f"{attempt + 1} attempt(s): {last_error}"
                )

            if response.status_code >= 400:
                snippet = redact_secrets(response.text[:300], extra_secrets=self._secret_values)
                raise TargetInvocationError(
                    f"Endpoint '{self.completions_url}' returned HTTP "
                    f"{response.status_code}: {snippet}"
                )

            try:
                data = response.json()
            except ValueError as exc:
                raise TargetInvocationError(
                    f"Endpoint '{self.completions_url}' returned non-JSON payload."
                ) from exc

            content = self._extract_message_content(data)
            latency_ms = round((time.perf_counter() - start) * 1000.0, 2)
            usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
            returned_model = str(data.get("model") or self.model)
            return TargetResponse(
                content=content,
                model=returned_model,
                latency_ms=latency_ms,
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
            )

        raise TargetInvocationError(last_error)  # pragma: no cover

    async def _sleep_backoff(self, attempt: int) -> None:
        delay = self._retry_backoff_base * (2**attempt)
        if delay > 0:
            await asyncio.sleep(delay)

    @staticmethod
    def _extract_message_content(payload: dict[str, Any]) -> str:
        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise TargetInvocationError(
                "Malformed chat completion response: missing non-empty 'choices' list."
            )
        first = choices[0]
        if not isinstance(first, dict):
            raise TargetInvocationError("Malformed chat completion response: invalid choice item.")
        message = first.get("message")
        if not isinstance(message, dict):
            raise TargetInvocationError(
                "Malformed chat completion response: missing 'message' object."
            )

        content = message.get("content")
        if content is None:
            # Handle OpenAI structured refusal field when content is null.
            refusal = message.get("refusal")
            if isinstance(refusal, str):
                return refusal
            return ""
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
            return "\n".join(parts)
        raise TargetInvocationError(
            "Malformed chat completion response: unsupported 'message.content' format."
        )

    async def aclose(self) -> None:
        await self._client.aclose()


class OpenAICompatibleTarget(TargetAdapter):
    """Target adapter invoking any OpenAI-compatible `/chat/completions` service."""

    def __init__(
        self,
        *,
        client: OpenAICompatibleClient,
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> None:
        self._client = client
        self._temperature = temperature
        self._max_tokens = max_tokens

    @property
    def endpoint_info(self) -> SanitizedEndpointInfo:
        return SanitizedEndpointInfo(
            mode=ProviderMode.OPENAI_COMPATIBLE,
            model=self._client.model,
            base_url=self._client.base_url,
            mock_profile=None,
        )

    async def generate(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        case_id: str | None = None,
    ) -> TargetResponse:
        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": user_prompt})
        return await self._client.chat_completion(
            messages=messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            json_mode=False,
        )

    async def aclose(self) -> None:
        await self._client.aclose()
