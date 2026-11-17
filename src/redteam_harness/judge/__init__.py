"""LLM-as-a-Judge engine factory, rubric catalog, and parser exports."""

from __future__ import annotations

import httpx

from redteam_harness.config import HarnessSettings
from redteam_harness.judge.base import JudgeEngine
from redteam_harness.judge.llm_judge import LLMJudgeEngine
from redteam_harness.judge.mock import MockJudgeEngine
from redteam_harness.judge.parser import (
    JudgeParseError,
    extract_json_object,
    parse_judge_output,
    reconcile_with_deterministic_guardrails,
)
from redteam_harness.judge.rubrics import (
    SECURITY_RUBRICS,
    DetectedSignal,
    SignalAnalysis,
    analyze_response_signals,
    build_judge_messages,
    get_rubric,
    list_rubrics,
)
from redteam_harness.schemas import JudgeConfig, ProviderMode
from redteam_harness.targets.openai_compat import OpenAICompatibleClient


def build_judge_engine(
    config: JudgeConfig,
    settings: HarnessSettings,
    *,
    allow_private_override: bool | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> JudgeEngine:
    """Construct a `JudgeEngine` from `JudgeConfig` and runtime gateway settings."""
    if config.mode == ProviderMode.MOCK:
        return MockJudgeEngine()

    base_url = (config.base_url or settings.default_judge_base_url).strip()
    model = (config.model or settings.default_judge_model).strip()
    api_key = (
        config.api_key.get_secret_value()
        if config.api_key is not None
        else settings.default_judge_api_key
    )
    allow_private = (
        settings.allow_private_targets if allow_private_override is None else allow_private_override
    )
    client = OpenAICompatibleClient(
        base_url=base_url,
        model=model,
        api_key=api_key,
        timeout_seconds=config.timeout_seconds,
        max_retries=config.max_retries,
        extra_headers=config.extra_headers,
        allow_private=allow_private,
        allowed_hosts=settings.allowed_target_hosts,
        transport=transport,
    )
    return LLMJudgeEngine(
        client=client,
        temperature=config.temperature,
        max_tokens=config.max_tokens,
        enforce_deterministic_guardrails=config.enforce_deterministic_guardrails,
    )


__all__ = [
    "DetectedSignal",
    "JudgeEngine",
    "JudgeParseError",
    "LLMJudgeEngine",
    "MockJudgeEngine",
    "SECURITY_RUBRICS",
    "SignalAnalysis",
    "analyze_response_signals",
    "build_judge_engine",
    "build_judge_messages",
    "extract_json_object",
    "get_rubric",
    "list_rubrics",
    "parse_judge_output",
    "reconcile_with_deterministic_guardrails",
]
