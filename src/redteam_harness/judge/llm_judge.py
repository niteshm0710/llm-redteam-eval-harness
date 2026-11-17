"""LLM-as-a-Judge grading engine backed by any OpenAI-compatible Chat Completions API."""

from __future__ import annotations

from redteam_harness.judge.base import JudgeEngine
from redteam_harness.judge.parser import (
    parse_judge_output,
    reconcile_with_deterministic_guardrails,
)
from redteam_harness.judge.rubrics import (
    analyze_response_signals,
    build_judge_messages,
    get_rubric,
)
from redteam_harness.schemas import (
    AttackCase,
    JudgeEvaluation,
    ProviderMode,
    SanitizedEndpointInfo,
)
from redteam_harness.targets.openai_compat import OpenAICompatibleClient


class LLMJudgeEngine(JudgeEngine):
    """Evaluates target responses with an OpenAI-compatible judge model and rubric prompts."""

    def __init__(
        self,
        *,
        client: OpenAICompatibleClient,
        temperature: float = 0.0,
        max_tokens: int = 512,
        enforce_deterministic_guardrails: bool = True,
    ) -> None:
        self._client = client
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._enforce_guardrails = enforce_deterministic_guardrails

    @property
    def endpoint_info(self) -> SanitizedEndpointInfo:
        return SanitizedEndpointInfo(
            mode=ProviderMode.OPENAI_COMPATIBLE,
            model=self._client.model,
            base_url=self._client.base_url,
            mock_profile=None,
        )

    async def evaluate(
        self,
        *,
        case: AttackCase,
        system_prompt: str,
        target_response: str,
    ) -> JudgeEvaluation:
        rubric = get_rubric(case.category)
        signal_analysis = analyze_response_signals(
            case=case,
            system_prompt=system_prompt,
            target_response=target_response,
        )
        messages = build_judge_messages(
            case=case,
            rubric=rubric,
            target_response=target_response,
            signal_analysis=signal_analysis,
        )
        completion = await self._client.chat_completion(
            messages=messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
            json_mode=True,
        )
        evaluation = parse_judge_output(
            completion.content,
            case=case,
            rubric=rubric,
            judge_mode=ProviderMode.OPENAI_COMPATIBLE,
        )
        if self._enforce_guardrails:
            evaluation = reconcile_with_deterministic_guardrails(
                evaluation,
                signal_analysis=signal_analysis,
                rubric=rubric,
            )
        return evaluation

    async def aclose(self) -> None:
        await self._client.aclose()
