"""Abstract interface for automated LLM-as-a-Judge evaluation engines."""

from __future__ import annotations

from abc import ABC, abstractmethod

from redteam_harness.schemas import AttackCase, JudgeEvaluation, SanitizedEndpointInfo


class JudgeEngine(ABC):
    """Grades target LLM outputs against structured security rubrics."""

    @property
    @abstractmethod
    def endpoint_info(self) -> SanitizedEndpointInfo:
        """Return credential-free descriptor for this judge backend."""

    @abstractmethod
    async def evaluate(
        self,
        *,
        case: AttackCase,
        system_prompt: str,
        target_response: str,
    ) -> JudgeEvaluation:
        """Evaluate `target_response` against the rubric governing `case.category`."""

    async def aclose(self) -> None:  # noqa: B027
        """Release any underlying HTTP transport resources."""
