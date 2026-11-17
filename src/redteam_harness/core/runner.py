"""Asynchronous red-team evaluation orchestrator with bounded concurrency and fault isolation."""

from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

from redteam_harness.attacks import AttackRegistry
from redteam_harness.config import DEFAULT_TARGET_SYSTEM_PROMPT, RESTRICTED_PII_CONTEXT_ADDENDUM
from redteam_harness.core.redaction import redact_secrets
from redteam_harness.core.scoring import compute_summary
from redteam_harness.judge import JudgeEngine, JudgeParseError, get_rubric
from redteam_harness.schemas import (
    AttackCase,
    AttackCategory,
    CaseResult,
    CaseSeverity,
    CaseStatus,
    EvaluationReport,
    JudgeEvaluation,
    MutationType,
    PolicyGateConfig,
    ProbeRequest,
    ProbeResponse,
    Severity,
    Verdict,
)
from redteam_harness.targets import TargetAdapter, TargetInvocationError


def _compose_system_prompt(base_prompt: str, addendum: str | None) -> str:
    if not addendum:
        return base_prompt
    if not base_prompt:
        return addendum.lstrip()
    return f"{base_prompt}\n{addendum.lstrip()}"


class EvaluationRunner:
    """Executes adversarial attack suites against a target adapter and grades responses."""

    def __init__(self, registry: AttackRegistry, *, max_concurrency: int = 20) -> None:
        self._registry = registry
        self._max_concurrency = max(1, max_concurrency)

    @property
    def registry(self) -> AttackRegistry:
        return self._registry

    async def run(
        self,
        *,
        target: TargetAdapter,
        judge: JudgeEngine,
        suites: list[str] | None = None,
        case_ids: list[str] | None = None,
        min_severity: CaseSeverity | None = None,
        mutations: list[MutationType] | None = None,
        include_base_cases: bool = True,
        system_prompt: str | None = None,
        concurrency: int = 5,
        policy_gate: PolicyGateConfig | None = None,
        metadata: dict[str, str] | None = None,
    ) -> EvaluationReport:
        """Run selected adversarial suites and produce a structured `EvaluationReport`."""
        executed_suites, cases = self._registry.resolve_cases(
            suites=suites,
            case_ids=case_ids,
            min_severity=min_severity,
            mutations=mutations,
            include_base_cases=include_base_cases,
        )

        effective_concurrency = max(1, min(concurrency, self._max_concurrency))
        semaphore = asyncio.Semaphore(effective_concurrency)
        base_prompt = DEFAULT_TARGET_SYSTEM_PROMPT if system_prompt is None else system_prompt

        run_id = f"run_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(UTC)
        start = time.perf_counter()

        async def _bounded_execute(case: AttackCase) -> CaseResult:
            async with semaphore:
                return await self._execute_single_case(
                    case=case,
                    base_system_prompt=base_prompt,
                    target=target,
                    judge=judge,
                )

        results = list(await asyncio.gather(*(_bounded_execute(case) for case in cases)))
        total_duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
        completed_at = datetime.now(UTC)

        summary = compute_summary(
            results,
            total_duration_ms=total_duration_ms,
            policy_gate=policy_gate,
        )
        unique_mutations = list(dict.fromkeys(mutations or []))

        return EvaluationReport(
            run_id=run_id,
            created_at=created_at,
            completed_at=completed_at,
            target=target.endpoint_info,
            judge=judge.endpoint_info,
            suites_executed=executed_suites,
            mutations_applied=unique_mutations,
            metadata=dict(metadata or {}),
            summary=summary,
            results=results,
        )

    async def _execute_single_case(
        self,
        *,
        case: AttackCase,
        base_system_prompt: str,
        target: TargetAdapter,
        judge: JudgeEngine,
    ) -> CaseResult:
        full_system_prompt = _compose_system_prompt(
            base_system_prompt, case.system_context_addendum
        )
        call_start = time.perf_counter()
        target_text = ""
        target_model = target.endpoint_info.model
        latency_ms = 0.0

        try:
            completion = await target.generate(
                system_prompt=full_system_prompt,
                user_prompt=case.prompt,
                case_id=case.id,
            )
            target_text = completion.content
            target_model = completion.model
            latency_ms = completion.latency_ms

            evaluation = await judge.evaluate(
                case=case,
                system_prompt=full_system_prompt,
                target_response=target_text,
            )
            return CaseResult(
                case_id=case.id,
                suite=case.suite,
                category=case.category,
                case_name=case.name,
                base_severity=case.base_severity,
                owasp_id=case.owasp_id,
                atlas_id=case.atlas_id,
                mutation=case.mutation,
                status=CaseStatus.COMPLETED,
                prompt=case.prompt,
                target_response=target_text,
                target_model=target_model,
                latency_ms=latency_ms,
                evaluation=evaluation,
                error=None,
            )
        except (TargetInvocationError, JudgeParseError) as exc:
            elapsed = latency_ms or round((time.perf_counter() - call_start) * 1000.0, 2)
            safe_error = redact_secrets(str(exc))
            rubric = get_rubric(case.category)
            fallback_eval = JudgeEvaluation(
                verdict=Verdict.SAFE,
                risk_score=0.0,
                severity=Severity.NONE,
                confidence=0.0,
                rubric_id=rubric.rubric_id,
                violated_criteria=[],
                matched_indicators=[],
                explanation=f"Probe could not be graded due to execution error: {safe_error}",
                remediation=(
                    "Verify target/judge endpoint connectivity, credentials, and JSON output support, "
                    "then re-run the affected suite."
                ),
                judge_mode=judge.endpoint_info.mode,
            )
            return CaseResult(
                case_id=case.id,
                suite=case.suite,
                category=case.category,
                case_name=case.name,
                base_severity=case.base_severity,
                owasp_id=case.owasp_id,
                atlas_id=case.atlas_id,
                mutation=case.mutation,
                status=CaseStatus.ERROR,
                prompt=case.prompt,
                target_response=target_text,
                target_model=target_model,
                latency_ms=elapsed,
                evaluation=fallback_eval,
                error=safe_error,
            )

    async def run_probe(
        self,
        *,
        request: ProbeRequest,
        target: TargetAdapter | None,
        judge: JudgeEngine,
    ) -> ProbeResponse:
        """Execute and grade a single ad-hoc adversarial probe (or pre-captured response)."""
        owasp_map = {
            AttackCategory.PROMPT_INJECTION: ("LLM01:2025", "AML.T0051.000"),
            AttackCategory.JAILBREAK: ("LLM01:2025", "AML.T0054"),
            AttackCategory.SYSTEM_PROMPT_EXTRACTION: ("LLM07:2025", "AML.T0056"),
            AttackCategory.PII_LEAKAGE: ("LLM02:2025", "AML.T0024.002"),
        }
        owasp_id, atlas_id = owasp_map[request.category]
        addendum = (
            RESTRICTED_PII_CONTEXT_ADDENDUM
            if request.category == AttackCategory.PII_LEAKAGE
            else None
        )
        synthetic_case = AttackCase(
            id="ADHOC-001",
            suite=request.category.value,
            category=request.category,
            name="Ad-Hoc Adversarial Probe",
            description="User-supplied single-turn red-team evaluation probe.",
            prompt=request.prompt,
            system_context_addendum=addendum,
            base_severity=request.base_severity,
            owasp_id=owasp_id,
            atlas_id=atlas_id,
            tags=["ad-hoc"],
            success_indicators=list(request.success_indicators),
            sensitive_literals=list(request.sensitive_literals),
        )

        base_prompt = (
            DEFAULT_TARGET_SYSTEM_PROMPT
            if request.target.system_prompt is None
            else request.target.system_prompt
        )
        full_system_prompt = _compose_system_prompt(base_prompt, addendum)

        if request.target_response is not None:
            response_text = request.target_response
            model_name = "user-supplied-response"
            latency_ms = 0.0
        else:
            if target is None:  # pragma: no cover - defensive guard
                raise ValueError("Target adapter is required when target_response is omitted.")
            completion = await target.generate(
                system_prompt=full_system_prompt,
                user_prompt=synthetic_case.prompt,
                case_id=None,
            )
            response_text = completion.content
            model_name = completion.model
            latency_ms = completion.latency_ms

        evaluation = await judge.evaluate(
            case=synthetic_case,
            system_prompt=full_system_prompt,
            target_response=response_text,
        )
        return ProbeResponse(
            category=request.category,
            prompt=request.prompt,
            target_response=response_text,
            target_model=model_name,
            latency_ms=latency_ms,
            evaluation=evaluation,
        )
