"""FastAPI application exposing adversarial suites, rubric grading, and evaluation runs."""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request, Response, status

from redteam_harness import __version__
from redteam_harness.api.auth import require_gateway_auth
from redteam_harness.attacks import (
    AttackRegistry,
    UnknownCaseError,
    UnknownSuiteError,
    create_default_registry,
    list_mutations,
)
from redteam_harness.config import HarnessSettings
from redteam_harness.core import EvaluationRunner, RunStore, redact_secrets
from redteam_harness.judge import (
    JudgeParseError,
    build_judge_engine,
    get_rubric,
    list_rubrics,
)
from redteam_harness.schemas import (
    AttackCategory,
    AttackSuiteDetail,
    AttackSuiteInfo,
    CaseSeverity,
    CompareRequest,
    CompareResponse,
    EvaluationListResponse,
    EvaluationReport,
    EvaluationRequest,
    HealthResponse,
    MockProfile,
    MutationInfo,
    ProbeRequest,
    ProbeResponse,
    ProfileComparisonEntry,
    ProviderMode,
    SecurityRubric,
    TargetConfig,
    Verdict,
)
from redteam_harness.targets import (
    EgressPolicyError,
    TargetInvocationError,
    build_target_adapter,
)


@dataclass(slots=True)
class HarnessAppState:
    """Dependency container bound to `app.state.harness`."""

    settings: HarnessSettings
    registry: AttackRegistry
    runner: EvaluationRunner
    store: RunStore
    target_transport: httpx.AsyncBaseTransport | None = None
    judge_transport: httpx.AsyncBaseTransport | None = None


def _get_state(request: Request) -> HarnessAppState:
    return request.app.state.harness


def create_app(
    *,
    settings: HarnessSettings | None = None,
    registry: AttackRegistry | None = None,
    target_transport: httpx.AsyncBaseTransport | None = None,
    judge_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    """Create and configure the LLM Red-Team Evaluation Harness FastAPI application."""
    resolved_settings = settings or HarnessSettings.from_env()
    resolved_registry = registry or create_default_registry()
    runner = EvaluationRunner(
        resolved_registry,
        max_concurrency=resolved_settings.max_concurrency,
    )
    store = RunStore(
        max_runs=resolved_settings.max_stored_runs,
        artifacts_dir=resolved_settings.artifacts_dir,
    )

    fastapi_app = FastAPI(
        title="LLM Red-Team & Prompt-Injection Evaluation Harness",
        description=(
            "Modular cybersecurity evaluation backend testing LLM endpoints against "
            "prompt injection, jailbreaks, system-prompt extraction, and PII leakage "
            "with automated LLM-as-a-Judge rubric scoring."
        ),
        version=__version__,
    )
    fastapi_app.state.harness = HarnessAppState(
        settings=resolved_settings,
        registry=resolved_registry,
        runner=runner,
        store=store,
        target_transport=target_transport,
        judge_transport=judge_transport,
    )

    @fastapi_app.middleware("http")
    async def _security_headers_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    @fastapi_app.get("/health", response_model=HealthResponse, tags=["system"])
    async def health(state: HarnessAppState = Depends(_get_state)) -> HealthResponse:
        """Liveness probe and active security capability manifest."""
        return HealthResponse(
            status="ok",
            version=__version__,
            registered_suites=state.registry.suite_names,
            total_attack_cases=state.registry.total_case_count(),
            gateway_auth_enabled=state.settings.api_token is not None,
            allow_private_targets=state.settings.allow_private_targets,
            stored_runs=state.store.count(),
            capabilities={
                "target_modes": [m.value for m in ProviderMode],
                "judge_modes": [m.value for m in ProviderMode],
                "mock_profiles": [p.value for p in MockProfile],
                "mutations": [m.name.value for m in list_mutations()],
                "host_allowlist_active": bool(state.settings.allowed_target_hosts),
            },
        )

    api = APIRouter(prefix="/api/v1", dependencies=[Depends(require_gateway_auth)])

    @api.get("/suites", response_model=list[AttackSuiteInfo], tags=["catalog"])
    async def get_suites(state: HarnessAppState = Depends(_get_state)) -> list[AttackSuiteInfo]:
        """List all registered adversarial attack suites and severity counts."""
        return state.registry.list_suites()

    @api.get("/suites/{suite_name}", response_model=AttackSuiteDetail, tags=["catalog"])
    async def get_suite_detail(
        suite_name: str,
        min_severity: CaseSeverity | None = Query(default=None),
        state: HarnessAppState = Depends(_get_state),
    ) -> AttackSuiteDetail:
        """Inspect all attack probes inside a single registered suite."""
        try:
            plugin = state.registry.get_plugin(suite_name)
        except UnknownSuiteError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        return plugin.get_detail(min_severity=min_severity)

    @api.get("/rubrics", response_model=list[SecurityRubric], tags=["catalog"])
    async def get_rubrics(
        category: AttackCategory | None = Query(default=None),
    ) -> list[SecurityRubric]:
        """List structured security rubrics used by the LLM-as-a-Judge engine."""
        if category is not None:
            return [get_rubric(category)]
        return list_rubrics()

    @api.get("/mutations", response_model=list[MutationInfo], tags=["catalog"])
    async def get_mutations() -> list[MutationInfo]:
        """List supported deterministic adversarial prompt mutation transforms."""
        return list_mutations()

    @api.post(
        "/evaluations",
        response_model=EvaluationReport,
        status_code=status.HTTP_201_CREATED,
        tags=["evaluations"],
    )
    async def create_evaluation(
        payload: EvaluationRequest,
        state: HarnessAppState = Depends(_get_state),
    ) -> EvaluationReport:
        """Execute an adversarial evaluation run against the configured target endpoint."""
        target = None
        judge = None
        try:
            # Validate suite/case selection before opening network clients.
            _, preview_cases = state.registry.resolve_cases(
                suites=payload.suites,
                case_ids=payload.case_ids,
                min_severity=payload.min_severity,
                mutations=payload.mutations,
                include_base_cases=payload.include_base_cases,
            )
            if not preview_cases:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="No attack cases matched the requested suite/severity filter.",
                )

            target = build_target_adapter(
                payload.target,
                state.settings,
                transport=state.target_transport,
            )
            judge = build_judge_engine(
                payload.judge,
                state.settings,
                transport=state.judge_transport,
            )
            report = await state.runner.run(
                target=target,
                judge=judge,
                suites=payload.suites,
                case_ids=payload.case_ids,
                min_severity=payload.min_severity,
                mutations=payload.mutations,
                include_base_cases=payload.include_base_cases,
                system_prompt=payload.target.system_prompt,
                concurrency=payload.concurrency,
                policy_gate=payload.policy_gate,
                metadata=payload.metadata,
            )
            state.store.save(report)
            return report
        except (UnknownSuiteError, UnknownCaseError, EgressPolicyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        finally:
            if target is not None:
                await target.aclose()
            if judge is not None:
                await judge.aclose()

    @api.get("/evaluations", response_model=EvaluationListResponse, tags=["evaluations"])
    async def list_evaluations(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        state: HarnessAppState = Depends(_get_state),
    ) -> EvaluationListResponse:
        """Return paginated summary metadata for previously executed evaluations."""
        total, items = state.store.list_runs(limit=limit, offset=offset)
        return EvaluationListResponse(total=total, limit=limit, offset=offset, items=items)

    @api.get("/evaluations/{run_id}", response_model=EvaluationReport, tags=["evaluations"])
    async def get_evaluation(
        run_id: str,
        verdict: Verdict | None = Query(default=None),
        min_severity: CaseSeverity | None = Query(default=None),
        state: HarnessAppState = Depends(_get_state),
    ) -> EvaluationReport:
        """Fetch a persisted evaluation report with optional finding filters."""
        report = state.store.get(run_id)
        if report is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evaluation run '{run_id}' not found.",
            )
        if verdict is None and min_severity is None:
            return report

        filtered = report.results
        if verdict is not None:
            filtered = [r for r in filtered if r.evaluation.verdict == verdict]
        if min_severity is not None:
            filtered = [r for r in filtered if r.evaluation.severity.rank >= min_severity.rank]
        return report.model_copy(update={"results": filtered})

    @api.delete(
        "/evaluations/{run_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["evaluations"],
    )
    async def delete_evaluation(
        run_id: str,
        state: HarnessAppState = Depends(_get_state),
    ) -> Response:
        """Delete a stored evaluation run artifact."""
        if not state.store.delete(run_id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evaluation run '{run_id}' not found.",
            )
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    @api.post("/probe", response_model=ProbeResponse, tags=["evaluations"])
    async def execute_probe(
        payload: ProbeRequest,
        state: HarnessAppState = Depends(_get_state),
    ) -> ProbeResponse:
        """Run a single ad-hoc adversarial probe or grade a pre-captured target response."""
        target = None
        judge = None
        try:
            if payload.target_response is None:
                target = build_target_adapter(
                    payload.target,
                    state.settings,
                    transport=state.target_transport,
                )
            judge = build_judge_engine(
                payload.judge,
                state.settings,
                transport=state.judge_transport,
            )
            return await state.runner.run_probe(request=payload, target=target, judge=judge)
        except (EgressPolicyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        except (TargetInvocationError, JudgeParseError) as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=redact_secrets(str(exc)),
            ) from exc
        finally:
            if target is not None:
                await target.aclose()
            if judge is not None:
                await judge.aclose()

    @api.post("/compare", response_model=CompareResponse, tags=["evaluations"])
    async def compare_profiles(
        payload: CompareRequest,
        state: HarnessAppState = Depends(_get_state),
    ) -> CompareResponse:
        """Benchmark multiple deterministic mock target profiles side by side."""
        judge = None
        unique_profiles = list(dict.fromkeys(payload.profiles))
        try:
            executed_suites, preview_cases = state.registry.resolve_cases(
                suites=payload.suites,
                min_severity=payload.min_severity,
                mutations=payload.mutations,
            )
            if not preview_cases:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                    detail="No attack cases matched the requested suite/severity filter.",
                )

            judge = build_judge_engine(
                payload.judge,
                state.settings,
                transport=state.judge_transport,
            )
            entries: list[ProfileComparisonEntry] = []
            for profile in unique_profiles:
                target = build_target_adapter(
                    TargetConfig(mode=ProviderMode.MOCK, mock_profile=profile),
                    state.settings,
                )
                try:
                    report = await state.runner.run(
                        target=target,
                        judge=judge,
                        suites=payload.suites,
                        min_severity=payload.min_severity,
                        mutations=payload.mutations,
                    )
                finally:
                    await target.aclose()
                state.store.save(report)
                entries.append(
                    ProfileComparisonEntry(
                        profile=profile,
                        run_id=report.run_id,
                        summary=report.summary,
                    )
                )
            return CompareResponse(suites_executed=executed_suites, comparisons=entries)
        except (UnknownSuiteError, EgressPolicyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=str(exc),
            ) from exc
        finally:
            if judge is not None:
                await judge.aclose()

    fastapi_app.include_router(api)
    return fastapi_app


app = create_app()
