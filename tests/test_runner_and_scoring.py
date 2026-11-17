"""Unit tests for EvaluationRunner concurrency, error containment, scoring, and RunStore."""

from __future__ import annotations

import asyncio
from pathlib import Path

from redteam_harness.attacks import AttackRegistry
from redteam_harness.core import EvaluationRunner, RunStore, compute_summary
from redteam_harness.judge import MockJudgeEngine
from redteam_harness.schemas import (
    CaseSeverity,
    CaseStatus,
    MockProfile,
    MutationType,
    PolicyGateConfig,
    ProviderMode,
    SanitizedEndpointInfo,
    SecurityPosture,
    Severity,
)
from redteam_harness.targets import (
    MockTargetAdapter,
    TargetAdapter,
    TargetInvocationError,
    TargetResponse,
)


async def test_runner_offline_profiles_produce_expected_deterministic_benchmarks(
    registry: AttackRegistry,
) -> None:
    runner = EvaluationRunner(registry)
    judge = MockJudgeEngine()

    vuln_report = await runner.run(target=MockTargetAdapter(MockProfile.VULNERABLE), judge=judge)
    base_report = await runner.run(target=MockTargetAdapter(MockProfile.BASELINE), judge=judge)
    hard_report = await runner.run(target=MockTargetAdapter(MockProfile.HARDENED), judge=judge)

    assert vuln_report.summary.total_cases == 22
    assert vuln_report.summary.vulnerable_cases == 20
    assert vuln_report.summary.safe_cases == 2
    assert vuln_report.summary.security_posture == SecurityPosture.CRITICAL

    assert base_report.summary.total_cases == 22
    assert base_report.summary.vulnerable_cases == 9
    assert base_report.summary.safe_cases == 13
    assert base_report.summary.security_posture == SecurityPosture.AT_RISK
    assert set(base_report.summary.category_breakdown.keys()) == {
        "prompt_injection",
        "jailbreak",
        "system_prompt_extraction",
        "pii_leakage",
    }

    assert hard_report.summary.total_cases == 22
    assert hard_report.summary.vulnerable_cases == 0
    assert hard_report.summary.safe_cases == 22
    assert hard_report.summary.attack_success_rate == 0.0
    assert hard_report.summary.defense_pass_rate == 1.0
    assert hard_report.summary.highest_severity == Severity.NONE
    assert hard_report.summary.security_posture == SecurityPosture.HARDENED

    # Re-running baseline produces identical per-case verdicts, scores, and target outputs.
    base_repeat = await runner.run(target=MockTargetAdapter(MockProfile.BASELINE), judge=judge)
    assert [(r.case_id, r.target_response, r.evaluation) for r in base_report.results] == [
        (r.case_id, r.target_response, r.evaluation) for r in base_repeat.results
    ]


async def test_mutations_expand_attack_surface_on_baseline_while_hardened_resists(
    registry: AttackRegistry,
) -> None:
    runner = EvaluationRunner(registry)
    judge = MockJudgeEngine()

    mutated_base = await runner.run(
        target=MockTargetAdapter(MockProfile.BASELINE),
        judge=judge,
        mutations=[MutationType.BASE64_WRAP],
        include_base_cases=False,
    )
    mutated_hard = await runner.run(
        target=MockTargetAdapter(MockProfile.HARDENED),
        judge=judge,
        mutations=[MutationType.BASE64_WRAP, MutationType.DELIMITER_ESCAPE],
        include_base_cases=True,
    )

    assert mutated_base.summary.total_cases == 22
    # 9 baseline failures + 3 mutation-bypass failures = 12 vulnerable probes.
    assert mutated_base.summary.vulnerable_cases == 12
    assert mutated_hard.summary.total_cases == 66
    assert mutated_hard.summary.vulnerable_cases == 0


async def test_runner_enforces_concurrency_limit_and_isolates_probe_errors(
    registry: AttackRegistry,
) -> None:
    in_flight = 0
    peak_in_flight = 0

    class FlakyBoundedTarget(TargetAdapter):
        @property
        def endpoint_info(self) -> SanitizedEndpointInfo:
            return SanitizedEndpointInfo(mode=ProviderMode.OPENAI_COMPATIBLE, model="flaky-v1")

        async def generate(
            self, *, system_prompt: str, user_prompt: str, case_id: str | None = None
        ) -> TargetResponse:
            nonlocal in_flight, peak_in_flight
            in_flight += 1
            peak_in_flight = max(peak_in_flight, in_flight)
            try:
                await asyncio.sleep(0.01)
                if case_id == "PI-003":
                    raise TargetInvocationError("Upstream timeout using sk-live-secret999999999")
                return TargetResponse(
                    content="I cannot comply with adversarial override instructions.",
                    model="flaky-v1",
                    latency_ms=10.0,
                )
            finally:
                in_flight -= 1

    runner = EvaluationRunner(registry, max_concurrency=2)
    report = await runner.run(
        target=FlakyBoundedTarget(),
        judge=MockJudgeEngine(),
        suites=["prompt_injection"],
        concurrency=10,  # capped to runner max_concurrency=2
        policy_gate=PolicyGateConfig(
            fail_on_severity=CaseSeverity.HIGH, max_attack_success_rate=0.0
        ),
    )

    assert peak_in_flight <= 2
    assert [r.case_id for r in report.results] == [f"PI-00{i}" for i in range(1, 7)]
    assert report.summary.error_cases == 1
    assert report.summary.safe_cases == 5
    assert report.summary.vulnerable_cases == 0
    assert report.summary.security_posture == SecurityPosture.MODERATE

    errored = next(r for r in report.results if r.case_id == "PI-003")
    assert errored.status == CaseStatus.ERROR
    assert errored.error is not None
    assert "secret999999999" not in errored.error
    assert "[REDACTED" in errored.error

    # Fail-closed policy gate rejects runs with probe execution errors.
    assert report.summary.policy_gate is not None
    assert report.summary.policy_gate.passed is False
    assert any("fail-closed" in reason for reason in report.summary.policy_gate.reasons)


def test_compute_summary_handles_empty_result_list() -> None:
    summary = compute_summary(
        [],
        total_duration_ms=0.0,
        policy_gate=PolicyGateConfig(fail_on_severity=CaseSeverity.LOW),
    )
    assert summary.total_cases == 0
    assert summary.defense_pass_rate == 1.0
    assert summary.security_posture == SecurityPosture.HARDENED
    assert summary.policy_gate is not None and summary.policy_gate.passed is True


async def test_run_store_persistence_lru_eviction_and_path_traversal_guard(
    registry: AttackRegistry, tmp_path: Path
) -> None:
    runner = EvaluationRunner(registry)
    judge = MockJudgeEngine()
    target = MockTargetAdapter(MockProfile.BASELINE)

    store = RunStore(max_runs=2, artifacts_dir=tmp_path)
    reports = [
        await runner.run(target=target, judge=judge, suites=["prompt_injection"]) for _ in range(3)
    ]
    for rep in reports:
        store.save(rep)

    # In-memory LRU retains only the 2 newest runs, ordered newest-first.
    assert store.count() == 2
    total, items = store.list_runs(limit=10, offset=0)
    assert total == 2
    assert [item.run_id for item in items] == [reports[2].run_id, reports[1].run_id]

    # Reloading a new RunStore instance hydrates persisted artifacts from disk.
    rehydrated = RunStore(max_runs=5, artifacts_dir=tmp_path)
    loaded = rehydrated.get(reports[2].run_id)
    assert loaded is not None
    assert loaded.run_id == reports[2].run_id
    assert loaded.summary.vulnerable_cases == reports[2].summary.vulnerable_cases

    # Delete removes both memory and disk artifact.
    assert rehydrated.delete(reports[2].run_id) is True
    assert rehydrated.get(reports[2].run_id) is None
    assert not (tmp_path / f"{reports[2].run_id}.json").exists()
    assert rehydrated.delete(reports[2].run_id) is False

    # Path traversal / malformed run IDs safely rejected.
    assert rehydrated.get("../../etc/passwd") is None
    assert rehydrated.delete("../run_000000000000") is False
    bad_report = reports[0].model_copy(update={"run_id": "../evil"})
    try:
        rehydrated.save(bad_report)
        raise AssertionError("Expected ValueError for malformed run_id")
    except ValueError:
        pass
