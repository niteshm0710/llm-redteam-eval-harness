"""Typed domain and API schemas for attacks, grading rubrics, and evaluation reports."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator


class AttackCategory(StrEnum):
    """Canonical adversarial attack suite categories."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    PII_LEAKAGE = "pii_leakage"


class CaseSeverity(StrEnum):
    """Inherent severity assigned to an adversarial attack probe or policy threshold."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANKS[self.value]


class Severity(StrEnum):
    """Evaluated finding severity emitted by the LLM-as-a-Judge engine."""

    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANKS[self.value]

    @classmethod
    def from_case_severity(cls, value: CaseSeverity) -> Severity:
        return cls(value.value)


_SEVERITY_RANKS: dict[str, int] = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class Verdict(StrEnum):
    """Binary security outcome for a graded target response."""

    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"


class SecurityPosture(StrEnum):
    """Aggregate deployment security rating computed over an evaluation run."""

    HARDENED = "HARDENED"
    MODERATE = "MODERATE"
    AT_RISK = "AT_RISK"
    CRITICAL = "CRITICAL"


class ProviderMode(StrEnum):
    """Supported target and judge execution backends."""

    MOCK = "mock"
    OPENAI_COMPATIBLE = "openai_compatible"


class MockProfile(StrEnum):
    """Deterministic offline target defense postures for local testing and demos."""

    VULNERABLE = "vulnerable"
    BASELINE = "baseline"
    HARDENED = "hardened"


class MutationType(StrEnum):
    """Deterministic prompt mutation transforms applied to attack probes."""

    BASE64_WRAP = "base64_wrap"
    DELIMITER_ESCAPE = "delimiter_escape"
    AUTHORITY_PREFIX = "authority_prefix"


class CaseStatus(StrEnum):
    """Execution status of an individual probe."""

    COMPLETED = "completed"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Attack Suite & Rubric Schemas
# ---------------------------------------------------------------------------


class AttackCase(BaseModel):
    """Single adversarial test case executed against a target LLM."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., min_length=2, max_length=80)
    suite: str = Field(..., min_length=2, max_length=64)
    category: AttackCategory
    name: str = Field(..., min_length=3, max_length=140)
    description: str = Field(..., min_length=5, max_length=600)
    prompt: str = Field(..., min_length=1, max_length=16_000)
    system_context_addendum: str | None = Field(
        default=None,
        description="Optional restricted system context appended for isolation/leakage tests.",
    )
    base_severity: CaseSeverity
    owasp_id: str = Field(..., description="OWASP Top 10 for LLM Applications (2025) identifier.")
    atlas_id: str = Field(..., description="MITRE ATLAS adversarial technique identifier.")
    tags: list[str] = Field(default_factory=list)
    success_indicators: list[str] = Field(
        default_factory=list,
        description="Deterministic compliance tokens indicating successful instruction override.",
    )
    sensitive_literals: list[str] = Field(
        default_factory=list,
        description="Confidential canaries, secrets, or PII literals that must never be disclosed.",
    )
    mutation: MutationType | None = Field(
        default=None,
        description="Prompt mutation transform applied to produce this variant, if any.",
    )


class AttackSuiteInfo(BaseModel):
    """Metadata summary for a registered adversarial attack suite."""

    name: str
    category: AttackCategory
    title: str
    description: str
    owasp_id: str
    atlas_ids: list[str]
    case_count: int
    severity_counts: dict[str, int]


class AttackSuiteDetail(AttackSuiteInfo):
    """Full attack suite payload including its constituent attack cases."""

    cases: list[AttackCase]


class MutationInfo(BaseModel):
    """Metadata describing a supported adversarial prompt mutation transform."""

    name: MutationType
    title: str
    description: str


class RubricCriterion(BaseModel):
    """Single security criterion within an LLM-as-a-Judge grading rubric."""

    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    description: str
    default_severity: CaseSeverity


class SecurityRubric(BaseModel):
    """Structured security rubric governing evaluation for an attack category."""

    model_config = ConfigDict(frozen=True)

    rubric_id: str
    category: AttackCategory
    title: str
    description: str
    pass_definition: str
    fail_definition: str
    criteria: list[RubricCriterion]
    remediation_guidance: str


# ---------------------------------------------------------------------------
# Provider & Policy Configuration Schemas
# ---------------------------------------------------------------------------


def _validate_extra_headers(headers: dict[str, str]) -> dict[str, str]:
    if len(headers) > 20:
        raise ValueError("extra_headers cannot contain more than 20 entries.")
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        header_name = key.strip()
        if not header_name:
            raise ValueError("Header names cannot be empty.")
        if any(ch in header_name or ch in value for ch in ("\r", "\n", "\x00")):
            raise ValueError("Header names and values must not contain CR/LF/NUL characters.")
        if header_name.lower() in {"host", "content-length", "transfer-encoding"}:
            raise ValueError(f"Header '{header_name}' is restricted.")
        cleaned[header_name] = value.strip()
    return cleaned


class TargetConfig(BaseModel):
    """Configuration for the target LLM endpoint under evaluation."""

    mode: ProviderMode = ProviderMode.MOCK
    mock_profile: MockProfile = MockProfile.BASELINE
    base_url: str | None = Field(
        default=None,
        max_length=512,
        description="OpenAI-compatible API base URL (e.g. https://api.openai.com/v1).",
    )
    model: str | None = Field(default=None, max_length=128)
    api_key: SecretStr | None = Field(default=None, exclude=True)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    max_tokens: int = Field(default=512, ge=16, le=4096)
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=180.0)
    max_retries: int = Field(default=2, ge=0, le=5)
    system_prompt: str | None = Field(
        default=None,
        max_length=16_000,
        description="Optional custom target system prompt (defaults to SentinelAssist prompt).",
    )
    extra_headers: dict[str, str] = Field(default_factory=dict, exclude=True)

    @field_validator("extra_headers")
    @classmethod
    def _check_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return _validate_extra_headers(value)


class JudgeConfig(BaseModel):
    """Configuration for the automated LLM-as-a-Judge grading engine."""

    mode: ProviderMode = ProviderMode.MOCK
    base_url: str | None = Field(default=None, max_length=512)
    model: str | None = Field(default=None, max_length=128)
    api_key: SecretStr | None = Field(default=None, exclude=True)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    max_tokens: int = Field(default=512, ge=64, le=2048)
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=180.0)
    max_retries: int = Field(default=2, ge=0, le=5)
    enforce_deterministic_guardrails: bool = Field(
        default=True,
        description=(
            "Enforce deterministic canary/PII floor checks on top of LLM judge verdicts "
            "to defend against judge prompt-injection and missed verbatim leaks."
        ),
    )
    extra_headers: dict[str, str] = Field(default_factory=dict, exclude=True)

    @field_validator("extra_headers")
    @classmethod
    def _check_headers(cls, value: dict[str, str]) -> dict[str, str]:
        return _validate_extra_headers(value)


class PolicyGateConfig(BaseModel):
    """Optional CI/CD release-gate thresholds applied to an evaluation summary."""

    fail_on_severity: CaseSeverity | None = Field(
        default=None,
        description="Fail the policy gate if any VULNERABLE case has severity >= this threshold.",
    )
    max_attack_success_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Fail the policy gate if aggregate attack_success_rate exceeds this ratio.",
    )


class PolicyGateResult(BaseModel):
    """Outcome of evaluating an EvaluationSummary against a PolicyGateConfig."""

    passed: bool
    fail_on_severity: CaseSeverity | None = None
    max_attack_success_rate: float | None = None
    reasons: list[str] = Field(default_factory=list)


class SanitizedEndpointInfo(BaseModel):
    """Credential-free provider descriptor persisted in evaluation reports."""

    mode: ProviderMode
    model: str
    base_url: str | None = None
    mock_profile: MockProfile | None = None


# ---------------------------------------------------------------------------
# Judge Output & Evaluation Report Schemas
# ---------------------------------------------------------------------------


class JudgeEvaluation(BaseModel):
    """Structured security score produced by the LLM-as-a-Judge grading engine."""

    verdict: Verdict
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Normalized vulnerability score: 0.0 = fully safe, 1.0 = fully compromised.",
    )
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    rubric_id: str
    violated_criteria: list[str] = Field(default_factory=list)
    matched_indicators: list[str] = Field(default_factory=list)
    explanation: str = Field(..., min_length=5)
    remediation: str = Field(..., min_length=5)
    judge_mode: ProviderMode

    @model_validator(mode="after")
    def _enforce_verdict_severity_consistency(self) -> JudgeEvaluation:
        if self.verdict == Verdict.SAFE:
            if self.severity != Severity.NONE:
                raise ValueError("SAFE verdicts must have severity 'NONE'.")
            if self.violated_criteria:
                raise ValueError("SAFE verdicts must not contain violated_criteria.")
        elif self.verdict == Verdict.VULNERABLE and self.severity == Severity.NONE:
            raise ValueError("VULNERABLE verdicts must specify a non-NONE severity.")
        return self


class CaseResult(BaseModel):
    """Full execution and grading record for a single adversarial probe."""

    case_id: str
    suite: str
    category: AttackCategory
    case_name: str
    base_severity: CaseSeverity
    owasp_id: str
    atlas_id: str
    mutation: MutationType | None = None
    status: CaseStatus
    prompt: str
    target_response: str
    target_model: str
    latency_ms: float = Field(..., ge=0.0)
    evaluation: JudgeEvaluation
    error: str | None = None


class CategorySummary(BaseModel):
    """Aggregated vulnerability metrics for a single attack category."""

    category: AttackCategory
    total_cases: int
    safe_cases: int
    vulnerable_cases: int
    error_cases: int
    attack_success_rate: float = Field(..., ge=0.0, le=1.0)
    defense_pass_rate: float = Field(..., ge=0.0, le=1.0)
    mean_risk_score: float = Field(..., ge=0.0, le=1.0)
    max_severity: Severity


class EvaluationSummary(BaseModel):
    """Top-level security posture scorecard for an evaluation run."""

    total_cases: int
    safe_cases: int
    vulnerable_cases: int
    error_cases: int
    attack_success_rate: float = Field(..., ge=0.0, le=1.0)
    defense_pass_rate: float = Field(..., ge=0.0, le=1.0)
    overall_risk_score: float = Field(..., ge=0.0, le=1.0)
    security_posture: SecurityPosture
    highest_severity: Severity
    severity_breakdown: dict[str, int]
    category_breakdown: dict[str, CategorySummary]
    total_duration_ms: float = Field(..., ge=0.0)
    policy_gate: PolicyGateResult | None = None


class EvaluationReport(BaseModel):
    """Complete persisted report produced by an evaluation run."""

    run_id: str
    created_at: datetime
    completed_at: datetime
    target: SanitizedEndpointInfo
    judge: SanitizedEndpointInfo
    suites_executed: list[str]
    mutations_applied: list[MutationType] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    summary: EvaluationSummary
    results: list[CaseResult]


class EvaluationListItem(BaseModel):
    """Compact evaluation summary returned by list endpoints."""

    run_id: str
    created_at: datetime
    target: SanitizedEndpointInfo
    judge: SanitizedEndpointInfo
    suites_executed: list[str]
    total_cases: int
    safe_cases: int
    vulnerable_cases: int
    attack_success_rate: float
    defense_pass_rate: float
    security_posture: SecurityPosture
    highest_severity: Severity


# ---------------------------------------------------------------------------
# API Request / Response Envelopes
# ---------------------------------------------------------------------------


class EvaluationRequest(BaseModel):
    """Request payload for `POST /api/v1/evaluations`."""

    target: TargetConfig = Field(default_factory=TargetConfig)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    suites: list[str] | None = Field(
        default=None,
        description="Suite names to execute; omit or pass null to run all registered suites.",
    )
    case_ids: list[str] | None = Field(
        default=None,
        description="Optional explicit subset of attack case IDs to execute.",
    )
    min_severity: CaseSeverity | None = Field(
        default=None,
        description="Only run probes with base_severity >= this threshold.",
    )
    mutations: list[MutationType] = Field(
        default_factory=list,
        description="Optional prompt mutations appended alongside canonical probes.",
    )
    include_base_cases: bool = Field(
        default=True,
        description="Include unmutated probes when `mutations` are also specified.",
    )
    concurrency: int = Field(default=5, ge=1, le=50)
    policy_gate: PolicyGateConfig | None = None
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 25:
            raise ValueError("metadata cannot contain more than 25 keys.")
        for key, item in value.items():
            if len(key) > 64 or len(item) > 256:
                raise ValueError("metadata keys must be <=64 chars and values <=256 chars.")
        return value

    @model_validator(mode="after")
    def _validate_mutation_selection(self) -> EvaluationRequest:
        if not self.include_base_cases and not self.mutations:
            raise ValueError("Must specify at least one mutation when include_base_cases is false.")
        return self


class EvaluationListResponse(BaseModel):
    """Paginated response payload for `GET /api/v1/evaluations`."""

    total: int
    limit: int
    offset: int
    items: list[EvaluationListItem]


class ProbeRequest(BaseModel):
    """Request payload for ad-hoc single-prompt testing or offline response grading."""

    prompt: str = Field(..., min_length=1, max_length=16_000)
    category: AttackCategory = AttackCategory.PROMPT_INJECTION
    base_severity: CaseSeverity = CaseSeverity.HIGH
    target_response: str | None = Field(
        default=None,
        max_length=32_000,
        description=(
            "Optional pre-captured target response. When supplied, target invocation is "
            "skipped and the judge grades `(prompt, target_response)` directly."
        ),
    )
    success_indicators: list[str] = Field(default_factory=list, max_length=20)
    sensitive_literals: list[str] = Field(default_factory=list, max_length=20)
    target: TargetConfig = Field(default_factory=TargetConfig)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)


class ProbeResponse(BaseModel):
    """Structured result for a single ad-hoc probe execution."""

    category: AttackCategory
    prompt: str
    target_response: str
    target_model: str
    latency_ms: float
    evaluation: JudgeEvaluation


class CompareRequest(BaseModel):
    """Request payload comparing multiple deterministic mock defense postures."""

    profiles: list[MockProfile] = Field(
        default_factory=lambda: [
            MockProfile.VULNERABLE,
            MockProfile.BASELINE,
            MockProfile.HARDENED,
        ],
        min_length=1,
        max_length=3,
    )
    suites: list[str] | None = None
    min_severity: CaseSeverity | None = None
    mutations: list[MutationType] = Field(default_factory=list)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)


class ProfileComparisonEntry(BaseModel):
    """Summary metrics for one profile inside a comparative benchmark."""

    profile: MockProfile
    run_id: str
    summary: EvaluationSummary


class CompareResponse(BaseModel):
    """Side-by-side posture comparison across evaluated profiles."""

    suites_executed: list[str]
    comparisons: list[ProfileComparisonEntry]


class HealthResponse(BaseModel):
    """Liveness and capability payload for `GET /health`."""

    status: str
    version: str
    registered_suites: list[str]
    total_attack_cases: int
    gateway_auth_enabled: bool
    allow_private_targets: bool
    stored_runs: int
    capabilities: dict[str, Any]
