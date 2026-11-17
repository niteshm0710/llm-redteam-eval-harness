"""Command-line runner for the LLM Red-Team & Prompt-Injection Evaluation Harness."""

from __future__ import annotations

import asyncio
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from pydantic import SecretStr
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from redteam_harness import __version__
from redteam_harness.attacks import (
    UnknownCaseError,
    UnknownSuiteError,
    create_default_registry,
    list_mutations,
)
from redteam_harness.config import HarnessSettings
from redteam_harness.core import EvaluationRunner, redact_secrets
from redteam_harness.judge import (
    JudgeParseError,
    build_judge_engine,
    get_rubric,
    list_rubrics,
)
from redteam_harness.schemas import (
    AttackCategory,
    CaseSeverity,
    CaseStatus,
    EvaluationReport,
    JudgeConfig,
    MockProfile,
    MutationType,
    PolicyGateConfig,
    ProbeRequest,
    ProbeResponse,
    ProviderMode,
    Severity,
    TargetConfig,
    Verdict,
)
from redteam_harness.targets import (
    EgressPolicyError,
    TargetInvocationError,
    build_target_adapter,
)


class OutputFormat(StrEnum):
    """CLI report rendering formats."""

    TABLE = "table"
    JSON = "json"


cli_app = typer.Typer(
    name="redteam",
    help=(
        "LLM Red-Team & Prompt-Injection Evaluation Harness — test target LLM endpoints "
        "against modular adversarial suites with automated LLM-as-a-Judge rubric scoring."
    ),
    no_args_is_help=True,
    add_completion=False,
)

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.NONE: "green",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "bold red",
    Severity.CRITICAL: "bold white on red",
}


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"redteam {__version__}")
        raise typer.Exit()


@cli_app.callback()
def _root_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Show harness version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Global options for the `redteam` CLI."""


@cli_app.command("suites")
def suites_command(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="List every individual probe across suites."),
    ] = False,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format (table or json)."),
    ] = OutputFormat.TABLE,
) -> None:
    """List registered adversarial attack suites, OWASP/ATLAS mappings, and probes."""
    registry = create_default_registry()
    suites = registry.list_suites()

    if output_format == OutputFormat.JSON:
        if verbose:
            details = [
                registry.get_plugin(s.name).get_detail().model_dump(mode="json") for s in suites
            ]
            import json

            typer.echo(json.dumps(details, indent=2))
        else:
            import json

            typer.echo(json.dumps([s.model_dump(mode="json") for s in suites], indent=2))
        return

    console = Console()
    table = Table(
        title="Registered Adversarial Attack Suites",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
    )
    table.add_column("Suite", style="bold")
    table.add_column("Title")
    table.add_column("OWASP", style="magenta")
    table.add_column("MITRE ATLAS", style="blue")
    table.add_column("Probes", justify="right")
    table.add_column("Severity Mix (C/H/M/L)", justify="right")

    for info in suites:
        sc = info.severity_counts
        mix = f"{sc['CRITICAL']}/{sc['HIGH']}/{sc['MEDIUM']}/{sc['LOW']}"
        table.add_row(
            info.name,
            info.title,
            info.owasp_id,
            ", ".join(info.atlas_ids),
            str(info.case_count),
            mix,
        )
    console.print(table)

    mutations_str = ", ".join(m.name.value for m in list_mutations())
    console.print(
        f"Total canonical probes: [bold]{registry.total_case_count()}[/bold]  |  "
        f"Available mutations: [cyan]{mutations_str}[/cyan]"
    )

    if verbose:
        cases_table = Table(
            title="Adversarial Probe Catalog",
            box=box.SIMPLE,
            header_style="bold cyan",
        )
        cases_table.add_column("ID", style="bold")
        cases_table.add_column("Suite")
        cases_table.add_column("Severity")
        cases_table.add_column("Name")
        cases_table.add_column("Tags", style="dim")
        for info in suites:
            for case in registry.get_plugin(info.name).get_cases():
                cases_table.add_row(
                    case.id,
                    case.suite,
                    case.base_severity.value,
                    case.name,
                    ", ".join(case.tags),
                )
        console.print(cases_table)


@cli_app.command("rubrics")
def rubrics_command(
    category: Annotated[
        AttackCategory | None,
        typer.Option("--category", "-c", help="Filter to a single attack category."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format (table or json)."),
    ] = OutputFormat.TABLE,
) -> None:
    """Display LLM-as-a-Judge security rubrics and failure criteria."""
    rubrics = [get_rubric(category)] if category is not None else list_rubrics()
    if output_format == OutputFormat.JSON:
        import json

        typer.echo(json.dumps([r.model_dump(mode="json") for r in rubrics], indent=2))
        return

    console = Console()
    for rubric in rubrics:
        criteria_lines = "\n".join(
            f"  • [bold]{c.id}[/bold] ({c.default_severity.value}) — {c.title}: {c.description}"
            for c in rubric.criteria
        )
        body = (
            f"[dim]{rubric.description}[/dim]\n\n"
            f"[green]PASS:[/green] {rubric.pass_definition}\n"
            f"[red]FAIL:[/red] {rubric.fail_definition}\n\n"
            f"[bold]Criteria:[/bold]\n{criteria_lines}\n\n"
            f"[cyan]Remediation:[/cyan] {rubric.remediation_guidance}"
        )
        console.print(Panel(body, title=f"{rubric.rubric_id} — {rubric.title}", expand=False))


@cli_app.command("run")
def run_command(
    target_mode: Annotated[
        ProviderMode,
        typer.Option("--target", "-t", help="Target LLM adapter mode."),
    ] = ProviderMode.MOCK,
    mock_profile: Annotated[
        MockProfile,
        typer.Option("--mock-profile", "-p", help="Defense posture when --target=mock."),
    ] = MockProfile.BASELINE,
    target_url: Annotated[
        str | None,
        typer.Option("--target-url", help="OpenAI-compatible target base URL."),
    ] = None,
    target_model: Annotated[
        str | None,
        typer.Option("--target-model", help="Target model identifier."),
    ] = None,
    target_api_key: Annotated[
        str | None,
        typer.Option(
            "--target-api-key", help="Target API key (prefer REDTEAM_TARGET_API_KEY env)."
        ),
    ] = None,
    judge_mode: Annotated[
        ProviderMode,
        typer.Option("--judge", "-j", help="LLM-as-a-Judge backend mode."),
    ] = ProviderMode.MOCK,
    judge_url: Annotated[
        str | None,
        typer.Option("--judge-url", help="OpenAI-compatible judge base URL."),
    ] = None,
    judge_model: Annotated[
        str | None,
        typer.Option("--judge-model", help="Judge model identifier."),
    ] = None,
    judge_api_key: Annotated[
        str | None,
        typer.Option("--judge-api-key", help="Judge API key (prefer REDTEAM_JUDGE_API_KEY env)."),
    ] = None,
    suite: Annotated[
        list[str] | None,
        typer.Option("--suite", "-s", help="Attack suite name (repeatable; defaults to all)."),
    ] = None,
    case_id: Annotated[
        list[str] | None,
        typer.Option("--case-id", help="Specific attack case ID to run (repeatable)."),
    ] = None,
    min_severity: Annotated[
        CaseSeverity | None,
        typer.Option("--min-severity", help="Run only probes with base severity >= threshold."),
    ] = None,
    mutation: Annotated[
        list[MutationType] | None,
        typer.Option("--mutation", "-m", help="Append deterministic prompt mutation(s)."),
    ] = None,
    system_prompt_file: Annotated[
        Path | None,
        typer.Option(
            "--system-prompt-file",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
            help="Path to a custom target system prompt text file.",
        ),
    ] = None,
    concurrency: Annotated[
        int,
        typer.Option("--concurrency", min=1, max=50, help="Maximum concurrent probe executions."),
    ] = 5,
    fail_on: Annotated[
        CaseSeverity | None,
        typer.Option(
            "--fail-on",
            help="CI gate: exit code 2 if any VULNERABLE finding meets or exceeds severity.",
        ),
    ] = None,
    max_asr: Annotated[
        float | None,
        typer.Option(
            "--max-asr",
            min=0.0,
            max=1.0,
            help="CI gate: exit code 2 if attack success rate exceeds ratio (e.g. 0.10).",
        ),
    ] = None,
    allow_local_urls: Annotated[
        bool,
        typer.Option(
            "--allow-local/--deny-local",
            help="Permit loopback/private target URLs (e.g. local Ollama/vLLM) from CLI.",
        ),
    ] = True,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Console output format (table or json)."),
    ] = OutputFormat.TABLE,
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write full structured JSON report to path."),
    ] = None,
    show_all: Annotated[
        bool,
        typer.Option("--show-all", help="Show both SAFE and VULNERABLE probes in findings table."),
    ] = False,
) -> None:
    """Execute adversarial attack suites against a target LLM and grade responses."""
    err_console = Console(stderr=True)
    settings = HarnessSettings.from_env()
    custom_prompt = (
        system_prompt_file.read_text(encoding="utf-8") if system_prompt_file is not None else None
    )

    target_cfg = TargetConfig(
        mode=target_mode,
        mock_profile=mock_profile,
        base_url=target_url,
        model=target_model,
        api_key=SecretStr(target_api_key) if target_api_key else None,
        system_prompt=custom_prompt,
    )
    judge_cfg = JudgeConfig(
        mode=judge_mode,
        base_url=judge_url,
        model=judge_model,
        api_key=SecretStr(judge_api_key) if judge_api_key else None,
    )
    gate = (
        PolicyGateConfig(fail_on_severity=fail_on, max_attack_success_rate=max_asr)
        if (fail_on is not None or max_asr is not None)
        else None
    )

    async def _execute() -> EvaluationReport:
        registry = create_default_registry()
        runner = EvaluationRunner(
            registry, max_concurrency=max(concurrency, settings.max_concurrency)
        )
        target = build_target_adapter(target_cfg, settings, allow_private_override=allow_local_urls)
        judge = build_judge_engine(judge_cfg, settings, allow_private_override=allow_local_urls)
        try:
            return await runner.run(
                target=target,
                judge=judge,
                suites=suite or None,
                case_ids=case_id or None,
                min_severity=min_severity,
                mutations=mutation or None,
                system_prompt=custom_prompt,
                concurrency=concurrency,
                policy_gate=gate,
            )
        finally:
            await target.aclose()
            await judge.aclose()

    try:
        report = asyncio.run(_execute())
    except (UnknownSuiteError, UnknownCaseError, EgressPolicyError, ValueError) as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if output_file is not None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    if output_format == OutputFormat.JSON:
        typer.echo(report.model_dump_json(indent=2))
    else:
        _render_evaluation_table(Console(), report, show_all=show_all, output_file=output_file)

    if report.summary.policy_gate is not None and not report.summary.policy_gate.passed:
        raise typer.Exit(code=2)


@cli_app.command("probe")
def probe_command(
    prompt: Annotated[
        str,
        typer.Option("--prompt", help="Adversarial prompt to execute or evaluate."),
    ],
    category: Annotated[
        AttackCategory,
        typer.Option("--category", "-c", help="Security rubric category to grade against."),
    ] = AttackCategory.PROMPT_INJECTION,
    response: Annotated[
        str | None,
        typer.Option(
            "--response",
            help="Optional pre-captured target response (grades directly without querying target).",
        ),
    ] = None,
    target_mode: Annotated[
        ProviderMode,
        typer.Option("--target", "-t", help="Target LLM adapter mode."),
    ] = ProviderMode.MOCK,
    mock_profile: Annotated[
        MockProfile,
        typer.Option("--mock-profile", "-p", help="Defense posture when --target=mock."),
    ] = MockProfile.BASELINE,
    target_url: Annotated[str | None, typer.Option("--target-url")] = None,
    target_model: Annotated[str | None, typer.Option("--target-model")] = None,
    judge_mode: Annotated[
        ProviderMode,
        typer.Option("--judge", "-j", help="LLM-as-a-Judge backend mode."),
    ] = ProviderMode.MOCK,
    judge_url: Annotated[str | None, typer.Option("--judge-url")] = None,
    judge_model: Annotated[str | None, typer.Option("--judge-model")] = None,
    indicator: Annotated[
        list[str] | None,
        typer.Option("--indicator", help="Optional compliance marker indicating compromise."),
    ] = None,
    sensitive: Annotated[
        list[str] | None,
        typer.Option("--sensitive", help="Optional confidential literal that must not leak."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format (json or table)."),
    ] = OutputFormat.JSON,
) -> None:
    """Run a single ad-hoc prompt probe (or grade a captured response) and emit JSON scores."""
    err_console = Console(stderr=True)
    settings = HarnessSettings.from_env()
    req = ProbeRequest(
        prompt=prompt,
        category=category,
        target_response=response,
        success_indicators=indicator or [],
        sensitive_literals=sensitive or [],
        target=TargetConfig(
            mode=target_mode,
            mock_profile=mock_profile,
            base_url=target_url,
            model=target_model,
        ),
        judge=JudgeConfig(
            mode=judge_mode,
            base_url=judge_url,
            model=judge_model,
        ),
    )

    async def _execute() -> ProbeResponse:
        runner = EvaluationRunner(create_default_registry())
        target = (
            build_target_adapter(req.target, settings, allow_private_override=True)
            if req.target_response is None
            else None
        )
        judge = build_judge_engine(req.judge, settings, allow_private_override=True)
        try:
            return await runner.run_probe(request=req, target=target, judge=judge)
        finally:
            if target is not None:
                await target.aclose()
            await judge.aclose()

    try:
        result = asyncio.run(_execute())
    except (EgressPolicyError, TargetInvocationError, JudgeParseError, ValueError) as exc:
        err_console.print(f"[bold red]Error:[/bold red] {redact_secrets(str(exc))}")
        raise typer.Exit(code=1) from exc

    if output_format == OutputFormat.JSON:
        typer.echo(result.model_dump_json(indent=2))
        return

    console = Console()
    ev = result.evaluation
    verdict_style = "bold green" if ev.verdict == Verdict.SAFE else "bold red"
    console.print(
        Panel(
            f"[bold]Target Model:[/bold] {result.target_model} ({result.latency_ms:.1f} ms)\n"
            f"[bold]Verdict:[/bold] [{verdict_style}]{ev.verdict.value}[/{verdict_style}]  |  "
            f"[bold]Severity:[/bold] {ev.severity.value}  |  "
            f"[bold]Risk Score:[/bold] {ev.risk_score:.2f}  |  "
            f"[bold]Confidence:[/bold] {ev.confidence:.2f}\n"
            f"[bold]Rubric:[/bold] {ev.rubric_id}\n"
            f"[bold]Violated Criteria:[/bold] {', '.join(ev.violated_criteria) or 'None'}\n"
            f"[bold]Target Response:[/bold] {result.target_response}\n\n"
            f"[bold]Explanation:[/bold] {ev.explanation}\n"
            f"[bold]Remediation:[/bold] {ev.remediation}",
            title=f"Ad-Hoc Probe Result ({result.category.value})",
            expand=False,
        )
    )


@cli_app.command("compare")
def compare_command(
    suite: Annotated[
        list[str] | None,
        typer.Option("--suite", "-s", help="Restrict comparison to specific suite(s)."),
    ] = None,
    mutation: Annotated[
        list[MutationType] | None,
        typer.Option("--mutation", "-m", help="Include prompt mutation(s) across all profiles."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format (table or json)."),
    ] = OutputFormat.TABLE,
) -> None:
    """Run an offline benchmark comparing vulnerable, baseline, and hardened defense profiles."""
    err_console = Console(stderr=True)
    settings = HarnessSettings.from_env()
    profiles = [MockProfile.VULNERABLE, MockProfile.BASELINE, MockProfile.HARDENED]

    async def _execute() -> list[tuple[MockProfile, EvaluationReport]]:
        registry = create_default_registry()
        runner = EvaluationRunner(registry)
        judge = build_judge_engine(JudgeConfig(mode=ProviderMode.MOCK), settings)
        outputs: list[tuple[MockProfile, EvaluationReport]] = []
        try:
            for profile in profiles:
                target = build_target_adapter(
                    TargetConfig(mode=ProviderMode.MOCK, mock_profile=profile), settings
                )
                try:
                    rep = await runner.run(
                        target=target,
                        judge=judge,
                        suites=suite or None,
                        mutations=mutation or None,
                    )
                finally:
                    await target.aclose()
                outputs.append((profile, rep))
            return outputs
        finally:
            await judge.aclose()

    try:
        rows = asyncio.run(_execute())
    except (UnknownSuiteError, ValueError) as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    if output_format == OutputFormat.JSON:
        import json

        payload = {
            "suites_executed": rows[0][1].suites_executed if rows else [],
            "comparisons": [
                {
                    "profile": profile.value,
                    "run_id": rep.run_id,
                    "summary": rep.summary.model_dump(mode="json"),
                }
                for profile, rep in rows
            ],
        }
        typer.echo(json.dumps(payload, indent=2))
        return

    console = Console()
    table = Table(
        title="Mock Defense Posture Benchmark (Offline Deterministic Mode)",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
    )
    table.add_column("Profile", style="bold", no_wrap=True)
    table.add_column("Probes", justify="right")
    table.add_column("SAFE", justify="right", style="green")
    table.add_column("VULN", justify="right", style="red")
    table.add_column("ASR", justify="right")
    table.add_column("Pass Rate", justify="right")
    table.add_column("Risk", justify="right")
    table.add_column("Max Sev", no_wrap=True)
    table.add_column("Posture", style="bold", no_wrap=True)

    for profile, rep in rows:
        sm = rep.summary
        table.add_row(
            profile.value,
            str(sm.total_cases),
            str(sm.safe_cases),
            str(sm.vulnerable_cases),
            f"{sm.attack_success_rate:.1%}",
            f"{sm.defense_pass_rate:.1%}",
            f"{sm.overall_risk_score:.2f}",
            sm.highest_severity.value,
            sm.security_posture.value,
        )
    console.print(table)


@cli_app.command("serve")
def serve_command(
    host: Annotated[
        str,
        typer.Option("--host", help="Bind interface (use 127.0.0.1 locally or 0.0.0.0 in Docker)."),
    ] = "127.0.0.1",
    port: Annotated[
        int,
        typer.Option("--port", min=1, max=65535, help="TCP port to listen on."),
    ] = 8000,
    reload: Annotated[
        bool,
        typer.Option("--reload", help="Enable auto-reload for local development."),
    ] = False,
) -> None:
    """Start the FastAPI Red-Team Evaluation Harness HTTP server."""
    uvicorn.run("redteam_harness.api.app:app", host=host, port=port, reload=reload)


def _render_evaluation_table(
    console: Console,
    report: EvaluationReport,
    *,
    show_all: bool,
    output_file: Path | None,
) -> None:
    sm = report.summary
    posture_color = {
        "HARDENED": "bold green",
        "MODERATE": "bold yellow",
        "AT_RISK": "bold red",
        "CRITICAL": "bold white on red",
    }[sm.security_posture.value]

    header = (
        f"[bold]Run ID:[/bold] {report.run_id}   "
        f"[bold]Target:[/bold] {report.target.model} ({report.target.mode.value})   "
        f"[bold]Judge:[/bold] {report.judge.model} ({report.judge.mode.value})\n"
        f"[bold]Posture:[/bold] [{posture_color}]{sm.security_posture.value}[/{posture_color}]   "
        f"[bold]SAFE:[/bold] [green]{sm.safe_cases}/{sm.total_cases}[/green] "
        f"({sm.defense_pass_rate:.1%})   "
        f"[bold]VULNERABLE:[/bold] [red]{sm.vulnerable_cases}/{sm.total_cases}[/red] "
        f"(ASR {sm.attack_success_rate:.1%})   "
        f"[bold]Risk Score:[/bold] {sm.overall_risk_score:.2f}   "
        f"[bold]Duration:[/bold] {sm.total_duration_ms:.1f} ms"
    )
    console.print(Panel(header, title="LLM Red-Team Evaluation Summary", expand=False))

    cat_table = Table(
        title="Suite Breakdown",
        box=box.SIMPLE_HEAVY,
        header_style="bold cyan",
    )
    cat_table.add_column("Category", style="bold")
    cat_table.add_column("Total", justify="right")
    cat_table.add_column("SAFE", justify="right", style="green")
    cat_table.add_column("VULNERABLE", justify="right", style="red")
    cat_table.add_column("ASR", justify="right")
    cat_table.add_column("Mean Risk", justify="right")
    cat_table.add_column("Max Severity")

    for cat_key, cs in sm.category_breakdown.items():
        sev_style = _SEVERITY_STYLES[cs.max_severity]
        cat_table.add_row(
            cat_key,
            str(cs.total_cases),
            str(cs.safe_cases),
            str(cs.vulnerable_cases),
            f"{cs.attack_success_rate:.1%}",
            f"{cs.mean_risk_score:.2f}",
            f"[{sev_style}]{cs.max_severity.value}[/{sev_style}]",
        )
    console.print(cat_table)

    displayed = (
        report.results
        if show_all
        else [
            r
            for r in report.results
            if r.evaluation.verdict == Verdict.VULNERABLE or r.status == CaseStatus.ERROR
        ]
    )
    if displayed:
        title = "All Probe Verdicts" if show_all else "Vulnerable Findings & Policy Failures"
        findings = Table(title=title, box=box.SIMPLE, header_style="bold cyan")
        findings.add_column("Case ID", style="bold", no_wrap=True)
        findings.add_column("Category", no_wrap=True)
        findings.add_column("Verdict", no_wrap=True)
        findings.add_column("Severity", no_wrap=True)
        findings.add_column("Risk", justify="right", no_wrap=True)
        findings.add_column("Failure / Defense Explanation")

        for item in displayed:
            ev = item.evaluation
            v_label = (
                "[yellow]ERROR[/yellow]"
                if item.status == CaseStatus.ERROR
                else (
                    "[green]SAFE[/green]"
                    if ev.verdict == Verdict.SAFE
                    else "[bold red]VULNERABLE[/bold red]"
                )
            )
            sev_style = _SEVERITY_STYLES[ev.severity]
            findings.add_row(
                item.case_id,
                item.category.value,
                v_label,
                f"[{sev_style}]{ev.severity.value}[/{sev_style}]",
                f"{ev.risk_score:.2f}",
                ev.explanation,
            )
        console.print(findings)
    else:
        console.print(
            "[bold green]All executed probes passed with zero vulnerabilities.[/bold green]"
        )

    if sm.policy_gate is not None:
        if sm.policy_gate.passed:
            console.print("[bold green]Policy Gate: PASSED[/bold green]")
        else:
            console.print("[bold red]Policy Gate: FAILED[/bold red]")
            for reason in sm.policy_gate.reasons:
                console.print(f"  [red]• {reason}[/red]")

    if output_file is not None:
        console.print(f"[dim]Full JSON report written to {output_file}[/dim]")


def main() -> None:
    """Console script entry point registered as `redteam`."""
    cli_app()
