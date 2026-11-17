"""Bounded in-memory evaluation report store with optional disk persistence."""

from __future__ import annotations

import re
import threading
from collections import OrderedDict
from pathlib import Path

from redteam_harness.schemas import EvaluationListItem, EvaluationReport

_RUN_ID_RE = re.compile(r"^run_[a-f0-9]{12}$")


class RunStore:
    """Thread-safe LRU evaluation store with optional atomic JSON file persistence."""

    def __init__(self, *, max_runs: int = 200, artifacts_dir: Path | None = None) -> None:
        self._max_runs = max(1, max_runs)
        self._artifacts_dir = artifacts_dir
        self._lock = threading.RLock()
        self._runs: OrderedDict[str, EvaluationReport] = OrderedDict()

        if self._artifacts_dir is not None:
            self._artifacts_dir.mkdir(parents=True, exist_ok=True)
            self._hydrate_from_disk()

    def _hydrate_from_disk(self) -> None:
        if self._artifacts_dir is None:
            return
        files = sorted(self._artifacts_dir.glob("run_*.json"), key=lambda p: p.stat().st_mtime)
        for path in files[-self._max_runs :]:
            try:
                report = EvaluationReport.model_validate_json(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if _RUN_ID_RE.fullmatch(report.run_id):
                self._runs[report.run_id] = report

    def _artifact_path(self, run_id: str) -> Path | None:
        if self._artifacts_dir is None or not _RUN_ID_RE.fullmatch(run_id):
            return None
        return self._artifacts_dir / f"{run_id}.json"

    def save(self, report: EvaluationReport) -> None:
        """Store `report` in memory and optionally persist atomically to disk."""
        if not _RUN_ID_RE.fullmatch(report.run_id):
            raise ValueError(f"Invalid run_id format: '{report.run_id}'.")

        with self._lock:
            self._runs[report.run_id] = report
            self._runs.move_to_end(report.run_id)
            while len(self._runs) > self._max_runs:
                self._runs.popitem(last=False)

            artifact = self._artifact_path(report.run_id)
            if artifact is not None:
                tmp_path = artifact.with_suffix(".json.tmp")
                tmp_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
                tmp_path.replace(artifact)

    def get(self, run_id: str) -> EvaluationReport | None:
        """Retrieve a stored `EvaluationReport` by `run_id`, or `None` if absent."""
        if not _RUN_ID_RE.fullmatch(run_id):
            return None
        with self._lock:
            report = self._runs.get(run_id)
            if report is not None:
                return report
            artifact = self._artifact_path(run_id)
            if artifact is not None and artifact.is_file():
                loaded = EvaluationReport.model_validate_json(artifact.read_text(encoding="utf-8"))
                self._runs[run_id] = loaded
                return loaded
            return None

    def list_runs(
        self, *, limit: int = 20, offset: int = 0
    ) -> tuple[int, list[EvaluationListItem]]:
        """Return `(total_count, page_items)` ordered newest-first."""
        with self._lock:
            ordered = list(reversed(self._runs.values()))
        total = len(ordered)
        sliced = ordered[offset : offset + limit]
        items = [
            EvaluationListItem(
                run_id=rep.run_id,
                created_at=rep.created_at,
                target=rep.target,
                judge=rep.judge,
                suites_executed=rep.suites_executed,
                total_cases=rep.summary.total_cases,
                safe_cases=rep.summary.safe_cases,
                vulnerable_cases=rep.summary.vulnerable_cases,
                attack_success_rate=rep.summary.attack_success_rate,
                defense_pass_rate=rep.summary.defense_pass_rate,
                security_posture=rep.summary.security_posture,
                highest_severity=rep.summary.highest_severity,
            )
            for rep in sliced
        ]
        return total, items

    def delete(self, run_id: str) -> bool:
        """Delete a stored evaluation report. Returns `True` if a report was removed."""
        if not _RUN_ID_RE.fullmatch(run_id):
            return False
        with self._lock:
            removed = self._runs.pop(run_id, None) is not None
            artifact = self._artifact_path(run_id)
            if artifact is not None and artifact.exists():
                artifact.unlink()
                removed = True
            return removed

    def count(self) -> int:
        with self._lock:
            return len(self._runs)
