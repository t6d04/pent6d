"""Build the JSON payloads the viewer SPA consumes from a run directory."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import TYPE_CHECKING, Any

from strix.core.paths import run_record_path
from strix.interface.tui.live_view import TuiLiveView


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_TERMINAL_STATUSES = {"completed", "stopped", "failed", "interrupted"}

_KNOWN_SEVERITIES = ("critical", "high", "medium", "low")


def severity_counts(vulns: list[Any]) -> dict[str, int]:
    """Bucket vulnerabilities into critical/high/medium/low counts.

    Mirrors the SPA's ``severityCounts``: severities are lowercased and
    trimmed, and anything outside the four known buckets (``info``,
    ``informational``, ``unknown``, missing, ...) folds into ``low`` so the
    shared UI renders cleanly.
    """
    counts = dict.fromkeys(_KNOWN_SEVERITIES, 0)
    for vuln in vulns:
        raw = vuln.get("severity") if isinstance(vuln, dict) else None
        severity = str(raw or "").lower().strip()
        if severity not in counts:
            severity = "low"
        counts[severity] += 1
    return counts


def build_run_state(run_dir: Path) -> dict[str, Any]:
    """Agent graph + full per-agent event/message stream.

    Reuses the shared ``TuiLiveView`` projection so the viewer and the TUI
    share one parser for ``agents.json`` + ``agents.db`` and never drift.
    """
    view = TuiLiveView()
    view.hydrate_from_run_dir(run_dir)
    return {"agents": list(view.agents.values()), "events": view.events}


def read_run_summary(run_dir: Path) -> dict[str, Any]:
    """The ``run.json`` record plus a computed ``finished`` flag."""
    record = _load_json(run_record_path(run_dir), default={})
    if not isinstance(record, dict):
        record = {}
    status = record.get("status")
    finished = status in _TERMINAL_STATUSES and bool(record.get("end_time"))
    return {**record, "finished": finished}


def primary_target(record: dict[str, Any]) -> str | None:
    """The first target's original string from a run record, or None."""
    targets = record.get("targets_info")
    if isinstance(targets, list):
        for entry in targets:
            if isinstance(entry, dict):
                original = entry.get("original")
                if isinstance(original, str) and original:
                    return original
    return None


def read_vulnerabilities(run_dir: Path) -> list[Any]:
    """The ``vulnerabilities.json`` list (empty until a scan writes it)."""
    data = _load_json(run_dir / "vulnerabilities.json", default=[])
    return data if isinstance(data, list) else []


def _stable_issue_id(prefix: str, value: object, index: int) -> str:
    """Return a deterministic id for a non-vulnerability issue artifact.

    Older runs did not persist an id for coverage observations or Thinking
    hypotheses.  Hashing the serialized record keeps selection/export links
    stable across viewer refreshes while the index prevents collisions when
    two otherwise identical observations were recorded.
    """
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        encoded = repr(value)
    digest = hashlib.sha256(f"{index}:{encoded}".encode()).hexdigest()[:12]
    return f"{prefix}-{digest}"


def _issue_defaults(
    *, issue_id: str, title: str, severity: str, description: str, created_at: str | None
) -> dict[str, Any]:
    """Create the common shape consumed by the Issues UI for an observation."""
    return {
        "id": issue_id,
        "scan_id": None,
        "pr_review_id": None,
        "title": title,
        "description": description,
        "cve": None,
        "cvss": None,
        "created_at": created_at or "",
        "timestamp": created_at or "",
        "potential_risk_saving": None,
        "risk_saving_description": None,
        "status": "open",
        "severity": severity,
        "impact": None,
        "endpoint": None,
        "method": None,
        "target": None,
        "technical_analysis": None,
        "poc_description": None,
        "poc_script_code": None,
        "code_diff": None,
        "code_file": None,
        "code_before": None,
        "code_after": None,
        "cwe": None,
        "code_locations": None,
        "remediation_steps": None,
        "fix_pr_body": None,
        "related_report_ids": None,
        "evidence": None,
        "assumptions": None,
        "fix_effort": None,
        "cvss_breakdown": None,
        "status_changed_at": None,
        "status_changed_by": None,
        "status_note": None,
        "snoozed_until": None,
        "reopened_at": None,
        "reopened_by": None,
        "original_severity": None,
        "severity_changed_at": None,
        "severity_changed_by": None,
        "severity_override_reason": None,
        "retest_of_vulnerability_id": None,
        "issue_type": severity,
        "finding_class": severity,
    }


def read_issues(run_dir: Path) -> list[Any]:
    """Return confirmed findings plus Informational and Thinking issues.

    Confirmed vulnerabilities remain byte-for-byte unchanged.  Coverage
    observations and unconfirmed hypotheses are adapted to the same record
    shape only for the viewer, so they can be selected, inspected and
    exported without being counted as confirmed vulnerabilities or emitted in
    SARIF.
    """
    issues: list[Any] = []
    for report in read_vulnerabilities(run_dir):
        if isinstance(report, dict):
            item = dict(report)
            item.setdefault("issue_type", "vulnerability")
            item.setdefault("finding_class", "vulnerability")
            issues.append(item)

    coverage = _load_json(run_dir / "coverage.json", default={})
    if not isinstance(coverage, dict) or not isinstance(coverage.get("entries"), list):
        coverage = _load_json(run_dir / ".state" / "coverage.json", default={})
    # The live runtime mirror is keyed by entry id, while the public artifact
    # stores an ``entries`` list. Normalize both forms for the viewer.
    if isinstance(coverage, dict) and not isinstance(coverage.get("entries"), list):
        coverage = {
            "entries": [
                {**value, "entry_id": entry_id}
                for entry_id, value in coverage.items()
                if isinstance(entry_id, str) and isinstance(value, dict)
            ]
        }
    entries = coverage.get("entries", []) if isinstance(coverage, dict) else []
    if isinstance(entries, list):
        for index, entry in enumerate(entries, start=1):
            if (
                not isinstance(entry, dict)
                or str(entry.get("outcome", "")).lower() != "informational"
            ):
                continue
            surface = str(entry.get("surface") or "Unknown surface").strip()
            risk_area = str(entry.get("risk_area") or "Observation").strip()
            evidence = str(entry.get("evidence") or "No evidence recorded.").strip()
            title = f"{surface} — {risk_area}"
            issue_id = str(entry.get("entry_id") or _stable_issue_id("info", entry, index))
            issue = _issue_defaults(
                issue_id=issue_id if issue_id.startswith("info-") else f"info-{issue_id}",
                title=title,
                severity="informational",
                description=evidence,
                created_at=str(entry.get("recorded_at") or entry.get("updated_at") or ""),
            )
            issue.update(
                {
                    "target": surface,
                    "technical_analysis": risk_area,
                    "evidence": evidence,
                    "impact": (
                        "Informational observation; no confirmed vulnerability was established."
                    ),
                    "issue_type": "informational",
                    "finding_class": "informational",
                }
            )
            issues.append(issue)

    thinking = _load_json(run_dir / "thinking.json", default=[])
    if not isinstance(thinking, list) or not thinking:
        record_thinking = read_run_summary(run_dir).get("thinking_hypotheses")
        thinking = record_thinking if isinstance(record_thinking, list) else []
    for index, hypothesis in enumerate(thinking, start=1):
        if not isinstance(hypothesis, dict):
            continue
        title = str(hypothesis.get("title") or "Unconfirmed security hypothesis").strip()
        issue = _issue_defaults(
            issue_id=_stable_issue_id("thinking", hypothesis, index),
            title=title,
            severity="thinking",
            description=str(hypothesis.get("hypothesis") or "").strip(),
            created_at=str(hypothesis.get("created_at") or ""),
        )
        issue.update(
            {
                "evidence": str(hypothesis.get("evidence") or "").strip() or None,
                "assumptions": str(hypothesis.get("why_unconfirmed") or "").strip() or None,
                "remediation_steps": (
                    str(hypothesis.get("suggested_validation") or "").strip() or None
                ),
                "related_report_ids": hypothesis.get("related_report_ids")
                if isinstance(hypothesis.get("related_report_ids"), list)
                else None,
                "impact": "Thinking hypothesis; not confirmed and not a vulnerability finding.",
                "issue_type": "thinking",
                "finding_class": "thinking",
            }
        )
        issues.append(issue)
    return issues


def read_report_markdown(run_dir: Path) -> str:
    """The executive report markdown (empty until a scan writes it)."""
    report_path = run_dir / "penetration_test_report.md"
    try:
        return report_path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _load_json(path: Path, *, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


__all__ = [
    "build_run_state",
    "primary_target",
    "read_issues",
    "read_report_markdown",
    "read_run_summary",
    "read_vulnerabilities",
    "severity_counts",
]
