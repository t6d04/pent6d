"""Mandatory attack-chain review and explicitly labelled hypotheses.

The model is still responsible for the security reasoning, but the runtime
keeps an auditable ledger of that reasoning and refuses to finalize a run
until every filed finding and informational observation has been reviewed.
Unproven ideas are deliberately kept out of the vulnerability index and are
stored as ``Thinking`` hypotheses instead.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from agents import RunContextWrapper, function_tool

from strix.report.state import get_global_report_state
from strix.tools.coverage.tools import get_coverage_entries


CHAIN_OUTCOMES: tuple[str, ...] = (
    "validated_chain",
    "impact_upgraded",
    "no_chain",
    "ruled_out",
    "blocked",
)
_CHAIN_REVIEWED_COVERAGE_OUTCOMES = frozenset({"reported", "informational"})


def _caller_identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    agent_id = inner.get("agent_id") if isinstance(inner.get("agent_id"), str) else None
    agent_name: str | None = None
    coordinator = inner.get("coordinator")
    if agent_id is not None and coordinator is not None:
        names = getattr(coordinator, "names", {})
        if isinstance(names, dict) and isinstance(names.get(agent_id), str):
            agent_name = names[agent_id]
    return agent_id, agent_name


def _state_or_error() -> tuple[Any | None, dict[str, Any] | None]:
    state = get_global_report_state()
    if state is None:
        return None, {"success": False, "error": "No active report state"}
    return state, None


def _required_items(state: Any) -> tuple[set[str], set[str]]:
    report_ids = {
        str(report.get("id"))
        for report in state.vulnerability_reports
        if isinstance(report, dict) and report.get("id")
    }
    coverage_ids = {
        str(entry.get("entry_id"))
        for entry in get_coverage_entries()
        if entry.get("entry_id")
        and str(entry.get("outcome", "")) in _CHAIN_REVIEWED_COVERAGE_OUTCOMES
    }
    return report_ids, coverage_ids


def _fingerprint(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _reviewed_items(state: Any) -> tuple[set[str], set[str]]:
    reports: set[str] = set()
    coverage: set[str] = set()
    reviews = state.run_record.get("chain_reviews", [])
    if not isinstance(reviews, list):
        return reports, coverage
    current_reports = {
        str(report.get("id")): _fingerprint(report)
        for report in state.vulnerability_reports
        if isinstance(report, dict) and report.get("id")
    }
    current_coverage = {
        str(entry.get("entry_id")): _fingerprint(entry)
        for entry in get_coverage_entries()
        if entry.get("entry_id")
    }
    for review in reviews:
        if not isinstance(review, dict):
            continue
        report_fingerprints = review.get("report_fingerprints")
        coverage_fingerprints = review.get("coverage_fingerprints")
        for item in review.get("reviewed_report_ids", []):
            key = str(item)
            if item and (
                not isinstance(report_fingerprints, dict)
                or (
                    key in report_fingerprints
                    and report_fingerprints.get(key) == current_reports.get(key)
                )
            ):
                reports.add(key)
        for item in review.get("reviewed_coverage_entry_ids", []):
            key = str(item)
            if item and (
                not isinstance(coverage_fingerprints, dict)
                or (
                    key in coverage_fingerprints
                    and coverage_fingerprints.get(key) == current_coverage.get(key)
                )
            ):
                coverage.add(key)
    return reports, coverage


def chain_review_status(state: Any | None = None) -> dict[str, Any]:
    """Return the machine-checkable chain gate status for the current run."""
    state = state or get_global_report_state()
    if state is None:
        return {"success": False, "error": "No active report state"}
    required_reports, required_coverage = _required_items(state)
    reviewed_reports, reviewed_coverage = _reviewed_items(state)
    missing_reports = sorted(required_reports - reviewed_reports)
    missing_coverage = sorted(required_coverage - reviewed_coverage)
    reviews = state.run_record.get("chain_reviews", [])
    return {
        "success": True,
        "ready": not missing_reports and not missing_coverage,
        "required_report_ids": sorted(required_reports),
        "required_coverage_entry_ids": sorted(required_coverage),
        "reviewed_report_ids": sorted(reviewed_reports & required_reports),
        "reviewed_coverage_entry_ids": sorted(reviewed_coverage & required_coverage),
        "missing_report_ids": missing_reports,
        "missing_coverage_entry_ids": missing_coverage,
        "review_count": len(reviews) if isinstance(reviews, list) else 0,
    }


def _record_chain_review_impl(  # noqa: PLR0911
    *,
    reviewed_report_ids: list[str],
    reviewed_coverage_entry_ids: list[str],
    outcome: str,
    analysis: str,
    upgraded_report_ids: list[str],
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    state, error = _state_or_error()
    if error:
        return error
    normalized = outcome.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in CHAIN_OUTCOMES:
        return {
            "success": False,
            "error": f"Invalid outcome {outcome!r}; choose one of {list(CHAIN_OUTCOMES)}",
        }
    if not analysis.strip():
        return {"success": False, "error": "analysis is required"}

    required_reports, required_coverage = _required_items(state)
    report_ids = list(
        dict.fromkeys(str(item).strip() for item in reviewed_report_ids if str(item).strip())
    )
    coverage_ids = list(
        dict.fromkeys(
            str(item).strip()
            for item in reviewed_coverage_entry_ids
            if str(item).strip()
        )
    )
    unknown_reports = sorted(set(report_ids) - required_reports)
    unknown_coverage = sorted(set(coverage_ids) - required_coverage)
    if unknown_reports or unknown_coverage:
        return {
            "success": False,
            "error": "Review references items that are not current chain obligations",
            "unknown_report_ids": unknown_reports,
            "unknown_coverage_entry_ids": unknown_coverage,
        }
    if not report_ids and not coverage_ids:
        return {
            "success": False,
            "error": "Review at least one finding or informational observation",
        }
    upgraded = list(
        dict.fromkeys(str(item).strip() for item in upgraded_report_ids if str(item).strip())
    )
    if normalized == "impact_upgraded" and not upgraded:
        return {
            "success": False,
            "error": "impact_upgraded requires at least one upgraded_report_id",
        }
    unknown_upgraded = sorted(set(upgraded) - set(report_ids))
    if unknown_upgraded:
        return {
            "success": False,
            "error": "upgraded_report_ids must be included in reviewed_report_ids",
            "unknown_upgraded_report_ids": unknown_upgraded,
        }

    review: dict[str, Any] = {
        "reviewed_report_ids": report_ids,
        "reviewed_coverage_entry_ids": coverage_ids,
        "outcome": normalized,
        "analysis": analysis.strip(),
        "upgraded_report_ids": upgraded,
        "report_fingerprints": {
            report_id: _fingerprint(report)
            for report_id in report_ids
            for report in state.vulnerability_reports
            if str(report.get("id")) == report_id
        },
        "coverage_fingerprints": {
            entry_id: _fingerprint(entry)
            for entry_id in coverage_ids
            for entry in get_coverage_entries()
            if str(entry.get("entry_id")) == entry_id
        },
        "created_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    if agent_id:
        review["agent_id"] = agent_id
    if agent_name:
        review["agent_name"] = agent_name
    reviews = state.run_record.setdefault("chain_reviews", [])
    if not isinstance(reviews, list):
        reviews = []
        state.run_record["chain_reviews"] = reviews
    reviews.append(review)
    state.save_run_data()
    result = chain_review_status(state)
    result.update({"recorded": True, "outcome": normalized, "analysis": analysis.strip()})
    return result


@function_tool(timeout=30)
async def record_chain_review(
    ctx: RunContextWrapper,
    reviewed_report_ids: list[str],
    reviewed_coverage_entry_ids: list[str],
    outcome: Literal["validated_chain", "impact_upgraded", "no_chain", "ruled_out", "blocked"],
    analysis: str,
    upgraded_report_ids: list[str] | None = None,
) -> str:
    """Record the mandatory post-finding chain and impact-upgrade review.

    Call this only after reviewing every confirmed finding and every
    ``informational`` coverage observation. ``validated_chain`` means a
    complete multi-step path was demonstrated; ``impact_upgraded`` means a
    chain changed the severity/impact of an existing report; ``no_chain`` and
    ``ruled_out`` document why combinations did not produce more impact;
    ``blocked`` records a real validation barrier and should normally be
    accompanied by a ``record_thinking`` hypothesis. ``finish_scan`` refuses
    to finalize until the union of these calls covers all required IDs.
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _record_chain_review_impl,
        reviewed_report_ids=reviewed_report_ids,
        reviewed_coverage_entry_ids=reviewed_coverage_entry_ids,
        outcome=outcome,
        analysis=analysis,
        upgraded_report_ids=upgraded_report_ids or [],
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def get_chain_review_status(ctx: RunContextWrapper) -> str:
    """Show which findings/observations are still missing chain review."""
    del ctx
    return json.dumps(chain_review_status(), ensure_ascii=False, default=str)


def _record_thinking_impl(
    *,
    title: str,
    hypothesis: str,
    evidence: str,
    why_unconfirmed: str,
    suggested_validation: str,
    related_report_ids: list[str],
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    state, error = _state_or_error()
    if error:
        return error
    values = {
        "title": title,
        "hypothesis": hypothesis,
        "evidence": evidence,
        "why_unconfirmed": why_unconfirmed,
        "suggested_validation": suggested_validation,
    }
    missing = [name for name, value in values.items() if not value.strip()]
    if missing:
        return {"success": False, "error": f"Required fields are empty: {', '.join(missing)}"}
    report_ids = {
        str(report.get("id"))
        for report in state.vulnerability_reports
        if isinstance(report, dict) and report.get("id")
    }
    related = list(
        dict.fromkeys(str(item).strip() for item in related_report_ids if str(item).strip())
    )
    unknown = sorted(set(related) - report_ids)
    if unknown:
        return {
            "success": False,
            "error": "Unknown related report ids",
            "unknown_report_ids": unknown,
        }
    item: dict[str, Any] = {
        "label": "Thinking",
        "title": title.strip(),
        "hypothesis": hypothesis.strip(),
        "evidence": evidence.strip(),
        "why_unconfirmed": why_unconfirmed.strip(),
        "suggested_validation": suggested_validation.strip(),
        "related_report_ids": related,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    if agent_id:
        item["agent_id"] = agent_id
    if agent_name:
        item["agent_name"] = agent_name
    hypotheses = state.run_record.setdefault("thinking_hypotheses", [])
    if not isinstance(hypotheses, list):
        hypotheses = []
        state.run_record["thinking_hypotheses"] = hypotheses
    hypotheses.append(item)
    state.thinking_hypotheses = hypotheses
    state.save_run_data()
    return {
        "success": True,
        "label": "Thinking",
        "thinking_count": len(hypotheses),
        "message": "Hypothesis stored as Thinking; it is not a confirmed vulnerability.",
    }


@function_tool(timeout=30)
async def record_thinking(
    ctx: RunContextWrapper,
    title: str,
    hypothesis: str,
    evidence: str,
    why_unconfirmed: str,
    suggested_validation: str,
    related_report_ids: list[str] | None = None,
) -> str:
    """Store an unproven security hypothesis with the visible label ``Thinking``.

    Use this for a plausible issue or attack path that was not demonstrated
    and not disproved. It is intentionally excluded from vulnerability counts,
    SARIF findings, and confirmed severity metrics.
    """
    agent_id, agent_name = _caller_identity(ctx)
    result = await asyncio.to_thread(
        _record_thinking_impl,
        title=title,
        hypothesis=hypothesis,
        evidence=evidence,
        why_unconfirmed=why_unconfirmed,
        suggested_validation=suggested_validation,
        related_report_ids=related_report_ids or [],
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def list_thinking(ctx: RunContextWrapper) -> str:
    """List all unconfirmed hypotheses labelled ``Thinking`` for this run."""
    del ctx
    state = get_global_report_state()
    hypotheses = [] if state is None else state.run_record.get("thinking_hypotheses", [])
    return json.dumps(
        {"success": state is not None, "label": "Thinking", "hypotheses": hypotheses},
        ensure_ascii=False,
        default=str,
    )
