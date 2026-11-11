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
import uuid
from collections import Counter
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
# These outcomes assert that no escalation exists; the caller must say which
# escalation directions it actually tried before making that claim.
_CHAIN_UPGRADE_OUTCOMES = frozenset({"no_chain", "ruled_out", "blocked"})
THINKING_TESTABILITY: tuple[str, ...] = (
    "testable_now",
    "needs_credentials",
    "needs_external",
    "unknown",
)
_CREATIVE_ROLES = frozenset({"hypothesis", "reflection", "chain_reviewer", "gap_closer"})
_CREATIVE_NAME_MARKERS = (
    "hypothesis explorer",
    "planner reflection",
    "chain and impact",
    "creative hypothesis",
)


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


def _state_or_error() -> tuple[Any, dict[str, Any] | None]:
    state = get_global_report_state()
    if state is None:
        return None, {"success": False, "error": "No active report state"}
    return state, None


def _required_items(state: Any) -> tuple[set[str], set[str], set[str]]:
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
    thinking_ids = {
        str(item.get("id"))
        for item in state.thinking_hypotheses
        if isinstance(item, dict) and item.get("id")
    }
    return report_ids, coverage_ids, thinking_ids


def _fingerprint(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _reviewed_items(state: Any) -> tuple[set[str], set[str], set[str]]:
    reports: set[str] = set()
    coverage: set[str] = set()
    thinking: set[str] = set()
    reviews = state.run_record.get("chain_reviews", [])
    if not isinstance(reviews, list):
        return reports, coverage, thinking
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
    current_thinking = {
        str(item.get("id")): _fingerprint(item)
        for item in state.thinking_hypotheses
        if isinstance(item, dict) and item.get("id")
    }
    for review in reviews:
        if not isinstance(review, dict):
            continue
        report_fingerprints = review.get("report_fingerprints")
        coverage_fingerprints = review.get("coverage_fingerprints")
        thinking_fingerprints = review.get("thinking_fingerprints")
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
        for item in review.get("reviewed_thinking_ids", []):
            key = str(item)
            if item and (
                not isinstance(thinking_fingerprints, dict)
                or (
                    key in thinking_fingerprints
                    and thinking_fingerprints.get(key) == current_thinking.get(key)
                )
            ):
                thinking.add(key)
    return reports, coverage, thinking


def chain_review_status(state: Any | None = None) -> dict[str, Any]:
    """Return the machine-checkable chain gate status for the current run."""
    state = state or get_global_report_state()
    if state is None:
        return {"success": False, "error": "No active report state"}
    required_reports, required_coverage, required_thinking = _required_items(state)
    reviewed_reports, reviewed_coverage, reviewed_thinking = _reviewed_items(state)
    missing_reports = sorted(required_reports - reviewed_reports)
    missing_coverage = sorted(required_coverage - reviewed_coverage)
    missing_thinking = sorted(required_thinking - reviewed_thinking)
    reviews = state.run_record.get("chain_reviews", [])
    return {
        "success": True,
        "ready": not missing_reports and not missing_coverage and not missing_thinking,
        "required_report_ids": sorted(required_reports),
        "required_coverage_entry_ids": sorted(required_coverage),
        "reviewed_report_ids": sorted(reviewed_reports & required_reports),
        "reviewed_coverage_entry_ids": sorted(reviewed_coverage & required_coverage),
        "missing_report_ids": missing_reports,
        "missing_coverage_entry_ids": missing_coverage,
        "required_thinking_ids": sorted(required_thinking),
        "reviewed_thinking_ids": sorted(reviewed_thinking & required_thinking),
        "missing_thinking_ids": missing_thinking,
        "review_count": len(reviews) if isinstance(reviews, list) else 0,
    }


def creative_scorecard(agent_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    """Summarize what the creative/reflection/chain layer actually produced."""
    state = get_global_report_state()
    if state is None:
        return {"success": False, "error": "No active report state"}
    graph = agent_graph if isinstance(agent_graph, dict) else {}
    raw_metadata = graph.get("metadata")
    metadata: dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    raw_names = graph.get("names")
    names: dict[str, Any] = raw_names if isinstance(raw_names, dict) else {}
    raw_statuses = graph.get("statuses")
    statuses: dict[str, Any] = raw_statuses if isinstance(raw_statuses, dict) else {}

    creative_ids: set[str] = set()
    for agent_id in set(metadata) | set(names):
        raw_meta = metadata.get(agent_id)
        role = str(raw_meta.get("role") or "").lower() if isinstance(raw_meta, dict) else ""
        name = str(names.get(agent_id) or "").lower()
        if role in _CREATIVE_ROLES or any(marker in name for marker in _CREATIVE_NAME_MARKERS):
            creative_ids.add(str(agent_id))
    creative_names = {str(names.get(agent_id) or "").lower() for agent_id in creative_ids}

    def _is_creative(agent_id: Any, agent_name: Any) -> bool:
        if str(agent_id or "") in creative_ids:
            return True
        name = str(agent_name or "").lower()
        return bool(name) and (
            name in creative_names or any(marker in name for marker in _CREATIVE_NAME_MARKERS)
        )

    hypotheses = [item for item in state.thinking_hypotheses if isinstance(item, dict)]
    testability = Counter(str(item.get("testability") or "unknown") for item in hypotheses)
    reports = [item for item in state.vulnerability_reports if isinstance(item, dict)]
    report_ids = {str(item.get("id")) for item in reports if item.get("id")}
    linked_hypotheses = sum(
        1
        for item in hypotheses
        if set(map(str, item.get("related_report_ids") or [])) & report_ids
    )
    creative_reports = [
        item for item in reports if _is_creative(item.get("agent_id"), item.get("agent_name"))
    ]
    reviews = state.run_record.get("chain_reviews", [])
    if not isinstance(reviews, list):
        reviews = []
    reviews = [item for item in reviews if isinstance(item, dict)]
    outcomes = Counter(str(item.get("outcome") or "unknown") for item in reviews)
    coverage_entries = get_coverage_entries()
    creative_agents = list(creative_ids)
    return {
        "success": True,
        "hypotheses": {
            "total": len(hypotheses),
            "by_testability": dict(testability),
            "with_related_reports": linked_hypotheses,
            "from_creative_agents": sum(
                1
                for item in hypotheses
                if _is_creative(item.get("agent_id"), item.get("agent_name"))
            ),
        },
        "chain_reviews": {
            "total": len(reviews),
            "by_outcome": dict(outcomes),
            "upgrade_attempts": sum(
                len(item.get("upgrade_attempts") or []) for item in reviews
            ),
            "validated_chain": outcomes.get("validated_chain", 0),
            "impact_upgraded": outcomes.get("impact_upgraded", 0),
        },
        "findings": {
            "total": len(reports),
            "created_by_creative": len(creative_reports),
            "report_ids": [str(item.get("id")) for item in creative_reports if item.get("id")],
        },
        "coverage": {
            "total": len(coverage_entries),
            "from_creative_agents": sum(
                1
                for entry in coverage_entries
                if isinstance(entry, dict)
                and _is_creative(entry.get("agent_id"), entry.get("agent_name"))
            ),
        },
        "agents": {
            "creative": len(creative_agents),
            "statuses": Counter(str(statuses.get(agent_id) or "?") for agent_id in creative_agents),
        },
    }


@function_tool(timeout=30)
async def get_creative_scorecard(ctx: RunContextWrapper) -> str:
    """Show how many hypotheses, chain attempts and findings came from creative work.

    Use this before finishing a standard/deep scan to check whether the
    hypothesis layer produced evidence or only recorded blocked ideas.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = inner.get("coordinator")
    graph: dict[str, Any] = {}
    if coordinator is not None and hasattr(coordinator, "snapshot"):
        graph = await coordinator.snapshot()
    return json.dumps(creative_scorecard(graph), ensure_ascii=False, default=str)


def _record_chain_review_impl(  # noqa: PLR0911
    *,
    reviewed_report_ids: list[str],
    reviewed_coverage_entry_ids: list[str],
    outcome: str,
    analysis: str,
    upgraded_report_ids: list[str],
    agent_id: str | None,
    agent_name: str | None,
    reviewed_thinking_ids: list[str] | None = None,
    upgrade_attempts: list[str] | None = None,
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
    attempts = list(
        dict.fromkeys(
            str(item).strip() for item in (upgrade_attempts or []) if str(item).strip()
        )
    )
    if normalized in _CHAIN_UPGRADE_OUTCOMES and not attempts:
        return {
            "success": False,
            "error": (
                "Before recording no_chain, ruled_out, or blocked, record at least "
                "one impact-upgrade direction you actually attempted."
            ),
            "hint": (
                "Pass upgrade_attempts=[...] with one entry per chain or severity "
                "escalation you tested and why it did not succeed."
            ),
        }

    required_reports, required_coverage, required_thinking = _required_items(state)
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
    thinking_ids = list(
        dict.fromkeys(
            str(item).strip()
            for item in (reviewed_thinking_ids or [])
            if str(item).strip()
        )
    )
    unknown_reports = sorted(set(report_ids) - required_reports)
    unknown_coverage = sorted(set(coverage_ids) - required_coverage)
    unknown_thinking = sorted(set(thinking_ids) - required_thinking)
    if unknown_reports or unknown_coverage or unknown_thinking:
        return {
            "success": False,
            "error": "Review references items that are not current chain obligations",
            "unknown_report_ids": unknown_reports,
            "unknown_coverage_entry_ids": unknown_coverage,
            "unknown_thinking_ids": unknown_thinking,
        }
    if not report_ids and not coverage_ids and not thinking_ids:
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
        "reviewed_thinking_ids": thinking_ids,
        "outcome": normalized,
        "analysis": analysis.strip(),
        "upgrade_attempts": attempts,
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
        "thinking_fingerprints": {
            thinking_id: _fingerprint(item)
            for thinking_id in thinking_ids
            for item in state.thinking_hypotheses
            if str(item.get("id")) == thinking_id
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
    reviewed_thinking_ids: list[str] | None = None,
    upgrade_attempts: list[str] | None = None,
) -> str:
    """Record the mandatory post-finding chain and impact-upgrade review.

    Call this only after reviewing every confirmed finding, every
    ``informational`` coverage observation, and every ``Thinking`` hypothesis.
    ``validated_chain`` means a
    complete multi-step path was demonstrated; ``impact_upgraded`` means a
    chain changed the severity/impact of an existing report; ``no_chain`` and
    ``ruled_out`` document why combinations did not produce more impact;
    ``blocked`` records a real validation barrier and should normally be
    accompanied by a ``record_thinking`` hypothesis. For ``no_chain``,
    ``ruled_out`` and ``blocked``, ``upgrade_attempts`` is required: list the
    concrete chain/severity-escalation directions you tried and why each did
    not succeed. ``finish_scan`` refuses to finalize until the union of these
    calls covers all required IDs.
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
        reviewed_thinking_ids=reviewed_thinking_ids or [],
        upgrade_attempts=upgrade_attempts or [],
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
    testability: str = "unknown",
) -> dict[str, Any]:
    state, error = _state_or_error()
    if error:
        return error
    normalized_testability = testability.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized_testability not in THINKING_TESTABILITY:
        return {
            "success": False,
            "error": (
                f"Invalid testability {testability!r}; choose one of "
                f"{list(THINKING_TESTABILITY)}"
            ),
        }
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
        "id": f"thinking-{uuid.uuid4().hex[:12]}",
        "label": "Thinking",
        "title": title.strip(),
        "hypothesis": hypothesis.strip(),
        "evidence": evidence.strip(),
        "why_unconfirmed": why_unconfirmed.strip(),
        "suggested_validation": suggested_validation.strip(),
        "related_report_ids": related,
        "testability": normalized_testability,
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
        "id": item["id"],
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
    testability: Literal[
        "testable_now", "needs_credentials", "needs_external", "unknown"
    ] = "unknown",
) -> str:
    """Store an unproven security hypothesis with the visible label ``Thinking``.

    Use this for a plausible issue or attack path that was not demonstrated
    and not disproved. It is intentionally excluded from vulnerability counts,
    SARIF findings, and confirmed severity metrics.

    ``testability`` records whether the next step can be tested with the current
    run's data (``testable_now``), needs credentials, needs an external asset,
    or is not yet classifiable. Prefer testing ``testable_now`` hypotheses
    before spending turns on hypotheses that are structurally blocked.
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
        testability=testability,
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
