"""Runtime chain/impact closure and Thinking hypothesis tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from agents.tool_context import ToolContext

from strix.report.state import ReportState, set_global_report_state
from strix.runtime.attack_graph import AttackGraph, TaskStatus
from strix.tools.chaining.tools import (
    _record_chain_review_impl,
    _record_thinking_impl,
    chain_review_status,
)
from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk
from strix.tools.finish.tool import (
    _do_finish,
    _mapper_completion_gate,
    _specialist_completion_gate,
    finish_scan,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path) -> ReportState:
    hydrate_coverage_from_disk(tmp_path / "runtime")
    state = ReportState(run_name="chain-test")
    state._run_dir = tmp_path / "run"
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


def test_finish_rejects_unreviewed_finding(report_state: ReportState) -> None:
    report_state.add_vulnerability_report(title="Test finding", severity="low")

    result = _do_finish(
        parent_id=None,
        executive_summary="summary",
        methodology="method",
        technical_analysis="analysis",
        recommendations="recommendations",
        agent_graph={},
    )

    assert result["success"] is False
    assert result["chain_review"]["missing_report_ids"] == ["vuln-0001"]


def test_informational_observation_is_a_chain_gate_obligation(report_state: ReportState) -> None:
    _record_impl(
        surface="GET /debug",
        risk_area="diagnostic disclosure",
        outcome="informational",
        evidence="Debug metadata observed; exploitability not demonstrated.",
        agent_id=None,
        agent_name=None,
    )
    status = chain_review_status(report_state)
    coverage_id = status["missing_coverage_entry_ids"][0]

    result = _record_chain_review_impl(
        reviewed_report_ids=[],
        reviewed_coverage_entry_ids=[coverage_id],
        outcome="no_chain",
        analysis="The observation does not enable a higher-impact path.",
        upgraded_report_ids=[],
        agent_id=None,
        agent_name=None,
    )

    assert result["ready"] is True


def test_finish_rejects_unresolved_follow_up(report_state: ReportState) -> None:
    assert report_state is not None
    _record_impl(
        surface="POST /upload",
        risk_area="file upload validation",
        outcome="needs_follow_up",
        evidence="Upload behavior could not be validated without a permitted test file.",
        agent_id=None,
        agent_name=None,
    )

    result = _do_finish(
        parent_id=None,
        executive_summary="summary",
        methodology="method",
        technical_analysis="analysis",
        recommendations="recommendations",
        agent_graph={},
    )

    assert result["success"] is False
    assert "needs_follow_up" in result["error"]
    assert result["coverage"]["unresolved_surfaces"][0]["surface"] == "POST /upload"


def test_report_revision_invalidates_prior_chain_review(report_state: ReportState) -> None:
    report_id = report_state.add_vulnerability_report(title="Test finding", severity="low")
    _record_chain_review_impl(
        reviewed_report_ids=[report_id],
        reviewed_coverage_entry_ids=[],
        outcome="no_chain",
        analysis="No higher-impact path was demonstrated.",
        upgraded_report_ids=[],
        agent_id=None,
        agent_name=None,
    )
    assert chain_review_status(report_state)["ready"] is True

    report_state.update_vulnerability_report(
        report_id,
        {"impact": "The impact changed after additional validation."},
        update_reason="New evidence",
    )

    status = chain_review_status(report_state)
    assert status["ready"] is False
    assert status["missing_report_ids"] == [report_id]


def test_thinking_is_not_a_confirmed_finding(report_state: ReportState) -> None:
    result = _record_thinking_impl(
        title="Possible tenant crossover",
        hypothesis="A client-readable token might be accepted by another tenant.",
        evidence="The token is exposed to client-side JavaScript.",
        why_unconfirmed="A second tenant session was unavailable.",
        suggested_validation="Replay the token against a second tenant.",
        related_report_ids=[],
        agent_id=None,
        agent_name=None,
    )

    assert result["label"] == "Thinking"
    assert report_state.vulnerability_reports == []
    assert report_state.run_record["thinking_hypotheses"][0]["label"] == "Thinking"
    assert (report_state.get_run_dir() / "thinking.json").exists()


def test_thinking_hypothesis_is_a_chain_gate_obligation(report_state: ReportState) -> None:
    result = _record_thinking_impl(
        title="Possible parser confusion",
        hypothesis="A second decoding pass may bypass the input filter.",
        evidence="The response changes after encoded input is replayed.",
        why_unconfirmed="A safe proof payload was not available during the run.",
        suggested_validation="Replay a harmless marker through both decoding paths.",
        related_report_ids=[],
        agent_id=None,
        agent_name=None,
    )
    thinking_id = result["id"]

    blocked = chain_review_status(report_state)
    assert blocked["ready"] is False
    assert blocked["missing_thinking_ids"] == [thinking_id]

    reviewed = _record_chain_review_impl(
        reviewed_report_ids=[],
        reviewed_coverage_entry_ids=[],
        reviewed_thinking_ids=[thinking_id],
        outcome="blocked",
        analysis="The hypothesis remains unproven because the safe replay fixture is unavailable.",
        upgraded_report_ids=[],
        agent_id=None,
        agent_name=None,
    )
    assert reviewed["ready"] is True


@pytest.mark.asyncio
async def test_finish_scan_blocks_until_graph_validator_is_recorded(
    report_state: ReportState, tmp_path: Path
) -> None:
    del report_state
    graph = AttackGraph(tmp_path / "state")
    created = await graph.add_task(
        title="Validate finding",
        role="validator",
        phase="validation",
    )
    task_id = created["task"]["task_id"]
    await graph.set_status(task_id, TaskStatus.SUCCEEDED)
    context = ToolContext(
        context={
            "parent_id": None,
            "validation_enabled": True,
            "attack_graph": graph,
        },
        tool_name=finish_scan.name,
        tool_call_id="finish-call",
        tool_arguments="{}",
    )
    args = {
        "executive_summary": "# Summary\nAssessment complete.",
        "methodology": "# Methodology\nEvidence-based testing.",
        "technical_analysis": "# Analysis\nNo additional detail.",
        "recommendations": "# Recommendations\nRetest after remediation.",
    }

    raw: str = await finish_scan.on_invoke_tool(context, json.dumps(args))
    blocked = json.loads(raw)
    assert blocked["success"] is False
    assert blocked["attack_graph"]["missing_validation"]

    await graph.bind_validation(task_id, "validation-1")
    raw = await finish_scan.on_invoke_tool(context, json.dumps(args))
    assert json.loads(raw)["success"] is True


def test_standard_deep_completion_requires_completed_specialist() -> None:
    root_only = {
        "statuses": {"root": "running"},
        "parent_of": {"root": None},
        "names": {"root": "Root Agent"},
    }
    blocked = _specialist_completion_gate(
        scan_mode="deep",
        target_types=["web_application"],
        agent_graph=root_only,
    )

    assert blocked is not None
    assert blocked["specialist_count"] == 0
    assert "No child agent exists yet" in blocked["error"]


def test_completed_specialist_satisfies_completion_gate() -> None:
    graph = {
        "statuses": {"root": "running", "child": "completed"},
        "parent_of": {"root": None, "child": "root"},
        "names": {"root": "Root Agent", "child": "Auth Specialist"},
    }

    assert (
        _specialist_completion_gate(
            scan_mode="deep",
            target_types=["web_application"],
            agent_graph=graph,
        )
        is None
    )


def test_quick_mode_remains_time_boxed() -> None:
    assert (
        _specialist_completion_gate(
            scan_mode="quick",
            target_types=["web_application"],
            agent_graph={
                "statuses": {"root": "running", "mapper": "completed"},
                "parent_of": {"root": None, "mapper": "root"},
                "names": {"root": "Root Agent", "mapper": "Recon Mapper"},
            },
        )
        is None
    )

    blocked = _mapper_completion_gate(
        scan_mode="quick",
        target_types=["web_application"],
        agent_graph={"statuses": {"root": "running"}, "parent_of": {"root": None}},
    )
    assert blocked is not None
    assert blocked["mapper_count"] == 0
