"""finish_scan confronts the root agent with the coverage the runtime can see."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.tools.coverage.tools import _record_impl, hydrate_coverage_from_disk
from strix.tools.finish.tool import _coverage_summary, _live_host_coverage_gate
from strix.tools.recon.tools import ReconObservation, _save


if TYPE_CHECKING:
    from pathlib import Path


_GRAPH = {
    "statuses": {"agent-1": "completed"},
    "names": {"agent-1": "injection-tester"},
    "metadata": {"agent-1": {"skills": ["sql_injection", "xss"]}},
}


@pytest.fixture(autouse=True)
def _empty_ledger(tmp_path: Path) -> None:
    hydrate_coverage_from_disk(tmp_path)


def _record(risk_area: str) -> None:
    _record_impl(
        surface="POST /api/orders/{id}",
        risk_area=risk_area,
        outcome="no_issue_found",
        evidence="Parameters fuzzed; no anomalies.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


def test_unrecorded_risk_class_is_reported_back_to_the_root_agent() -> None:
    _record("SQL injection")

    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 1
    assert len(summary["coverage_gaps"]) == 1
    assert "xss" in summary["coverage_gaps"][0]
    assert "unexamined" in summary["coverage_gap_warning"]


def test_fully_accounted_coverage_raises_no_gap_warning() -> None:
    _record("SQL injection")
    _record("cross-site scripting")

    summary = _coverage_summary(_GRAPH)

    assert "coverage_gaps" not in summary
    assert "coverage_gap_warning" not in summary


def test_an_empty_ledger_still_warns_first() -> None:
    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 0
    assert "No coverage was recorded" in summary["coverage_warning"]


def test_deep_scan_requires_completed_assignment_for_every_live_host(tmp_path: Path) -> None:
    _save(
        tmp_path,
        [
            ReconObservation(
                kind="service",
                value="https://alive.example.com/",
                source="direct probe",
                scope="in_scope",
                alive="alive",
                status_code=200,
            ).model_dump(),
            ReconObservation(
                kind="service",
                value="https://second.example.com/",
                source="direct probe",
                scope="in_scope",
                alive="alive",
                status_code=200,
            ).model_dump(),
        ],
        "recon",
    )
    graph = {
        "statuses": {"root": "running", "child": "completed"},
        "parent_of": {"root": None, "child": "root"},
        "names": {"root": "Root", "child": "Host specialist"},
        "metadata": {"child": {"role": "specialist", "task": "https://alive.example.com/"}},
    }

    blocked = _live_host_coverage_gate(
        scan_mode="deep",
        target_types=["web_application"],
        agent_graph=graph,
        run_dir=tmp_path,
    )

    assert blocked is not None
    assert blocked["missing_hosts"] == ["second.example.com"]
