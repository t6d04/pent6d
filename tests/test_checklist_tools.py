"""Evidence-aware methodology checklist tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from strix.tools.checklist import tools as checklist


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _fresh_checklist(tmp_path: Path) -> None:
    checklist.hydrate_checklist_from_disk(tmp_path / "state")


def _code() -> str:
    return next(iter(checklist._storage))


def test_hydration_persists_catalog_and_starts_open(tmp_path: Path) -> None:
    code = _code()
    assert checklist._storage[code]["status"] == "pending"
    assert (tmp_path / "state" / "checklist.json").is_file()
    assert (tmp_path / "checklist.json").is_file()

    payload = json.loads((tmp_path / "state" / "checklist.json").read_text(encoding="utf-8"))
    assert code in payload["items"]
    assert payload["items"][code]["status"] == "pending"


def test_pass_requires_surface_evidence_and_complete_marker() -> None:
    code = _code()

    missing_evidence = checklist._update_impl(
        code=code,
        status="pass",
        reason="Checked the application behavior.",
        surface="GET /health",
        role="tester",
        session="default",
        evidence="",
        evidence_ids=[],
        finding_ids=[],
        complete_for_item=True,
        agent_id="agent-1",
        agent_name="tester",
    )
    assert missing_evidence["success"] is False
    assert "requires evidence" in " ".join(missing_evidence["errors"])

    incomplete = checklist._update_impl(
        code=code,
        status="pass",
        reason="Checked one surface with evidence.",
        surface="GET /health",
        role="tester",
        session="default",
        evidence="HTTP 200 with no security-sensitive data.",
        evidence_ids=[],
        finding_ids=[],
        complete_for_item=False,
        agent_id="agent-1",
        agent_name="tester",
    )
    assert incomplete["success"] is False
    assert "complete_for_item" in " ".join(incomplete["errors"])


def test_partial_keeps_item_open_until_complete_pass() -> None:
    code = _code()
    partial = checklist._update_impl(
        code=code,
        status="partial",
        reason="Only the unauthenticated surface was assessed so far.",
        surface="GET /public",
        role="anonymous",
        session="default",
        evidence="No issue observed in the public flow.",
        evidence_ids=["evidence-1"],
        finding_ids=[],
        complete_for_item=False,
        agent_id="agent-1",
        agent_name="tester",
    )
    assert partial["success"] is True
    assert partial["status"] == "partial"
    assert partial["progress"]["complete"] is False

    finished = checklist._update_impl(
        code=code,
        status="pass",
        reason="All applicable surfaces were assessed and closed.",
        surface="GET /authenticated",
        role="user",
        session="default",
        evidence="Authenticated and unauthenticated flows were exercised.",
        evidence_ids=["evidence-2"],
        finding_ids=[],
        complete_for_item=True,
        agent_id="agent-1",
        agent_name="tester",
    )
    assert finished["success"] is True
    assert finished["status"] == "pass"
    assert checklist._storage[code]["status"] == "pass"


def test_not_applicable_requires_a_specific_reason() -> None:
    code = _code()
    short = checklist._update_impl(
        code=code,
        status="not_applicable",
        reason="No.",
        surface="",
        role="",
        session="",
        evidence="",
        evidence_ids=[],
        finding_ids=[],
        complete_for_item=True,
        agent_id="agent-1",
        agent_name="tester",
    )
    assert short["success"] is False
    assert "at least 10 characters" in " ".join(short["errors"])

    valid = checklist._update_impl(
        code=code,
        status="not_applicable",
        reason="No file upload or parser surface exists in this target.",
        surface="",
        role="",
        session="",
        evidence="Scope inventory confirms the feature is absent.",
        evidence_ids=[],
        finding_ids=[],
        complete_for_item=True,
        agent_id="agent-1",
        agent_name="tester",
    )
    assert valid["success"] is True
    assert valid["status"] == "not_applicable"
