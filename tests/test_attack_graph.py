"""Tests for the run-scoped Planner attack graph."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from strix.runtime.attack_graph import AttackGraph, TaskStatus


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
async def test_attack_graph_enforces_dependencies_and_persists(tmp_path: Path) -> None:
    graph = AttackGraph(tmp_path)
    recon = await graph.add_task(
        title="Map target",
        role="recon",
        phase="recon",
        dispatch_key="recon:target",
    )
    recon_id = recon["task"]["task_id"]
    exploit = await graph.add_task(
        title="Validate authorization",
        role="authorization",
        phase="execution",
        dependencies=[recon_id],
        dispatch_key="authz:target",
    )
    assert exploit["task"]["status"] == TaskStatus.BLOCKED.value
    assert await graph.ready_tasks() == [recon["task"]]

    await graph.set_status(recon_id, TaskStatus.SUCCEEDED)
    ready = await graph.ready_tasks()
    assert [item["task_id"] for item in ready] == [exploit["task"]["task_id"]]

    restored = AttackGraph(tmp_path)
    snapshot = await restored.snapshot()
    assert snapshot["tasks"][exploit["task"]["task_id"]]["status"] == TaskStatus.READY.value


@pytest.mark.asyncio
async def test_attack_graph_dispatch_key_is_idempotent(tmp_path: Path) -> None:
    graph = AttackGraph(tmp_path)
    first = await graph.add_task(
        title="Check JWT",
        role="jwt",
        phase="execution",
        dispatch_key="jwt:target",
    )
    second = await graph.add_task(
        title="Check JWT again",
        role="jwt",
        phase="execution",
        dispatch_key="jwt:target",
    )

    assert first["created"] is True
    assert second["created"] is False
    assert second["task"]["task_id"] == first["task"]["task_id"]


@pytest.mark.asyncio
async def test_agent_completion_schedules_validation_and_chain_review(tmp_path: Path) -> None:
    graph = AttackGraph(tmp_path)
    origin = await graph.add_task(
        title="Test tenant authorization",
        role="specialist",
        phase="execution",
        dispatch_key="tenant|idor|testing",
        metadata={
            "agent_id": "agent-1",
            "checklist_codes": ["P6-VULNERABILITY-IDOR"],
        },
    )
    origin_id = origin["task"]["task_id"]

    result = await graph.complete_and_schedule_followups(
        agent_id="agent-1",
        role="specialist",
        success=True,
        report_ids=["vuln-1"],
        findings=["Cross-tenant read confirmed"],
        evidence_ids=["req-1"],
        checklist_codes=["P6-VULNERABILITY-IDOR"],
    )

    assert result["success"] is True
    assert {task["role"] for task in result["scheduled_tasks"]} == {
        "validator",
        "chain_reviewer",
    }
    snapshot = await graph.snapshot()
    assert snapshot["tasks"][origin_id]["status"] == TaskStatus.SUCCEEDED.value
    validator = next(
        task for task in snapshot["tasks"].values() if task["role"] == "validator"
    )
    chain = next(
        task for task in snapshot["tasks"].values() if task["role"] == "chain_reviewer"
    )
    assert validator["status"] == TaskStatus.READY.value
    assert chain["status"] == TaskStatus.BLOCKED.value
    assert chain["dependencies"] == [validator["task_id"]]
    assert chain["metadata"]["filed_report_ids"] == ["vuln-1"]

    repeated = await graph.complete_and_schedule_followups(
        agent_id="agent-1",
        role="specialist",
        success=True,
        report_ids=["vuln-1"],
    )
    assert repeated["success"] is True
    assert len((await graph.snapshot())["tasks"]) == 3
