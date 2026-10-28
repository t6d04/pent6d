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
