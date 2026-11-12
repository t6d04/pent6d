"""Durable independent validator verdicts and graph binding."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool_context import ToolContext

from strix.runtime.attack_graph import AttackGraph
from strix.tools.validation.tools import (
    hydrate_validations_from_disk,
    record_validation,
    validation_status_for_state_dir,
)


if TYPE_CHECKING:
    from pathlib import Path


async def _call(
    args: dict[str, Any], *, graph: AttackGraph, state_dir: Path
) -> dict[str, Any]:
    context = ToolContext(
        context={"attack_graph": graph, "state_dir": state_dir, "agent_id": "validator-1"},
        tool_name=record_validation.name,
        tool_call_id="validation-call",
        tool_arguments="{}",
    )
    raw: str = await record_validation.on_invoke_tool(context, json.dumps(args))
    return cast("dict[str, Any]", json.loads(raw))


@pytest.mark.asyncio
async def test_validator_record_is_durable_and_bound_to_graph(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    hydrate_validations_from_disk(state_dir)
    graph = AttackGraph(state_dir)
    created = await graph.add_task(
        title="Validate IDOR evidence",
        role="validator",
        phase="validation",
        dispatch_key="validator:idor",
    )
    task_id = created["task"]["task_id"]

    result = await _call(
        {
            "task_id": task_id,
            "verdict": "confirmed",
            "confidence": "high",
            "summary": "Cross-tenant object access reproduced.",
            "evidence": "The same object was returned with a second tenant identity.",
            "evidence_ids": ["request-1"],
            "target_identity": "https://app.example.test",
            "reproduced": True,
        },
        graph=graph,
        state_dir=state_dir,
    )

    assert result["success"] is True
    record_id = result["record_id"]
    snapshot = await graph.snapshot()
    assert snapshot["tasks"][task_id]["metadata"]["validation_record_id"] == record_id
    assert (state_dir / "validations.json").exists()
    assert validation_status_for_state_dir(state_dir)["total"] == 1


@pytest.mark.asyncio
async def test_validator_rejects_unreproduced_confirmation(tmp_path: Path) -> None:
    state_dir = tmp_path / "state"
    hydrate_validations_from_disk(state_dir)
    graph = AttackGraph(state_dir)
    created = await graph.add_task(
        title="Validate candidate",
        role="validator",
        phase="validation",
    )

    result = await _call(
        {
            "task_id": created["task"]["task_id"],
            "verdict": "confirmed",
            "confidence": "medium",
            "summary": "Candidate appears exploitable.",
            "evidence": "Only an anomaly was observed.",
            "target_identity": "https://app.example.test",
            "reproduced": False,
        },
        graph=graph,
        state_dir=state_dir,
    )

    assert result["success"] is False
    assert any("reproduced=true" in error for error in result["errors"])
