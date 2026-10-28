"""Agent-facing tools for the run-scoped Planner attack graph."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.runtime.attack_graph import AttackGraph, TaskStatus


def _graph(ctx: RunContextWrapper) -> AttackGraph | None:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    value = inner.get("attack_graph")
    if isinstance(value, AttackGraph):
        return value
    state_dir = inner.get("state_dir")
    if isinstance(state_dir, (Path, str)) and str(state_dir).strip():
        return AttackGraph(Path(state_dir))
    return None


def _json_list(value: str, *, field: str) -> tuple[list[str] | None, str | None]:
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, ValueError):
        return None, f"{field} must be valid JSON"
    if not isinstance(parsed, list):
        return None, f"{field} must contain a JSON array"
    return [str(item) for item in parsed if str(item).strip()], None


def _json_object(value: str, *, field: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return None, f"{field} must be valid JSON"
    if not isinstance(parsed, dict):
        return None, f"{field} must contain a JSON object"
    return parsed, None


@function_tool(timeout=30)
async def create_attack_task(
    ctx: RunContextWrapper,
    title: str,
    role: str,
    phase: str,
    risk: str = "low",
    dispatch_key: str = "",
    dependencies_json: str = "[]",
    evidence_ids_json: str = "[]",
    metadata_json: str = "{}",
) -> str:
    """Create an idempotent Planner task in the run's attack graph.

    Use stable ``dispatch_key`` values so recovery or repeated planning does
    not spawn duplicate responsibilities. Dependencies and metadata are JSON
    strings to keep the model tool schema strict and portable across providers.
    Use metadata keys ``node_type``, ``generated_by``, ``source_node_ids`` and
    ``source_information`` when the task was derived from another graph node.
    """

    graph = _graph(ctx)
    if graph is None:
        return json.dumps({"success": False, "error": "attack graph unavailable"})
    dependencies, error = _json_list(dependencies_json, field="dependencies_json")
    if error:
        return json.dumps({"success": False, "error": error})
    evidence_ids, error = _json_list(evidence_ids_json, field="evidence_ids_json")
    if error:
        return json.dumps({"success": False, "error": error})
    metadata, error = _json_object(metadata_json, field="metadata_json")
    if error:
        return json.dumps({"success": False, "error": error})
    result = await graph.add_task(
        title=title,
        role=role,
        phase=phase,
        risk=risk,
        dispatch_key=dispatch_key,
        dependencies=dependencies,
        evidence_ids=evidence_ids,
        metadata=metadata,
    )
    return json.dumps(result, ensure_ascii=False)


@function_tool(timeout=30)
async def update_attack_task(
    ctx: RunContextWrapper,
    task_id: str,
    status: str,
    increment_attempt: bool = False,
) -> str:
    """Update a task status after planning or execution progress."""

    graph = _graph(ctx)
    if graph is None:
        return json.dumps({"success": False, "error": "attack graph unavailable"})
    result = await graph.set_status(task_id, status, increment_attempt=increment_attempt)
    return json.dumps(result, ensure_ascii=False)


@function_tool(timeout=30)
async def list_attack_tasks(
    ctx: RunContextWrapper,
    role: str = "",
    status: str = "",
) -> str:
    """List persisted attack-graph tasks for Planner/specialist coordination."""

    graph = _graph(ctx)
    if graph is None:
        return json.dumps({"success": False, "error": "attack graph unavailable"})
    if status:
        try:
            TaskStatus(status)
        except ValueError:
            return json.dumps({"success": False, "error": f"unknown task status: {status}"})
    snapshot = await graph.snapshot()
    tasks = list(snapshot["tasks"].values())
    if role:
        tasks = [task for task in tasks if task["role"] == role]
    if status:
        tasks = [task for task in tasks if task["status"] == status]
    return json.dumps({"success": True, "tasks": tasks, "count": len(tasks)}, ensure_ascii=False)


__all__ = ["create_attack_task", "list_attack_tasks", "update_attack_task"]
