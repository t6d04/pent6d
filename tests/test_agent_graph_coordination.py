"""Tests for parent/child coordination once a non-interactive child has finished.

A non-interactive agent's loop returns after its terminal state, so nothing will
ever read a message sent to it afterwards. Messaging it must say so instead of
reporting delivery, waiting on it must return at once, and its completion report
must carry the ids of the reports it actually filed so the parent does not have
to go asking.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.report.state import ReportState, set_global_report_state
from strix.runtime.attack_graph import AttackGraph
from strix.tools.agents_graph.tools import (
    agent_finish,
    create_agent,
    dispatch_ready_tasks,
    send_message_to_agent,
    wait_for_agents,
)
from strix.tools.checklist.tools import known_checklist_codes


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture
def report_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="test-run")
    set_global_report_state(state)
    yield state
    set_global_report_state(None)


async def _graph(*, interactive: bool) -> AgentCoordinator:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "strix", parent_id=None)
    await coordinator.register("child", "Validator", parent_id="root")
    await coordinator.attach_runtime("root", resumable=interactive)
    await coordinator.attach_runtime("child", resumable=interactive)
    return coordinator


async def _call(
    tool: Any, coordinator: AgentCoordinator, agent_id: str, args: dict[str, Any], **extra: Any
) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": agent_id, **extra},
        tool_name=tool.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await tool.on_invoke_tool(ctx, json.dumps(args))
    return cast("dict[str, Any]", json.loads(raw))


@pytest.mark.asyncio
async def test_create_agent_forwards_source_review_without_internal_skill_names() -> None:
    coordinator = await _graph(interactive=False)
    captured: dict[str, Any] = {}

    async def _spawn(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"success": True, "agent_id": "source-child"}

    result = await _call(
        create_agent,
        coordinator,
        "root",
        {
            "name": "Local Code Review - Discovered Source",
            "task": "Review /workspace/.strix-source-artifacts/example/artifact/source",
            "skills": ["custom/source_aware_sast"],
            "source_review": True,
        },
        spawn_child_agent=_spawn,
    )

    assert result["success"] is True
    assert captured["source_review"] is True
    assert captured["skills"] == ["custom/source_aware_sast"]


@pytest.mark.asyncio
async def test_create_agent_keeps_legacy_spawner_compatible_for_normal_children() -> None:
    coordinator = await _graph(interactive=False)

    async def _legacy_spawn(
        *,
        parent_ctx: dict[str, Any],
        name: str,
        task: str,
        skills: list[str],
        parent_history: list[Any],
    ) -> dict[str, Any]:
        del parent_ctx, task, skills, parent_history
        return {"success": True, "agent_id": "legacy-child", "name": name}

    result = await _call(
        create_agent,
        coordinator,
        "root",
        {"name": "Recon", "task": "Map the target", "skills": ["asset_discovery"]},
        spawn_child_agent=_legacy_spawn,
    )

    assert result["success"] is True
    assert result["name"] == "Recon"


@pytest.mark.asyncio
async def test_live_standard_scan_requires_mapper_before_specialist() -> None:
    coordinator = await _graph(interactive=False)
    called = False

    async def _spawn(**_kwargs: Any) -> dict[str, Any]:
        nonlocal called
        called = True
        return {"success": True, "agent_id": "specialist-child"}

    result = await _call(
        create_agent,
        coordinator,
        "root",
        {
            "name": "IDOR Specialist",
            "task": "Test the tenant API object boundary",
            "skills": ["vulnerabilities/idor"],
            "role": "specialist",
            "component": "tenant-api",
            "risk_area": "idor",
            "phase": "testing",
            "evidence_ids": ["recon-1"],
            "stop_conditions": ["all tenant object references are tested"],
            "dispatch_key": "tenant-api|idor|testing",
        },
        spawn_child_agent=_spawn,
        scan_mode="standard",
        scan_target_types=["web_application"],
        max_concurrent_children=4,
        recon_finalized=True,
    )

    assert result["success"] is False
    assert "first child" in result["error"]
    assert called is False


@pytest.mark.asyncio
async def test_live_specialist_is_blocked_until_recon_snapshot_is_finalized() -> None:
    coordinator = await _graph(interactive=False)

    async def _spawn(**_kwargs: Any) -> dict[str, Any]:
        return {"success": True, "agent_id": "specialist-child"}

    result = await _call(
        create_agent,
        coordinator,
        "root",
        {
            "name": "SSRF Specialist",
            "task": "Test server-side request forgery candidates",
            "skills": ["vulnerabilities/ssrf"],
            "role": "specialist",
            "component": "web",
            "risk_area": "ssrf",
            "phase": "testing",
            "evidence_ids": ["recon-1"],
            "stop_conditions": ["all SSRF candidates are tested"],
            "dispatch_key": "web|ssrf|testing",
        },
        spawn_child_agent=_spawn,
        scan_mode="quick",
        scan_target_types=["web_application"],
        max_concurrent_children=2,
        recon_finalized=False,
    )

    assert result["success"] is False
    assert "Recon is not finalized" in result["error"]


@pytest.mark.asyncio
async def test_checklist_enabled_dispatch_requires_owned_checklist_codes() -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.register("mapper", "Recon Mapper", parent_id="root", role="recon")

    async def _spawn(**_kwargs: Any) -> dict[str, Any]:
        return {"success": True, "agent_id": "specialist-child"}

    base_args = {
        "name": "IDOR Specialist",
        "task": "Test the tenant API object boundary",
        "skills": ["vulnerabilities/idor"],
        "role": "specialist",
        "component": "tenant-api",
        "risk_area": "idor",
        "phase": "testing",
        "evidence_ids": ["recon-1"],
        "stop_conditions": ["all tenant object references are tested"],
        "dispatch_key": "tenant-api|idor|testing",
    }
    context = {
        "spawn_child_agent": _spawn,
        "scan_mode": "standard",
        "scan_target_types": ["web_application"],
        "max_concurrent_children": 4,
        "recon_finalized": True,
        "checklist_enabled": True,
    }
    missing = await _call(create_agent, coordinator, "root", base_args, **context)
    assert missing["success"] is False
    assert "checklist_codes" in missing["error"]

    code = next(iter(known_checklist_codes()))
    complete = await _call(
        create_agent,
        coordinator,
        "root",
        {**base_args, "checklist_codes": [code], "dispatch_key": "tenant-api|idor|testing-2"},
        **context,
    )
    assert complete["success"] is True


@pytest.mark.asyncio
async def test_root_dispatches_ready_followup_from_attack_graph(tmp_path: Path) -> None:
    coordinator = await _graph(interactive=False)
    graph = AttackGraph(tmp_path)
    origin = await graph.add_task(
        title="Test authorization",
        role="specialist",
        phase="execution",
        dispatch_key="api|idor|testing",
        metadata={
            "agent_id": "child",
            "node_type": "specialist",
            "skills": ["vulnerabilities/idor"],
            "checklist_codes": ["P6-VULNERABILITY-IDOR"],
            "component": "api",
            "risk_area": "idor",
        },
    )
    await graph.complete_and_schedule_followups(
        agent_id="child",
        role="specialist",
        success=True,
        report_ids=["finding-1"],
    )
    captured: dict[str, Any] = {}

    async def _spawn(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"success": True, "agent_id": "validator-child"}

    result = await _call(
        dispatch_ready_tasks,
        coordinator,
        "root",
        {"max_tasks": 1},
        attack_graph=graph,
        spawn_child_agent=_spawn,
        max_concurrent_children=4,
    )
    assert result["success"] is True
    assert len(result["dispatched"]) == 1
    assert captured["role"] == "validator"
    assert captured["checklist_codes"] == ["P6-VULNERABILITY-IDOR"]
    snapshot = await graph.snapshot()
    validator = next(task for task in snapshot["tasks"].values() if task["role"] == "validator")
    assert validator["status"] == "running"
    assert validator["metadata"]["agent_id"] == "validator-child"
    assert origin["task"]["task_id"] in validator["dependencies"]


# --- send_message_to_agent -------------------------------------------------------


@pytest.mark.asyncio
async def test_message_to_finished_non_interactive_child_is_not_delivered() -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.set_status("child", "completed")

    result = await _call(
        send_message_to_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "message": "did you file it?", "message_type": "query"},
    )

    assert result["success"] is False
    assert result["delivery_status"] == "not_delivered"
    assert result["target_status"] == "completed"
    assert "list_reports" in result["error"]
    assert coordinator.pending_counts.get("child", 0) == 0
    assert coordinator.runtimes["child"].mailbox == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["stopped", "failed", "crashed"])
async def test_every_terminal_non_interactive_status_is_unreachable(status: str) -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.set_status("child", status)

    assert await coordinator.send("child", {"from": "root", "content": "hi"}) is False
    assert await coordinator.reachability("child") == (False, status)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["running", "waiting"])
async def test_message_to_live_child_is_delivered(status: str) -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.set_status("child", status)

    result = await _call(
        send_message_to_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "message": "wrap up"},
    )

    assert result["success"] is True
    assert result["delivery_status"] == "delivered"
    assert coordinator.pending_counts["child"] == 1


@pytest.mark.asyncio
async def test_message_to_finished_interactive_child_still_wakes_it() -> None:
    # An interactive loop parks after finishing and resumes on a message.
    coordinator = await _graph(interactive=True)
    await coordinator.set_status("child", "completed")

    result = await _call(
        send_message_to_agent,
        coordinator,
        "root",
        {"target_agent_id": "child", "message": "one more thing"},
    )

    assert result["success"] is True
    assert coordinator.pending_counts["child"] == 1


@pytest.mark.asyncio
async def test_unknown_target_is_reported_as_not_found() -> None:
    coordinator = await _graph(interactive=False)

    result = await _call(
        send_message_to_agent,
        coordinator,
        "root",
        {"target_agent_id": "ghost", "message": "hello"},
    )

    assert result["success"] is False
    assert result["target_status"] is None
    assert "not found" in result["error"]


# --- wait_for_agents -------------------------------------------------------------


@pytest.mark.asyncio
async def test_wait_returns_at_once_when_no_child_can_answer() -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.set_status("child", "completed")
    # The completion report was already consumed in an earlier turn.

    result = await _call(
        wait_for_agents,
        coordinator,
        "root",
        {"reason": "waiting for validator", "timeout_seconds": 240},
    )

    assert result["wait_outcome"] == "no_active_agents"
    assert result["agents"] == [{"agent_id": "child", "name": "Validator", "status": "completed"}]
    assert coordinator.statuses["root"] == "running"


@pytest.mark.asyncio
async def test_wait_delivers_a_pending_report_before_checking_liveness() -> None:
    coordinator = await _graph(interactive=False)
    await coordinator.send("root", {"from": "child", "type": "completion", "content": "done"})
    await coordinator.set_status("child", "completed")

    result = await _call(wait_for_agents, coordinator, "root", {"timeout_seconds": 5})

    assert result["wait_outcome"] == "message_arrived"
    assert result["pending_messages"] == 1


@pytest.mark.asyncio
async def test_wait_still_parks_while_a_child_is_running() -> None:
    coordinator = await _graph(interactive=False)

    result = await _call(wait_for_agents, coordinator, "root", {"timeout_seconds": 1})

    assert result["wait_outcome"] == "timeout"


@pytest.mark.asyncio
async def test_interactive_wait_parks_even_without_active_children() -> None:
    # In an interactive run a finished child can be woken later, so parking is
    # legitimate; the run loop's own auto-resume bounds the wait.
    coordinator = await _graph(interactive=True)
    await coordinator.set_status("child", "completed")

    result = await _call(
        wait_for_agents, coordinator, "root", {"timeout_seconds": 5}, interactive=True
    )

    assert result["wait_outcome"] == "waiting"


# --- agent_finish ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_agent_finish_lists_the_reports_the_child_filed(report_state: ReportState) -> None:
    coordinator = await _graph(interactive=False)
    mine = report_state.add_vulnerability_report(
        title="IDOR on /api/audits", severity="high", agent_id="child", agent_name="Validator"
    )
    report_state.add_vulnerability_report(title="Root's own", severity="low", agent_id="root")

    result = await _call(
        agent_finish,
        coordinator,
        "child",
        {"result_summary": "confirmed", "findings": ["IDOR confirmed"]},
        parent_id="root",
    )

    assert result["filed_report_ids"] == [mine]
    delivered = coordinator.runtimes["root"].mailbox
    assert len(delivered) == 1
    assert delivered[0]["filed_report_ids"] == [mine]
    body = delivered[0]["content"]
    assert f"- {mine} [HIGH] IDOR on /api/audits" in body
    assert "Root's own" not in body


@pytest.mark.asyncio
async def test_agent_finish_states_explicitly_when_nothing_was_filed(
    report_state: ReportState,
) -> None:
    coordinator = await _graph(interactive=False)
    report_state.add_vulnerability_report(title="Someone else's", severity="low", agent_id="root")

    result = await _call(
        agent_finish,
        coordinator,
        "child",
        {"result_summary": "nothing exploitable", "findings": ["ruled out X"]},
        parent_id="root",
    )

    assert result["filed_report_ids"] == []
    body = coordinator.runtimes["root"].mailbox[0]["content"]
    assert "Vulnerability reports filed by this agent" in body
    assert body.index("filed by this agent") < body.index("- (none)")


@pytest.mark.asyncio
async def test_agent_finish_without_report_state_still_completes() -> None:
    set_global_report_state(None)
    coordinator = await _graph(interactive=False)

    result = await _call(
        agent_finish, coordinator, "child", {"result_summary": "done"}, parent_id="root"
    )

    assert result["success"] is True
    assert result["filed_report_ids"] == []
