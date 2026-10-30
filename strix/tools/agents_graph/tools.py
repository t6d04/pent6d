"""Multi-agent graph tools backed by AgentCoordinator."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import uuid
from collections import Counter
from datetime import UTC, datetime
from typing import Any, Literal, get_args

from agents import RunContextWrapper, function_tool

from strix.core.agents import Status, coordinator_from_context
from strix.core.execution import notify_parent_on_terminal
from strix.core.hooks import LLM_TURN_KEY
from strix.report.state import get_global_report_state
from strix.skills import validate_requested_skills
from strix.tools.checklist.tools import validate_checklist_codes


_ACTIVE_STATUSES: frozenset[str] = frozenset({"running", "waiting"})
_AGENT_ROLES: frozenset[str] = frozenset(
    {"recon", "source_mapper", "specialist", "validator", "gap_closer", "chain_reviewer"}
)


logger = logging.getLogger(__name__)


def _ctx(ctx: RunContextWrapper) -> dict[str, Any]:
    return ctx.context if isinstance(ctx.context, dict) else {}


def _normalize_agent_role(  # noqa: PLR0911
    raw: str | None, *, name: str, skills: list[str]
) -> str:
    """Normalize explicit role metadata, with a conservative legacy fallback."""
    value = (raw or "").strip().lower().replace("-", "_").replace(" ", "_")
    if value in _AGENT_ROLES:
        return value
    if "source" in value or any("source" in skill.lower() for skill in skills):
        return "source_mapper"
    haystack = f"{name} {' '.join(skills)}".lower()
    if re.search(r"\b(recon|reconnaissance|asset[_ -]?discovery|mapping)\b", haystack):
        return "recon"
    if re.search(r"\b(chain|impact)\b", haystack):
        return "chain_reviewer"
    if re.search(r"\b(validate|validation|verif|independent)\b", haystack):
        return "validator"
    if re.search(r"\b(gap|follow[_ -]?up|closure)\b", haystack):
        return "gap_closer"
    return "specialist"


def _derived_dispatch_key(
    *, role: str, component: str, risk_area: str, phase: str, task: str
) -> str:
    """Create a stable-enough key when older callers omit one explicitly."""
    parts = [component, risk_area, phase]
    if not any(parts):
        # Do not dedupe arbitrary legacy tasks: only explicit bounded metadata
        # can safely identify two responsibilities as equivalent.
        return ""
    normalized = [re.sub(r"\s+", " ", part.strip().lower()) for part in parts]
    return "|".join([role, *normalized])


def _filed_reports_by(agent_id: str) -> list[dict[str, Any]]:
    """Vulnerability reports the agent actually filed, from report state.

    The narrative ``findings`` an agent hands to ``agent_finish`` is prose; a
    parent that wants to act on a child's work needs the report ids. Read them
    from the report state rather than trusting the child's description.
    """
    state = get_global_report_state()
    if state is None:
        return []
    filed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for report in state.get_existing_vulnerabilities():
        if report.get("agent_id") != agent_id:
            continue
        report_id = str(report.get("id") or "")
        if not report_id or report_id in seen:
            continue
        seen.add(report_id)
        filed.append(report)
    return filed


def _render_filed_report(report: dict[str, Any]) -> str:
    line = f"- {report.get('id')}"
    severity = report.get("severity")
    if severity:
        line += f" [{str(severity).upper()}]"
    title = report.get("title")
    if title:
        line += f" {title}"
    return line


def _render_completion_report(
    *,
    agent_name: str,
    agent_id: str,
    task: str,
    success: bool,
    result_summary: str,
    findings: list[str],
    recommendations: list[str],
    open_items: list[str],
    filed_reports: list[dict[str, Any]] | None = None,
) -> str:
    """Render a child's completion report as plain structured text.

    Goes into the parent's SDK session with coordinator-added sender
    metadata, so this body just carries the contents. No XML — no
    escaping concerns, no parser ambiguity.
    """
    status = "SUCCESS" if success else "FAILED"
    completion_time = datetime.now(UTC).isoformat()

    lines: list[str] = [
        f"== Completion report from {agent_name} ({agent_id}) ==",
        f"Status: {status}",
        f"Time: {completion_time}",
    ]
    if task:
        lines.append(f"Task: {task}")
    lines.append("")
    lines.append("Summary:")
    lines.append(result_summary or "(none)")
    if findings:
        lines.append("")
        lines.append("Findings:")
        lines.extend(f"- {f}" for f in findings)
    lines.append("")
    lines.append("Vulnerability reports filed by this agent (authoritative; use these ids):")
    if filed_reports:
        lines.extend(_render_filed_report(r) for r in filed_reports)
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("Open items (unresolved, need follow-up):")
    if open_items:
        lines.extend(f"- {o}" for o in open_items)
    else:
        lines.append("- (none)")
    if recommendations:
        lines.append("")
        lines.append("Recommendations:")
        lines.extend(f"- {r}" for r in recommendations)
    return "\n".join(lines)


@function_tool(timeout=30)
async def view_agent_graph(ctx: RunContextWrapper) -> str:
    """Print the multi-agent tree — every agent, its parent, its status.

    Use before spawning a new agent (don't duplicate work — check whether
    something specialized for that task already exists) and any time you
    want a snapshot of who's still ``running`` / ``waiting`` /
    ``completed`` / ``crashed`` / ``stopped``. Output is an indented
    bullet list with status in brackets; the agent that called this tool
    is marked ``← you``.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator not initialized in context"},
            ensure_ascii=False,
            default=str,
        )

    parent_of, statuses, names, _ = await coordinator.graph_snapshot()

    lines: list[str] = []

    def render(aid: str, depth: int) -> None:
        status = statuses.get(aid, "?")
        marker = "  ← you" if aid == me else ""
        lines.append(f"{'  ' * depth}- {names.get(aid, aid)} ({aid}) [{status}]{marker}")
        for child, p in parent_of.items():
            if p == aid:
                render(child, depth + 1)

    roots = [aid for aid, parent in parent_of.items() if parent is None]
    for root in roots:
        render(root, 0)

    counts = Counter(statuses.values())
    summary: dict[str, int] = {"total": len(parent_of)}
    for status_name in get_args(Status):
        summary[status_name] = counts.get(status_name, 0)
    return json.dumps(
        {
            "success": True,
            "graph_structure": "\n".join(lines) or "(no agents)",
            "summary": summary,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def send_message_to_agent(
    ctx: RunContextWrapper,
    target_agent_id: str,
    message: str,
    message_type: Literal["query", "instruction", "information"] = "information",
    priority: Literal["low", "normal", "high", "urgent"] = "normal",
) -> str:
    """Send a message to another agent's inbox — sparingly.

    Inter-agent messages are appended to the target's SDK session and
    interrupt any active target turn so the next run cycle sees them.
    Use only when essential:

    - Sharing a discovered finding/credential another agent needs.
    - Asking a specialist a focused question.
    - Coordinating who covers what (avoid overlap).
    - Telling a child to wrap up or change course.

    **Don't** use for routine "hello/status" pings, for context the
    target already has (children inherit parent history), or when
    parent/child completion via ``agent_finish`` already covers the
    flow. In interactive runs a message wakes the target regardless of
    status, so a follow-up can restart a completed/stopped/failed agent.
    In non-interactive runs a finished agent is gone for good: the call
    fails with the target's status, and you should read its filed
    reports (``list_reports``) or spawn a new agent instead of waiting.

    Args:
        target_agent_id: Recipient's 8-char id.
        message: The full message body. Be specific — include payloads,
            URLs, or what you want them to do, not just headlines.
        message_type: ``query`` (you want a reply), ``instruction``
            (you're directing them), ``information`` (FYI, no reply
            expected). Default ``information``.
        priority: ``low`` / ``normal`` / ``high`` / ``urgent``.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )
    if target_agent_id == me:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "Cannot send a message to yourself; use `think` to record a "
                    "private note, or `agent_finish` / `finish_scan` to terminate"
                ),
            },
            ensure_ascii=False,
            default=str,
        )

    msg_id = f"msg_{uuid.uuid4().hex[:8]}"
    delivered = await coordinator.send(
        target_agent_id,
        {
            "id": msg_id,
            "from": me,
            "content": message,
            "type": message_type,
            "priority": priority,
        },
    )
    if not delivered:
        _, status = await coordinator.reachability(target_agent_id)
        if status is None:
            error = f"Target agent '{target_agent_id}' not found"
        else:
            error = (
                f"Target agent '{target_agent_id}' is '{status}' and cannot be woken in "
                "this run; it will never read this message. Its filed reports are in "
                "list_reports / get_report. Do not wait_for_agents on it - spawn a new "
                "agent if more work is needed."
            )
        return json.dumps(
            {
                "success": False,
                "error": error,
                "target_agent_id": target_agent_id,
                "target_status": status,
                "delivery_status": "not_delivered",
            },
            ensure_ascii=False,
            default=str,
        )
    return json.dumps(
        {
            "success": True,
            "message_id": msg_id,
            "target_agent_id": target_agent_id,
            "delivery_status": "delivered",
        },
        ensure_ascii=False,
        default=str,
    )


def _session_items_payload(items: list[Any]) -> list[dict[str, Any]]:
    payload: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            role = item.get("role")
            content = item.get("content")
            payload.append({"role": role, "content": content})
        else:
            payload.append({"content": str(item)})
    return payload


_WAIT_DEFAULT_TIMEOUT_S = 300
# Enforced by the SDK around the whole tool call, so it caps an oversized
# ``timeout_seconds`` the model asks for. One second of headroom lets the
# tool's own timeout fire first and return a clean result.
_WAIT_HARD_CEILING_S = _WAIT_DEFAULT_TIMEOUT_S + 1
_WAITED_TURN_KEY = "waited_llm_turn"


@function_tool(timeout=_WAIT_HARD_CEILING_S)
async def wait_for_agents(  # noqa: PLR0911
    ctx: RunContextWrapper,
    reason: str = "Waiting for messages from other agents",
    timeout_seconds: int = _WAIT_DEFAULT_TIMEOUT_S,
) -> str:
    """Pause until another AGENT messages you (or the timeout elapses).

    Use when you have nothing useful to do until a child or peer
    responds — typically after spawning subagents and you want their
    completion reports. You resume the instant any message arrives, so
    size ``timeout_seconds`` to the work you're awaiting.

    **Issue exactly one wait, then stop and react to what it returns.**
    This call blocks and resumes on its own; it is not a poll you repeat.
    Do not write out a wait/check loop ahead of time — a second wait in
    the same turn returns immediately without waiting.

    **This tool is only for waiting on other agents.** Two things it is
    NOT for:

    - **Talking to the user.** Use ``respond_to_user``, which delivers
      your message and hands control back in one call.
    - **Waiting for a long-running command.** This tool does not watch
      processes at all — it sleeps until a *message* arrives, so it
      burns the full timeout even if your command finished a second
      later. Poll the process instead: ``exec_command`` returns a
      session/process id, and ``write_stdin`` with ``chars=""`` returns
      as soon as there is new output or the process exits.

    **Critical caveats:**

    - **Never** call this if you have no agents left to hear from —
      that just strands you until the timeout. Call ``finish_scan``
      (root) or ``agent_finish`` (subagent) instead.
    - If you're waiting on an agent that **isn't your child**, message
      it first asking it to ping you when done — otherwise it has no
      reason to send to your inbox and you'll wait the full timeout.
    - Children update the parent automatically via ``agent_finish``
      → no extra coordination needed.

    Args:
        reason: One-line note shown in graph snapshots while you're
            waiting (helps a human or sibling agent debug who's stuck
            on what).
        timeout_seconds: Max seconds to wait (default 300, and values above
            that are cut short by a hard ceiling). This is only
            a cap — the tool returns the INSTANT a message arrives, so a
            larger value never makes you wait longer when the reply does
            come. Right-size it to what you're waiting on: a short wait
            (e.g. 10-60s) for a quick ack or a small/fast subtask, and a
            longer one (e.g. ~100-200s) only for genuinely long-running
            work (deep recon, exploitation, a full sub-scan). The cap only
            bites when the expected message never arrives — so an oversized
            timeout on a trivial wait just strands you idle until it
            elapses. On timeout the tool returns and you decide whether to
            keep working or wait again.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    interactive = bool(inner.get("interactive", False))
    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )

    turn = inner.get(LLM_TURN_KEY)
    if turn is not None and inner.get(_WAITED_TURN_KEY) == turn:
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "already_waited",
                "reason": reason,
                "note": (
                    "You already waited in this turn. A single wait_for_agents blocks and "
                    "resumes on its own, so queueing more waits only strands you — issue one "
                    "wait, then react to what it returns."
                ),
            },
            ensure_ascii=False,
            default=str,
        )
    inner[_WAITED_TURN_KEY] = turn

    async with coordinator._lock:
        stopped = coordinator.statuses.get(me) == "stopped"
    if stopped:
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "stopped",
                "reason": reason,
                "note": "Wait ended because this agent is stopped.",
            },
            ensure_ascii=False,
            default=str,
        )

    pending, items = await coordinator.consume_pending(me, include_items=True)
    if pending > 0:
        await coordinator.mark_running(me)
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "message_arrived",
                "pending_messages": pending,
                "messages": _session_items_payload(items),
                "reason": reason,
            },
            ensure_ascii=False,
            default=str,
        )

    if interactive:
        await coordinator.park_waiting(me, wait_kind="agents")
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "waiting",
                "reason": reason,
                "note": "Agent parked; execution will resume when a message arrives.",
            },
            ensure_ascii=False,
            default=str,
        )

    # Non-interactive agents cannot be woken once terminal, so with nobody
    # running or waiting there is no message left to wait for.
    if not await coordinator.active_agents_except(me):
        _, statuses, names, _ = await coordinator.graph_snapshot()
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "no_active_agents",
                "reason": reason,
                "agents": [
                    {"agent_id": aid, "name": names.get(aid, aid), "status": status}
                    for aid, status in statuses.items()
                    if aid != me
                ],
                "note": (
                    "No other agent is running or waiting, so no message can arrive. "
                    "Finished agents' results are in list_reports / get_report and their "
                    "completion reports are already in your history. Continue your own "
                    "work, spawn a new agent, or finish."
                ),
            },
            ensure_ascii=False,
            default=str,
        )

    await coordinator.park_waiting(me, wait_kind="agents")
    try:
        await asyncio.wait_for(coordinator.wait_for_message(me), timeout_seconds)
    except TimeoutError:
        await coordinator.mark_running(me)
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "timeout",
                "timeout_seconds": timeout_seconds,
                "reason": reason,
                "note": "No messages within timeout — continue work or call agent_finish.",
            },
            ensure_ascii=False,
            default=str,
        )

    async with coordinator._lock:
        stopped = coordinator.statuses.get(me) == "stopped"
    if stopped:
        return json.dumps(
            {
                "success": True,
                "wait_outcome": "stopped",
                "reason": reason,
                "note": "Wait ended because this agent is stopped.",
            },
            ensure_ascii=False,
            default=str,
        )

    pending, items = await coordinator.consume_pending(me, include_items=True)
    await coordinator.mark_running(me)

    return json.dumps(
        {
            "success": True,
            "wait_outcome": "message_arrived",
            "pending_messages": pending,
            "messages": _session_items_payload(items),
            "reason": reason,
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=120)
async def create_agent(  # noqa: PLR0911, PLR0912, PLR0915
    ctx: RunContextWrapper,
    name: str,
    task: str,
    inherit_context: bool = True,
    skills: list[str] | None = None,
    source_review: bool = False,
    role: str | None = None,
    component: str = "",
    risk_area: str = "",
    phase: str = "",
    evidence_ids: list[str] | None = None,
    checklist_codes: list[str] | None = None,
    stop_conditions: list[str] | None = None,
    dispatch_key: str = "",
) -> str:
    """Spawn a specialist child agent to run in parallel.

    Decompose complex pentests by handing focused subtasks to dedicated
    children. The child runs asynchronously — the parent continues
    immediately and can ``wait_for_agents`` later (or just keep
    working in parallel). When the child calls ``agent_finish``, its
    completion report lands in the parent's inbox.

    **Before spawning, call ``view_agent_graph``** to confirm no
    existing agent already covers this scope — duplicate specialists
    waste turns and create coordination headaches.

    **Specialization principles:**

    - Most agents need at least one ``skill`` to be useful.
    - Aim for **1-3 related skills** per agent. Up to 5 only when the
      task genuinely spans them.
    - One skill = most focused (e.g., XSS-only). Five skills = upper
      bound.
    - Match the ``name`` to the focus (``XSS Specialist``,
      ``SQLi Validator``, ``Auth Specialist``).

    **When to spawn vs do it yourself:**

    - Spawn when the subtask is large, parallelizable, or needs
      different specialization than what you're already doing.
    - Don't spawn for trivial one-shot probes — just run the tool
      yourself.

    **Dispatch metadata (required for new scans):**

    - ``role``: ``recon``, ``source_mapper``, ``specialist``, ``validator``,
      ``gap_closer``, or ``chain_reviewer``.  If omitted, Strix infers a
      conservative role from the name and skills for backwards compatibility.
    - ``component`` and ``risk_area`` identify the bounded responsibility.
    - ``phase`` is ``discovery``, ``testing``, ``validation``, or
      ``impact_review``.
    - ``evidence_ids`` names recon/request/finding records supporting the task.
    - ``checklist_codes`` assigns the methodology classes this child owns;
      every specialist/validator on checklist-enabled runs must receive at
      least one code so the planner can reconcile work without guessing.
    - ``dispatch_key`` should be stable for the run (for example
      ``api.example.test|tenant-api|idor|testing``); an active or completed
      child with the same key is not spawned again.

    Args:
        name: Human-readable child name (used in graph views and
            ``send_message_to_agent`` flows).
        task: Specific objective. Be concrete — what to test, what
            success looks like, any constraints. Name the target the
            child should call ``get_threat_model`` on, and any shared
            state it should build on rather than rediscover — what
            recon already mapped, which surfaces are already covered,
            which coverage entry it is picking up. A child that is not
            told what is already known repeats it.
        inherit_context: Default ``True``. The child receives the
            parent's input history as background; only set ``False``
            when starting a clean-slate task.
        skills: List of skill names (e.g. ``["xss", "sql_injection"]``).
            Max 5; prefer 1-3.
        source_review: Set ``True`` only when the task reviews source already
            materialized inside ``/workspace`` (including source recovered
            during a black-box scan). This loads the internal white-box/source
            analysis baseline for the child. It does not authorize another
            target, expand network scope, or make discovered external assets
            eligible for active testing.
        role: Bounded child role. New scans should always provide this.
        component: One trust boundary or product component, not the whole target.
        risk_area: One vulnerability family or hypothesis area.
        phase: Lifecycle phase for this child.
        evidence_ids: IDs of durable observations supporting the dispatch.
        checklist_codes: Stable methodology checklist codes owned by the child.
        stop_conditions: Concrete conditions for ending the child.
        dispatch_key: Stable deduplication key for this responsibility.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    parent_id = inner.get("agent_id")
    spawner = inner.get("spawn_child_agent")

    if coordinator is None or parent_id is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )
    if not callable(spawner):
        return json.dumps(
            {
                "success": False,
                "error": "Scan runner did not provide a child-agent spawner in context",
            },
            ensure_ascii=False,
            default=str,
        )

    skill_list = list(skills or [])
    skill_error = validate_requested_skills(skill_list)
    if skill_error:
        return json.dumps(
            {"success": False, "error": skill_error, "agent_id": None},
            ensure_ascii=False,
            default=str,
        )

    role_value = _normalize_agent_role(role, name=name, skills=skill_list)
    component_value = component.strip()
    risk_value = risk_area.strip()
    phase_value = phase.strip()
    evidence_values = [str(value).strip() for value in (evidence_ids or []) if str(value).strip()]
    checklist_values = [
        str(value).strip() for value in (checklist_codes or []) if str(value).strip()
    ]
    stop_values = [str(value).strip() for value in (stop_conditions or []) if str(value).strip()]
    dispatch_value = dispatch_key.strip() or _derived_dispatch_key(
        role=role_value,
        component=component_value,
        risk_area=risk_value,
        phase=phase_value,
        task=task,
    )

    scan_mode = str(inner.get("scan_mode") or "").strip().lower()
    target_types = {
        str(value).strip().lower()
        for value in (inner.get("scan_target_types") or [])
        if str(value).strip()
    }
    live_target = bool(
        target_types
        & {"web_application", "api_spec", "ip_address", "repository", "local_code"}
    )
    parent_is_root = coordinator.parent_of.get(parent_id) is None
    if (
        live_target
        and scan_mode in {"quick", "standard", "deep"}
        and role_value not in {"recon", "source_mapper"}
        and not inner.get("recon_finalized")
    ):
        return json.dumps(
            {
                "success": False,
                "error": (
                    "Recon is not finalized. Wait for the mapper to complete, "
                    "call finalize_recon to snapshot the full inventory into "
                    "shared memory, then spawn specialists."
                ),
            },
            ensure_ascii=False,
        )
    unknown_checklist_codes = validate_checklist_codes(checklist_values)
    if unknown_checklist_codes:
        return json.dumps(
            {
                "success": False,
                "error": "Unknown checklist code(s): " + ", ".join(unknown_checklist_codes),
                "checklist_codes": checklist_values,
            },
            ensure_ascii=False,
        )
    if parent_is_root and live_target and scan_mode in {"standard", "deep"}:
        required_metadata = [
            field
            for field, present in (
                ("component", bool(component_value)),
                ("phase", bool(phase_value)),
                ("stop_conditions", bool(stop_values)),
            )
            if not present
        ]
        if role_value not in {"recon", "source_mapper"} and not evidence_values:
            required_metadata.append("evidence_ids")
        if (
            inner.get("checklist_enabled")
            and role_value not in {"recon", "source_mapper"}
            and not checklist_values
        ):
            required_metadata.append("checklist_codes")
        if required_metadata:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "A bounded child dispatch is missing required metadata: "
                        + ", ".join(required_metadata)
                        + "."
                    ),
                    "dispatch_key": dispatch_value,
                },
                ensure_ascii=False,
            )
        child_metadata = coordinator.metadata
        has_mapper = any(
            isinstance(metadata, dict)
            and (
                metadata.get("role") in {"recon", "source_mapper"}
                or _normalize_agent_role(
                    None,
                    name=coordinator.names.get(child_id, ""),
                    skills=list(metadata.get("skills") or []),
                )
                in {"recon", "source_mapper"}
            )
            for child_id, metadata in child_metadata.items()
            if coordinator.parent_of.get(child_id) is not None
        )
        if not has_mapper and role_value not in {"recon", "source_mapper"}:
            return json.dumps(
                {
                    "success": False,
                    "error": (
                        "The first child for a standard/deep live scan must be a "
                        "recon or source_mapper child. Provide role='recon' or "
                        "role='source_mapper' and a bounded component."
                    ),
                    "dispatch_key": dispatch_value,
                },
                ensure_ascii=False,
            )

    max_children = int(inner.get("max_concurrent_children") or 4)
    active_statuses = {"running", "waiting", "budget_paused"}
    active_children = sum(
        1
        for child_id, status in coordinator.statuses.items()
        if coordinator.parent_of.get(child_id) is not None and status in active_statuses
    )
    if active_children >= max(1, max_children):
        return json.dumps(
            {
                "success": False,
                "error": (
                    f"Concurrent child limit reached ({max_children}). Wait for a "
                    "child to finish before spawning another focused task."
                ),
                "active_children": active_children,
                "max_concurrent_children": max_children,
            },
            ensure_ascii=False,
        )

    if dispatch_value:
        duplicate = next(
            (
                child_id
                for child_id, metadata in coordinator.metadata.items()
                if coordinator.parent_of.get(child_id) is not None
                and isinstance(metadata, dict)
                and metadata.get("dispatch_key") == dispatch_value
            ),
            None,
        )
        if duplicate is not None:
            return json.dumps(
                {
                    "success": False,
                    "error": "A child with the same dispatch_key already exists.",
                    "duplicate_agent_id": duplicate,
                    "dispatch_key": dispatch_value,
                },
                ensure_ascii=False,
            )

    parent_history = list(ctx.turn_input) if inherit_context and ctx.turn_input else []
    try:
        spawn_kwargs: dict[str, Any] = {
            "parent_ctx": inner,
            "name": name,
            "task": task,
            "skills": skill_list,
            "parent_history": parent_history,
            "role": role_value,
            "component": component_value,
            "risk_area": risk_value,
            "phase": phase_value,
            "evidence_ids": evidence_values,
            "checklist_codes": checklist_values,
            "stop_conditions": stop_values,
            "dispatch_key": dispatch_value,
        }
        if source_review:
            spawn_kwargs["source_review"] = True
        try:
            result = await spawner(**spawn_kwargs)
        except TypeError as exc:
            # A few integrations still expose the pre-metadata spawner
            # signature.  Preserve that compatibility without weakening the
            # runtime policy used by the built-in runner.
            if "unexpected keyword" not in str(exc) and "got an unexpected" not in str(exc):
                raise
            legacy_kwargs = {
                key: spawn_kwargs[key]
                for key in ("parent_ctx", "name", "task", "skills", "parent_history")
            }
            if source_review:
                legacy_kwargs["source_review"] = True
            result = await spawner(**legacy_kwargs)
    except Exception as e:
        logger.exception("create_agent: scan runner failed to spawn child '%s'", name)
        return json.dumps(
            {"success": False, "error": f"child spawn failed: {e!s}"},
            ensure_ascii=False,
            default=str,
        )

    logger.info(
        "create_agent: spawned %s (%s) parent=%s skills=%d task_len=%d",
        result.get("agent_id"),
        name,
        parent_id or "-",
        len(skill_list),
        len(task or ""),
    )

    # Keep the workflow graph populated even when a legacy caller only uses
    # create_agent. Explicit Planner tasks can still add richer dependency and
    # source-node metadata through create_attack_task.
    attack_graph = inner.get("attack_graph")
    if attack_graph is not None and hasattr(attack_graph, "add_task"):
        with contextlib.suppress(Exception):
            graph_task = await attack_graph.add_task(
                title=task.strip() or name.strip(),
                role=role_value,
                phase=phase_value or "execution",
                risk="high" if risk_value in {"critical", "high"} else "medium",
                dispatch_key=dispatch_value,
                evidence_ids=evidence_values,
                metadata={
                    "node_type": "specialist",
                    "generated_by": (
                        f"run:{inner.get('scan_id')}" if parent_is_root else str(parent_id)
                    ),
                    "source_node_ids": [f"run:{inner.get('scan_id')}"] if parent_is_root else [],
                    "source_information": evidence_values,
                    "checklist_codes": checklist_values,
                    "skills": skill_list,
                    "source_review": source_review,
                    "component": component_value,
                    "risk_area": risk_value,
                    "stop_conditions": stop_values,
                    "agent_id": result.get("agent_id"),
                },
            )
            if graph_task.get("success") and isinstance(graph_task.get("task"), dict):
                result = {
                    **result,
                    "attack_task_id": graph_task["task"].get("task_id"),
                }

    return json.dumps(
        result,
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=120)
async def dispatch_ready_tasks(
    ctx: RunContextWrapper,
    max_tasks: int = 4,
) -> str:
    """Dispatch ready graph follow-ups without duplicating child agents.

    This is the deterministic bridge between the Planner graph and the
    coordinator. It only dispatches scheduler-created validator/chain tasks
    that carry inherited skills and evidence; broad planner tasks still need
    an explicit ``create_agent`` call with a bounded scope.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    graph = inner.get("attack_graph")
    spawner = inner.get("spawn_child_agent")
    if coordinator is None or not isinstance(me, str):
        return json.dumps({"success": False, "error": "agent coordinator unavailable"})
    if coordinator.parent_of.get(me) is not None:
        return json.dumps(
            {"success": False, "error": "only the root agent may dispatch graph tasks"}
        )
    if graph is None or not hasattr(graph, "ready_tasks"):
        return json.dumps({"success": False, "error": "attack graph unavailable"})
    if not callable(spawner):
        return json.dumps({"success": False, "error": "child-agent spawner unavailable"})

    limit = max(1, min(int(max_tasks), 8))
    ready = await graph.ready_tasks()
    candidates = [
        task
        for task in ready
        if task.get("role") in {"validator", "chain_reviewer", "gap_closer"}
        and isinstance(task.get("metadata"), dict)
        and task["metadata"].get("node_type") in {"validator", "chain_reviewer", "follow_up"}
    ]
    active = sum(
        1
        for child_id, status in coordinator.statuses.items()
        if coordinator.parent_of.get(child_id) is not None
        and status in {"running", "waiting", "budget_paused"}
    )
    capacity = max(0, int(inner.get("max_concurrent_children") or 4) - active)
    selected = candidates[: min(limit, capacity)]
    if not selected:
        return json.dumps(
            {
                "success": True,
                "dispatched": [],
                "skipped": len(candidates),
                "active_children": active,
                "note": "No dispatchable ready follow-up task is available.",
            },
            ensure_ascii=False,
        )

    parent_history = list(ctx.turn_input) if ctx.turn_input else []
    dispatched: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for task in selected:
        task_id = str(task.get("task_id") or "")
        metadata = dict(task.get("metadata") or {})
        skills = [str(item) for item in metadata.get("skills", []) if str(item).strip()]
        if not task_id or not skills:
            failures.append({"task_id": task_id, "error": "follow-up has no inherited skills"})
            continue
        await graph.set_status(task_id, "running", increment_attempt=True)
        try:
            result = await spawner(
                parent_ctx=inner,
                name=str(task.get("title") or task.get("role") or "Follow-up"),
                task=(
                    f"{task.get('title', 'Follow-up task')}\n"
                    "Use the inherited evidence and shared memory; validate the source task, "
                    "record coverage/checklist outcomes, and close with agent_finish."
                ),
                skills=skills,
                parent_history=parent_history,
                source_review=bool(metadata.get("source_review")),
                role=str(task.get("role") or "validator"),
                component=str(metadata.get("component") or ""),
                risk_area=str(metadata.get("risk_area") or task.get("risk") or ""),
                phase=str(task.get("phase") or "validation"),
                evidence_ids=list(task.get("evidence_ids") or []),
                checklist_codes=list(metadata.get("checklist_codes") or []),
                stop_conditions=list(metadata.get("stop_conditions") or []),
                dispatch_key=str(task.get("dispatch_key") or task_id),
            )
            if not result.get("success") or not result.get("agent_id"):
                await graph.set_status(task_id, "failed")
                failures.append({"task_id": task_id, "error": result.get("error", "spawn failed")})
                continue
            await graph.bind_agent(task_id, str(result["agent_id"]))
            dispatched.append({"task": task, "agent": result})
        except (RuntimeError, TypeError, ValueError) as exc:
            await graph.set_status(task_id, "failed")
            failures.append({"task_id": task_id, "error": str(exc)})

    return json.dumps(
        {
            "success": not failures,
            "dispatched": dispatched,
            "failures": failures,
            "remaining_ready": max(0, len(candidates) - len(selected)),
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def agent_finish(
    ctx: RunContextWrapper,
    result_summary: str,
    findings: list[str] | None = None,
    open_items: list[str] | None = None,
    success: bool = True,
    report_to_parent: bool = True,
    final_recommendations: list[str] | None = None,
) -> str:
    """Subagent termination — post a completion report to the parent.

    **Subagents only.** Root agents must call ``finish_scan`` instead;
    this tool refuses to run for root agents. Calling this:

    1. Marks the subagent as ``completed``.
    2. Posts a structured completion report to the parent's inbox
       (when ``report_to_parent`` is true).
    3. Stops this subagent's execution.

    For checklist-enabled runs, completion also closes the matching attack
    graph task and creates idempotent validator/chain-review tasks when the
    role and evidence warrant them. The parent receives those task records in
    the completion message and should dispatch them before finishing.

    **Vulnerability findings must already be filed via
    ``create_vulnerability_report`` (or ``create_dependency_report``
    for known-CVE dependency/supply-chain findings) before calling
    this.** The ``findings`` field here is for narrative summary only
    — it does not register vulns in the scan report.

    Write the summary as if the parent has no idea what you were
    doing: what did you test, what did you find/confirm/rule out,
    what's still open.

    **Close out honestly.** Before calling this, every surface you
    assessed should have a ``record_coverage`` entry, and anything you
    could neither confirm nor rule out belongs in ``open_items`` — an
    unresolved candidate handed up to the parent is useful, a silently
    dropped one is a missed vulnerability. Reporting nothing and
    listing no open items asserts the area is clean; only say that if
    you mean it.

    Args:
        result_summary: What you accomplished and discovered. Concrete
            and specific (URLs, parameters, payloads that worked).
        findings: Optional bullet list of confirmed observations. For
            credit-bearing vulnerabilities, file
            ``create_vulnerability_report`` first (or
            ``create_dependency_report`` for dependency CVEs); this is
            for narrative.
        open_items: Candidates you could NOT confirm and could NOT rule
            out with a named control, plus anything you ran out of time
            or access to test. State the specific gap (e.g. "password
            reset token entropy — could not obtain a second account to
            compare tokens"). Pass an empty list only when nothing is
            genuinely left open.
        success: Whether the assigned subtask was completed
            successfully. Default ``True``.
        report_to_parent: Whether to deliver the completion report to
            the parent's inbox. Default ``True``.
        final_recommendations: Optional next-step suggestions for the
            parent (e.g., "prioritize testing X", "spawn an agent to
            cover Y").
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )

    parent_id = inner.get("parent_id")
    if parent_id is None:
        return json.dumps(
            {
                "success": False,
                "error": (
                    "agent_finish is for subagents. Root/main agents must call finish_scan instead"
                ),
            },
            ensure_ascii=False,
            default=str,
        )

    filed_reports = _filed_reports_by(me)
    filed_report_ids = [str(r.get("id")) for r in filed_reports]

    scheduled_tasks: list[dict[str, Any]] = []
    attack_graph = inner.get("attack_graph")
    if me and attack_graph is not None and hasattr(attack_graph, "complete_and_schedule_followups"):
        metadata = coordinator.metadata.get(me, {}) if coordinator is not None else {}
        with contextlib.suppress(Exception):
            follow_up = await attack_graph.complete_and_schedule_followups(
                agent_id=me,
                role=str(metadata.get("role") or "specialist"),
                success=success,
                report_ids=filed_report_ids,
                findings=list(findings or []),
                open_items=list(open_items or []),
                evidence_ids=list(metadata.get("evidence_ids") or []),
                checklist_codes=list(metadata.get("checklist_codes") or []),
            )
            scheduled_tasks = list(follow_up.get("scheduled_tasks") or [])

    # Mark the current child terminal before dispatching so its slot is
    # released and the follow-up scheduler can use the full concurrency budget.
    await coordinator.set_status(me, "completed")
    automatic_dispatch = await coordinator.dispatch_ready_followups()
    automatic_tasks = list(automatic_dispatch.get("dispatched") or [])

    parent_notified = False
    if report_to_parent and await coordinator.claim_parent_notice(me):
        async with coordinator._lock:
            agent_name = coordinator.names.get(me, me)
        report = _render_completion_report(
            agent_name=agent_name,
            agent_id=me,
            task=str(inner.get("task", "")),
            success=success,
            result_summary=result_summary,
            findings=list(findings or []),
            recommendations=list(final_recommendations or []),
            open_items=list(open_items or []),
            filed_reports=filed_reports,
        )
        if scheduled_tasks:
            report += "\n\n[Workflow scheduler] Follow-up tasks created:\n" + "\n".join(
                f"- {task.get('task_id')}: {task.get('role')} — {task.get('title')} "
                f"({task.get('status')})"
                for task in scheduled_tasks
            )
        if automatic_tasks:
            report += "\n\n[Workflow scheduler] Automatically dispatched:\n" + "\n".join(
                f"- {item.get('agent', {}).get('agent_id', '')}: "
                f"{item.get('task', {}).get('role', 'follow-up')} — "
                f"{item.get('task', {}).get('title', '')}"
                for item in automatic_tasks
            )
        await coordinator.send(
            parent_id,
            {
                "id": f"report_{uuid.uuid4().hex[:8]}",
                "from": me,
                "content": report,
                "type": "completion",
                "priority": "high",
                "filed_report_ids": filed_report_ids,
                "scheduled_tasks": scheduled_tasks,
            },
        )
        parent_notified = True

    if not parent_notified:
        # Silence here would leave a parent waiting on a report that is never coming.
        await notify_parent_on_terminal(coordinator, me, "completed")

    logger.info(
        "agent_finish: %s success=%s findings=%d filed_reports=%d parent_notified=%s",
        me,
        success,
        len(findings or []),
        len(filed_report_ids),
        parent_notified,
    )

    return json.dumps(
        {
            "success": True,
            "agent_completed": True,
            "parent_notified": parent_notified,
            "agent_id": me,
            "summary": result_summary,
            "filed_report_ids": filed_report_ids,
            "scheduled_tasks": scheduled_tasks,
            "automatic_dispatch": automatic_dispatch,
            "findings_count": len(findings or []),
            "open_items_count": len(open_items or []),
            "has_recommendations": bool(final_recommendations),
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def stop_agent(
    ctx: RunContextWrapper,
    target_agent_id: str,
    cascade: bool = True,
    reason: str = "",
) -> str:
    """Gracefully stop a running agent (and optionally its descendants).

    Uses the SDK's ``RunResultStreaming.cancel(mode="after_turn")`` so the
    target's current turn finishes — including saving items to its
    session — before the run loop honors the cancel. The agent's
    interactive outer loop parks as ``stopped``; later user/peer
    messages can wake it again.

    Use sparingly. Prefer ``send_message_to_agent`` (asking the agent
    to wrap up) for soft-stop scenarios. Reach for ``stop_agent`` when
    a child has gone off-track and won't self-correct.

    Args:
        target_agent_id: The 8-char id from ``view_agent_graph`` /
            ``create_agent``. Cannot stop yourself.
        cascade: If ``True`` (default), also stop every descendant of
            ``target_agent_id`` leaves-first. ``False`` stops only the
            target.
        reason: Optional human-readable reason for the stop, surfaced
            in logs and telemetry.
    """
    inner = _ctx(ctx)
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    if coordinator is None or me is None:
        return json.dumps(
            {"success": False, "error": "Agent coordinator or agent_id missing in context"},
            ensure_ascii=False,
            default=str,
        )
    if target_agent_id == me:
        return json.dumps(
            {
                "success": False,
                "error": "Cannot stop yourself; call agent_finish or finish_scan instead",
            },
            ensure_ascii=False,
            default=str,
        )
    _, statuses, _, _ = await coordinator.graph_snapshot()
    if target_agent_id not in statuses:
        return json.dumps(
            {"success": False, "error": f"Unknown agent_id: {target_agent_id}"},
            ensure_ascii=False,
            default=str,
        )

    current_status = statuses[target_agent_id]
    if current_status not in _ACTIVE_STATUSES:
        return json.dumps(
            {
                "success": False,
                "error": (
                    f"Agent {target_agent_id} is already '{current_status}'; "
                    "stop_agent only acts on running/waiting agents — use "
                    "view_agent_graph to find still-active descendants and "
                    "stop them individually, or send_message_to_agent if you "
                    "want to wake this one with new instructions"
                ),
                "target_agent_id": target_agent_id,
                "current_status": current_status,
            },
            ensure_ascii=False,
            default=str,
        )

    if cascade:
        stopped = await coordinator.cancel_descendants_graceful(target_agent_id)
    else:
        await coordinator.request_stop(target_agent_id)
        stopped = [target_agent_id]

    # The stopper knows what it just did; anyone else waiting on those agents does not.
    async with coordinator._lock:
        orphaned = [aid for aid in stopped if coordinator.parent_of.get(aid) not in (None, me)]
    for aid in orphaned:
        await notify_parent_on_terminal(coordinator, aid, "stopped")

    logger.info(
        "stop_agent: target=%s cascade=%s reason=%r",
        target_agent_id,
        cascade,
        reason,
    )
    return json.dumps(
        {
            "success": True,
            "target_agent_id": target_agent_id,
            "cascade": cascade,
            "reason": reason,
            "note": "Cancellation is graceful — current turn completes first.",
        },
        ensure_ascii=False,
        default=str,
    )
