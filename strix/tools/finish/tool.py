"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool

from strix.core.agents import coordinator_from_context
from strix.tools.checklist.tools import checklist_status_for_state_dir
from strix.tools.recon.tools import _host_key, read_recon


logger = logging.getLogger(__name__)


_SPECIALIST_REQUIRED_MODES: frozenset[str] = frozenset({"standard", "deep"})
_LIVE_TARGET_TYPES: frozenset[str] = frozenset(
    {"web_application", "api_spec", "ip_address", "repository", "local_code"}
)
_MAPPER_ROLES: frozenset[str] = frozenset({"recon", "source_mapper"})


def _child_role(agent_id: str, *, metadata: Any, names: Any) -> str:
    """Read role metadata, with a name-based fallback for old run state."""
    role = metadata.get("role") if isinstance(metadata, dict) else None
    if isinstance(role, str):
        return role.strip().lower()
    name = str(names.get(agent_id, "") if isinstance(names, dict) else "").lower()
    if any(token in name for token in ("recon", "mapping", "asset discovery", "source mapper")):
        return "recon"
    if "source" in name and ("review" in name or "code" in name):
        return "source_mapper"
    return "specialist"


def _mapper_completion_gate(
    *,
    scan_mode: str | None,
    target_types: list[str] | tuple[str, ...] | None,
    agent_graph: dict[str, Any],
) -> dict[str, Any] | None:
    """Require a completed mapper even for quick live scans."""
    mode = (scan_mode or "").strip().lower()
    types = [str(value).strip().lower() for value in (target_types or []) if value]
    if mode not in {"quick", "standard", "deep"} or not any(
        target_type in _LIVE_TARGET_TYPES for target_type in types
    ):
        return None
    statuses = agent_graph.get("statuses")
    parents = agent_graph.get("parent_of")
    metadata = agent_graph.get("metadata")
    names = agent_graph.get("names")
    if not isinstance(statuses, dict) or not isinstance(parents, dict):
        return {
            "error": "The agent graph is unavailable, so the required mapper cannot be verified.",
            "scan_mode": mode,
            "target_types": types,
            "mapper_count": 0,
        }
    mapper_ids = [
        agent_id
        for agent_id in statuses
        if parents.get(agent_id) is not None
        and _child_role(
            agent_id,
            metadata=metadata.get(agent_id) if isinstance(metadata, dict) else None,
            names=names,
        )
        in _MAPPER_ROLES
    ]
    completed = [agent_id for agent_id in mapper_ids if statuses.get(agent_id) == "completed"]
    if completed:
        return None
    return {
        "error": (
            "A live scan must complete a recon/source_mapper child before "
            "finish_scan. Spawn a bounded mapper, wait for its durable handoff, "
            "then retry."
        ),
        "scan_mode": mode,
        "target_types": types,
        "mapper_count": len(mapper_ids),
        "mapper_statuses": {str(agent_id): statuses.get(agent_id) for agent_id in mapper_ids},
    }


def _specialist_completion_gate(
    *,
    scan_mode: str | None,
    target_types: list[str] | tuple[str, ...] | None,
    agent_graph: dict[str, Any],
) -> dict[str, Any] | None:
    """Require a real child assessment before a standard/deep scan can finish.

    The root prompt asks the model to delegate, but prompt compliance alone is
    not a reliable completion guarantee.  A live target with only the root in
    the graph is the exact failure mode that produced an under-covered run.
    Keep this gate narrow: quick scans remain time-boxed, and runs without a
    target are allowed to finish their configuration/error report.
    """
    mode = (scan_mode or "").strip().lower()
    types = [str(value).strip().lower() for value in (target_types or []) if value]
    if mode not in _SPECIALIST_REQUIRED_MODES or not any(
        target_type in _LIVE_TARGET_TYPES for target_type in types
    ):
        return None

    statuses = agent_graph.get("statuses")
    parents = agent_graph.get("parent_of")
    metadata = agent_graph.get("metadata")
    if not isinstance(statuses, dict) or not isinstance(parents, dict):
        return {
            "error": (
                "The agent graph is unavailable, so specialist delegation cannot be "
                "verified. Call view_agent_graph, spawn a focused specialist, and retry."
            ),
            "scan_mode": mode,
            "target_types": types,
            "specialist_count": 0,
        }

    names = agent_graph.get("names")
    specialist_ids = [
        agent_id
        for agent_id in statuses
        if parents.get(agent_id) is not None
        and _child_role(
            agent_id,
            metadata=metadata.get(agent_id) if isinstance(metadata, dict) else None,
            names=names,
        )
        not in _MAPPER_ROLES
    ]
    completed_ids = [
        agent_id
        for agent_id in specialist_ids
        if statuses.get(agent_id) == "completed"
    ]
    if completed_ids:
        return None

    specialist_names = [
        str(names.get(agent_id, agent_id))
        for agent_id in specialist_ids
        if isinstance(names, dict)
    ]
    if not specialist_ids:
        return {
            "error": (
                "A standard/deep scan with an in-scope testable target must have at "
                "least one completed specialist child. No child agent exists yet. "
                "Call view_agent_graph, then create_agent with a focused recon-derived "
                "task (or Hypothesis Explorer), wait_for_agents, and retry finish_scan."
            ),
            "scan_mode": mode,
            "target_types": types,
            "specialist_count": 0,
        }

    return {
        "error": (
            "No specialist child has completed a standard/deep assessment. Do not "
            "finish after spawning/stopping a child without its completion report; "
            "wait for the child or spawn a replacement focused specialist, then retry."
        ),
        "scan_mode": mode,
        "target_types": types,
        "specialist_count": len(specialist_ids),
        "specialist_names": specialist_names,
        "specialist_statuses": {
            str(agent_id): statuses.get(agent_id) for agent_id in specialist_ids
        },
        "metadata_present": isinstance(metadata, dict),
    }


def _live_host_coverage_gate(
    *,
    scan_mode: str | None,
    target_types: list[str] | tuple[str, ...] | None,
    agent_graph: dict[str, Any],
    run_dir: Path | None,
) -> dict[str, Any] | None:
    """Require a completed specialist assignment for every live hostname."""

    mode = (scan_mode or "").strip().lower()
    types = {str(value).strip().lower() for value in (target_types or []) if value}
    if mode not in {"standard", "deep"} or not types & _LIVE_TARGET_TYPES or run_dir is None:
        return None
    try:
        entries = read_recon(run_dir).get("entries", [])
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return {
            "error": "Live-host coverage cannot be verified because recon.json is unreadable.",
            "required_hosts": [],
            "missing_hosts": [],
        }
    required_hosts = sorted(
        {
            host
            for entry in entries
            if isinstance(entry, dict)
            and entry.get("scope") == "in_scope"
            and entry.get("alive") == "alive"
            and entry.get("kind") in {"subdomain", "service", "endpoint"}
            and (host := _host_key(str(entry.get("value") or "")))
        }
    )
    if not required_hosts:
        return None

    statuses = agent_graph.get("statuses")
    parents = agent_graph.get("parent_of")
    metadata = agent_graph.get("metadata")
    names = agent_graph.get("names")
    if (
        not isinstance(statuses, dict)
        or not isinstance(parents, dict)
        or not isinstance(metadata, dict)
    ):
        return {
            "error": (
                "Live-host coverage cannot be verified because the agent graph "
                "is unavailable."
            ),
            "required_hosts": required_hosts,
            "missing_hosts": required_hosts,
        }

    completed_specialists: list[tuple[str, str]] = []
    for agent_id, status in statuses.items():
        if status != "completed" or parents.get(agent_id) is None:
            continue
        agent_metadata = metadata.get(agent_id)
        role = _child_role(agent_id, metadata=agent_metadata, names=names)
        if role in _MAPPER_ROLES:
            continue
        task_text = json.dumps(agent_metadata, ensure_ascii=False).lower()
        completed_specialists.append((str(agent_id), task_text))

    covered_hosts = sorted(
        host
        for host in required_hosts
        if any(
            re.search(
                rf"(?<![a-z0-9.-]){re.escape(host.lower())}(?![a-z0-9.-])",
                task_text,
            )
            for _, task_text in completed_specialists
        )
    )
    missing_hosts = sorted(set(required_hosts) - set(covered_hosts))
    if not missing_hosts:
        return None
    return {
        "error": (
            "Every in-scope alive host must have a completed specialist assignment "
            "before a standard/deep scan can finish. Spawn or replace focused host "
            "coverage agents for the missing hosts, then retry finish_scan."
        ),
        "required_hosts": required_hosts,
        "covered_hosts": covered_hosts,
        "missing_hosts": missing_hosts,
        "completed_specialist_count": len(completed_specialists),
    }


def _do_finish(  # noqa: PLR0911
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    agent_graph: dict[str, Any],
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": (
                "This tool can only be used by the root/main agent. "
                "If you are a subagent, use agent_finish instead"
            ),
        }

    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if not methodology.strip():
        errors.append("Methodology cannot be empty")
    if not technical_analysis.strip():
        errors.append("Technical analysis cannot be empty")
    if not recommendations.strip():
        errors.append("Recommendations cannot be empty")
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    try:
        from strix.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; scan results not persisted")
            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed (not persisted)",
                "warning": "Results could not be persisted - report state unavailable",
            }
        from strix.tools.chaining.tools import chain_review_status

        chain_status = chain_review_status(report_state)
        if not chain_status.get("ready", False):
            return {
                "success": False,
                "error": (
                    "Chain/impact review is incomplete. Review every confirmed finding, "
                    "informational observation, and Thinking hypothesis with "
                    "record_chain_review before "
                    "calling finish_scan."
                ),
                "chain_review": chain_status,
            }
        coverage_summary = _coverage_summary(agent_graph)
        unresolved_surfaces = coverage_summary.get("unresolved_surfaces")
        if isinstance(unresolved_surfaces, list) and unresolved_surfaces:
            return {
                "success": False,
                "error": (
                    "Coverage still contains needs_follow_up surfaces. Continue the "
                    "validation, or update each existing row to reported, "
                    "informational, no_issue_found, ruled_out, or not_applicable "
                    "with concrete evidence before calling finish_scan."
                ),
                "coverage": coverage_summary,
            }
        report_state.update_scan_final_fields(
            executive_summary=executive_summary.strip(),
            methodology=methodology.strip(),
            technical_analysis=technical_analysis.strip(),
            recommendations=recommendations.strip(),
        )
        vuln_count = len(report_state.vulnerability_reports)
    except (ImportError, AttributeError) as e:
        logger.exception("finish_scan persistence failed")
        return {"success": False, "error": f"Failed to complete scan: {e!s}"}
    else:
        logger.info(
            "finish_scan: completed scan with %d vulnerability report(s)",
            vuln_count,
        )
        result: dict[str, Any] = {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": vuln_count,
        }
        result.update(coverage_summary)
        result["chain_review"] = chain_status
        return result


def _coverage_summary(agent_graph: dict[str, Any]) -> dict[str, Any]:
    """Coverage counts, unresolved surfaces, and gaps the runtime can see.

    The gap list is derived from the agent graph rather than from the ledger,
    so it catches the failure the ledger cannot: a risk class an agent was
    equipped for and never accounted for. Surfacing it here — in the response
    to the call that ends the scan — is the last point at which the root agent
    can still dispatch work or record the class as unresolved instead of
    letting the report imply it was clean.
    """
    from strix.report.coverage import agents_from_graph, skill_coverage_gaps
    from strix.tools.coverage.tools import get_coverage_entries, outcome_counts

    entries = get_coverage_entries()
    if not entries:
        return {
            "coverage_recorded": 0,
            "coverage_warning": (
                "No coverage was recorded for this scan. The report cannot show which "
                "surfaces were reviewed and cleared — only what was found. Use "
                "record_coverage during testing so future scans can report negative space."
            ),
        }

    counts = outcome_counts()
    summary: dict[str, Any] = {
        "coverage_recorded": len(entries),
        "coverage_outcomes": counts,
    }
    unresolved = [e for e in entries if e.get("outcome") == "needs_follow_up"]
    if unresolved:
        summary["coverage_warning"] = (
            f"{len(unresolved)} surface(s) closed as 'needs_follow_up' and remain "
            "unresolved. finish_scan will remain blocked until they are validated "
            "or moved to a terminal outcome with evidence."
        )
        summary["unresolved_surfaces"] = [
            {"surface": e.get("surface", ""), "risk_area": e.get("risk_area", "")}
            for e in unresolved
        ]

    gaps = skill_coverage_gaps(entries, agents_from_graph(agent_graph))
    if gaps:
        summary["coverage_gaps"] = [gap["detail"] for gap in gaps]
        summary["coverage_gap_warning"] = (
            f"{len(gaps)} risk class(es) assigned to agents have no coverage entry and "
            "will be published as unexamined. Record them (or a needs_follow_up row) "
            "before the report goes out."
        )
    return summary


@function_tool(timeout=60)
async def finish_scan(  # noqa: PLR0911, PLR0912
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> str:
    """Finalize the scan — persist the customer-facing report.

    **Root-agent only.** Subagents must call ``agent_finish`` from the
    multi-agent graph tools instead. Calling this finalizes everything:

    1. Verifies you are the root agent.
    2. Writes the four narrative sections to the scan record.
    3. Marks the scan completed and stops execution.

    **This is a terminal action, not a status probe.** Whatever you pass
    is persisted VERBATIM as the final, customer-facing report and then
    execution stops. There is no draft mode and no second chance: never
    submit placeholder, provisional, or "checking if done" text in any
    field, and never call ``finish_scan`` to poll whether subagents are
    done (use ``view_agent_graph`` / ``wait_for_agents`` for that).
    Call it exactly ONCE, only when every field holds genuine, finished
    assessment prose.

    **Pre-flight checklist (mandatory — do not skip):**

    1. **Call ``view_agent_graph`` first.** Inspect every entry in the
       summary. If ANY agent is in ``running`` / ``waiting`` state,
       you MUST NOT call ``finish_scan`` yet —
       wrap them up first via ``send_message_to_agent`` (ask them to
       finish), ``wait_for_agents`` (block until their report
       arrives), or ``stop_agent`` (graceful cancel). Only ``completed``
       / ``crashed`` / ``stopped`` agents are safe to leave behind.
       Calling ``finish_scan`` while children are alive orphans their
       work and produces an incomplete report.
    2. It's a good idea to call ``list_reports`` before finishing to
       review every finding filed in this scan (use ``get_report`` for
       full detail on any of them) so your ``executive_summary`` /
       ``technical_analysis`` are grounded in what was actually reported
       — don't invent or omit findings. All vulnerabilities you found are
       filed via ``create_vulnerability_report`` — or, for known-CVE
       dependency findings, ``create_dependency_report`` (un-reported
       findings are not tracked and not credited). A dependency CVE
       already filed via ``create_dependency_report`` counts as reported;
       it does NOT need re-filing here and does NOT block finishing.
    3. Don't double-report — one report per distinct vulnerability.
    4. **Attack-chaining gate.** Call ``record_chain_review`` after reviewing
       every confirmed finding and every ``informational`` coverage entry.
       The runtime rejects ``finish_scan`` until the union of those calls
       covers all required IDs. Consider chaining the findings into
       higher-impact, end-to-end attack paths and test every plausible
       combination. Use ``validated_chain`` or ``impact_upgraded`` when a
       chain is demonstrated, and file/update the affected vulnerability
       report with ``related_report_ids``. Use ``no_chain`` or ``ruled_out``
       with a concrete explanation when no higher-impact path exists. If a
       plausible path cannot be proven, record it with ``record_thinking``
       (label ``Thinking``) and document the validation barrier; do not file
       it as a confirmed vulnerability.
    5. **Coverage reconciliation.** Call ``list_coverage`` and check
       what was actually assessed against the surfaces you enumerated
       during reconnaissance. Every surface you dispatched work on
       should have a coverage entry. Anything still open may be recorded as a
       temporary ``needs_follow_up`` row, but it is not a terminal state:
       dispatch a validator and update the existing row before finishing. If
       a significant surface has no entry at all, dispatch an agent to cover it
       or record it as ``needs_follow_up`` and then resolve it. The runtime
       blocks ``finish_scan`` while unresolved rows remain.
     6. **Mapper delegation gate.** Every live quick, standard, or deep run
        must have a completed recon/source-mapper child before this tool can
        succeed. This keeps even time-boxed quick runs evidence-based.
     7. **Specialist delegation gate.** Standard and deep runs with a real
        target must have a completed non-mapper specialist assignment for
        every in-scope hostname whose service is alive. A single broad child
        does not satisfy this gate unless its task explicitly names every
        required hostname and the child completes.
    8. **Methodology checklist gate.** Every skill-derived methodology class
       must be closed as ``pass``, ``fail``, or ``not_applicable``. ``pass``
       and ``fail`` require a concrete surface and evidence; ``partial``,
       ``blocked``, and ``needs_validation`` are interim states and block
       completion. Use ``checklist_progress`` and ``checklist_list`` to
       reconcile the shared checklist before this call.
    9. **Attack-graph validator gate.** Every generated validator and
       chain-review task must be terminal, and every successful validator must
       have a durable ``record_validation`` record before this call.

    **Calling this multiple times overwrites the previous report.**
    Make the single call comprehensive.

    **Report output rules** (this content may be rendered into generated
    reports):

    - Never mention internal infrastructure: no local/absolute paths
      (``/workspace/...``), no agent names, no sandbox/orchestrator/
      tooling references, no system prompts, no model-internal errors.
      Never leak internal identifiers (proxy request IDs, internal
      vulnerability report IDs, or any system-generated IDs) into any
      field.
    - Tone: formal, third-person, objective, concise. This is a
      consultant deliverable, not an engineering log.
    - Each section has a specific role:

        - ``executive_summary`` — for non-technical leadership. Risk
          posture, business impact (data exposure / compliance /
          reputation), notable criticals, overarching remediation
          theme.
        - ``methodology`` — frameworks followed (OWASP WSTG, PTES,
          OSSTMM, NIST), engagement type (black/gray/white box), scope
          and constraints, categories of testing performed. **No**
          internal execution detail.
        - ``technical_analysis`` — consolidated findings overview with
          severity model and systemic root causes. Reference individual
          vuln reports for repro steps; don't duplicate raw evidence.
        - ``recommendations`` — prioritized actions grouped by urgency
          (Immediate / Short-term / Medium-term), each with concrete
          remediation steps. End with retest/validation guidance.

    - **Formatting — use markdown in every field.** These fields may be
      rendered into generated reports, so structure them clearly: lead
      each section with a short ``# Heading``, use ``**bold**`` for labels/emphasis,
      ``inline code`` for identifiers/paths/parameters, bullet or
      numbered lists for enumerations, and fenced code blocks
      (```` ```language ````) for any code/payload excerpts. Never emit
      one flat wall of prose or leave code unformatted.
    - If **zero** vulnerabilities were found, say so plainly and
      characterize the posture positively; ``technical_analysis`` should
      summarize the areas tested and confirm no issues, and
      ``recommendations`` should focus on general hardening.

    Example (abbreviated — mirror this structure, not the wording)::

        executive_summary:
            # Executive Summary

            An external assessment of the **Acme Customer Portal**
            identified multiple weaknesses that could lead to
            unauthorized access to customer data.

            **Overall risk posture:** Elevated.

            **Key findings**
            - Confirmed SSRF in a URL-preview feature reaching internal
              network ranges.
            - Broken tenant isolation enabling cross-tenant data access.

            **Business impact**
            - Potential exposure of customer records across tenants.

        methodology:
            # Methodology

            Conducted per the **OWASP WSTG**.

            **Engagement type:** Gray-box external test.
            **Scope:** `https://app.acme.example`, `.../api/v1/`.

            **Activities:** recon, authn/session review, authorization
            and tenant-isolation testing, input/SSRF testing.

        technical_analysis:
            # Technical Analysis

            **Severity model** reflects exploitability x impact.

            1. **SSRF in URL preview** (Critical) — insufficient
               destination validation; reaches link-local addresses.
            2. **Broken tenant isolation** (High) — object identifiers
               accepted without ownership checks.

            **Systemic themes:** authorization enforced inconsistently;
            no deny-by-default egress policy.

        recommendations:
            # Recommendations

            **Immediate**
            1. Remediate SSRF: enforce a destination allowlist,
               deny-by-default, re-validate on every redirect hop.

            **Short-term**
            2. Centralize authorization with deny-by-default middleware.

            **Retest & validation:** re-test immediate items to confirm
            SSRF and tenant-isolation controls hold.

    Args:
        executive_summary: Business-level summary for leadership.
        methodology: Frameworks, scope, and approach.
        technical_analysis: Consolidated findings + systemic themes.
        recommendations: Prioritized, actionable remediation.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    parent_id = inner.get("parent_id")
    if coordinator is not None and parent_id is None and me is not None:
        active_agents = await coordinator.active_agents_except(me)
        if active_agents and coordinator.reserve_stopped:
            active_agents = []
    else:
        active_agents = []

    if active_agents:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Cannot finish scan while child agents are still active. "
                    "Wait for completion, send them finish instructions, or stop them first"
                ),
                "active_agents": active_agents,
            },
            ensure_ascii=False,
            default=str,
        )

    graph = await coordinator.snapshot() if coordinator is not None else {}
    mode = str(inner.get("scan_mode") or "").strip().lower()
    target_types = {
        str(value).strip().lower()
        for value in (inner.get("scan_target_types") or [])
        if str(value).strip()
    }
    if (
        mode in {"quick", "standard", "deep"}
        and target_types & _LIVE_TARGET_TYPES
        and not inner.get("recon_finalized")
    ):
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Recon has not been finalized. Complete the mapper, call "
                    "finalize_recon to persist the full inventory into shared memory, "
                    "then continue the assessment."
                ),
            },
            ensure_ascii=False,
        )
    mapper_gate = _mapper_completion_gate(
        scan_mode=mode,
        target_types=inner.get("scan_target_types"),
        agent_graph=graph,
    )
    if mapper_gate is not None:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                **mapper_gate,
            },
            ensure_ascii=False,
            default=str,
        )
    specialist_gate = _specialist_completion_gate(
        scan_mode=str(inner.get("scan_mode") or ""),
        target_types=inner.get("scan_target_types"),
        agent_graph=graph,
    )
    if specialist_gate is not None:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                **specialist_gate,
            },
            ensure_ascii=False,
            default=str,
        )
    host_coverage_gate = _live_host_coverage_gate(
        scan_mode=mode,
        target_types=inner.get("scan_target_types"),
        agent_graph=graph,
        run_dir=(Path(inner["state_dir"]).parent if inner.get("state_dir") else None),
    )
    if host_coverage_gate is not None:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                **host_coverage_gate,
            },
            ensure_ascii=False,
            default=str,
        )

    if inner.get("validation_enabled") and inner.get("attack_graph"):
        graph = inner["attack_graph"]
        if hasattr(graph, "completion_gate"):
            graph_gate = await graph.completion_gate()
            if not graph_gate.get("success"):
                return json.dumps(
                    {
                        "success": False,
                        "scan_completed": False,
                        "error": (
                            "Attack-graph validation is incomplete. Resolve all ready, "
                            "running, blocked, retrying, failed, and unvalidated "
                            "validator/chain tasks before finishing."
                        ),
                        "attack_graph": graph_gate,
                    },
                    ensure_ascii=False,
                    default=str,
                )

    if inner.get("checklist_enabled") and inner.get("state_dir"):
        checklist = checklist_status_for_state_dir(Path(inner["state_dir"]))
        if not checklist.get("complete"):
            return json.dumps(
                {
                    "success": False,
                    "scan_completed": False,
                    "error": (
                        "Methodology checklist is incomplete. Close every item as "
                        "pass, fail, or not_applicable; use partial/blocked/"
                        "needs_validation only while work remains. Every pass/fail "
                        "must include evidence."
                    ),
                    "checklist": checklist,
                },
                ensure_ascii=False,
                default=str,
            )

    result = await asyncio.to_thread(
        _do_finish,
        parent_id=parent_id,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
        agent_graph=graph,
    )
    if (
        result.get("success")
        and result.get("scan_completed")
        and coordinator is not None
        and isinstance(me, str)
    ):
        await coordinator.set_status(me, "completed")
        supervisor = inner.get("supervisor")
        if supervisor is not None:
            with contextlib.suppress(Exception):
                await supervisor.mark_status("completed", reason="finish_scan")
    return json.dumps(result, ensure_ascii=False, default=str)
