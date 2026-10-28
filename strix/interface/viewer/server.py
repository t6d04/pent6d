"""Local HTTP server that serves the viewer SPA and a run's data from disk.

Design notes:
- Uses only the standard library (no new runtime dependency). The workload is
  serving static files plus a handful of JSON reads off disk, so an async stack
  buys nothing here.
- The browser polls the JSON endpoints (~1s) rather than using SSE: a finished
  run stops polling, and short-lived polls survive sleep/network blips without
  server-side connection state, which suits a stdlib ThreadingHTTPServer.
- All reads happen per-request straight from disk, so the same server serves a
  live in-progress run and a finished one identically; the SPA distinguishes
  them via the ``finished`` flag on /api/run.
"""

from __future__ import annotations

import json
import logging
import mimetypes
import os
import secrets
import socket
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import IPv4Network, IPv6Network, ip_address
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from strix.branding import PRODUCT_DISPLAY_NAME
from strix.core.paths import run_record_path
from strix.interface.viewer import auth
from strix.interface.viewer.transcript import (
    build_run_state,
    primary_target,
    read_issues,
    read_report_markdown,
    read_run_summary,
    read_vulnerabilities,
    severity_counts,
)
from strix.report.writer import render_vulnerability_md


if TYPE_CHECKING:
    from collections.abc import Callable


logger = logging.getLogger(__name__)

_ClientNetwork = IPv4Network | IPv6Network


class _NetworkRestrictedThreadingHTTPServer(ThreadingHTTPServer):
    """HTTP server that accepts loopback plus explicitly trusted networks."""

    def __init__(
        self,
        server_address: tuple[str, int],
        request_handler: type[BaseHTTPRequestHandler],
        *,
        allowed_client_networks: tuple[_ClientNetwork, ...],
    ) -> None:
        self.allowed_client_networks = allowed_client_networks
        super().__init__(server_address, request_handler)

    def verify_request(self, request: Any, client_address: tuple[str, int]) -> bool:
        if not super().verify_request(request, client_address):
            return False
        try:
            client = ip_address(client_address[0])
        except ValueError:
            logger.warning(
                "viewer rejected a client with an invalid IP address: %r", client_address[0]
            )
            return False
        return client.is_loopback or any(
            client in network for network in self.allowed_client_networks
        )


def bundle_dir() -> Path:
    """Directory holding the committed, prebuilt SPA (index.html + assets)."""
    return Path(__file__).resolve().parent / "static"


def bundle_is_built() -> bool:
    return (bundle_dir() / "index.html").is_file()


def _iter_run_dirs(base_dir: Path) -> list[Path]:
    """Every run directory under ``base_dir``, newest first by record mtime."""
    if not base_dir.is_dir():
        return []
    run_dirs = [child for child in base_dir.iterdir() if run_record_path(child).is_file()]
    run_dirs.sort(key=lambda child: run_record_path(child).stat().st_mtime, reverse=True)
    return run_dirs


def run_list_entry(run_dir: Path) -> dict[str, Any]:
    """Compact summary of a single run for the history list."""
    record = read_run_summary(run_dir)
    return {
        "name": record.get("run_name") or run_dir.name,
        "target": primary_target(record),
        "scan_mode": record.get("scan_mode"),
        "status": record.get("status"),
        "start_time": record.get("start_time"),
        "end_time": record.get("end_time"),
        "finished": bool(record.get("finished")),
        "project_id": (
            record.get("project_id") if isinstance(record.get("project_id"), str) else None
        ),
        "project_name": (
            record.get("project_name") if isinstance(record.get("project_name"), str) else None
        ),
        "severity_counts": severity_counts(read_vulnerabilities(run_dir)),
    }


def build_runs_payload(base_dir: Path, *, verified: bool) -> dict[str, Any]:
    """The /api/runs payload. Gates the run list behind email verification.

    The count is always advertised so the UI can tease the history, but the
    entries only appear once the viewer is verified.
    """
    run_dirs = _iter_run_dirs(base_dir)
    count = len(run_dirs)
    if not verified:
        return {"locked": True, "count": count, "runs": []}
    return {"locked": False, "count": count, "runs": [run_list_entry(d) for d in run_dirs]}


_WORKFLOW_LANES: tuple[tuple[str, str], ...] = (
    ("scope", "Scope"),
    ("recon", "Recon"),
    ("planning", "Planning"),
    ("execution", "Execution"),
    ("validation", "Validation"),
    ("chain_impact", "Chain / Impact"),
    ("reporting", "Reporting"),
)


def _mcp_config_paths() -> list[Path]:
    """Return global MCP config candidates, newest/most specific first."""

    candidates: list[Path] = []
    configured = os.environ.get("STRIX_MCP_CONFIG")
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend(
        [
            Path.home() / ".strix" / "pent6d-hexstrike-mcp.json",
            Path.home() / ".strix" / "mcp-servers.json",
        ]
    )
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in candidates:
        if path in seen:
            continue
        seen.add(path)
        unique.append(path)
    return unique


def _mcp_config_entries() -> list[dict[str, Any]]:
    """Read the non-secret MCP roster used by Pent6d, independent of a run."""

    for path in _mcp_config_paths():
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        entries = raw.get("servers") if isinstance(raw, dict) else raw
        if not isinstance(entries, list):
            continue
        return [entry for entry in entries if isinstance(entry, dict)]
    return []


def _mcp_endpoint(entry: dict[str, Any]) -> tuple[str, int] | None:
    """Extract a local HTTP endpoint from an MCP entry without exposing it."""

    candidates: list[str] = []
    for key in ("url", "server", "endpoint"):
        value = entry.get(key)
        if isinstance(value, str):
            candidates.append(value)
    args = entry.get("args")
    if isinstance(args, list):
        candidates.extend(str(value) for value in args if isinstance(value, str))
    for value in candidates:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        return parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    return None


def _mcp_endpoint_online(endpoint: tuple[str, int] | None) -> bool:
    if endpoint is None:
        return True  # stdio MCPs are detected from their configured command.
    try:
        with socket.create_connection(endpoint, timeout=0.75):
            return True
    except OSError:
        return False


def read_global_mcp_status() -> dict[str, Any]:
    """Return the global MCP roster, independent of any persisted run."""

    connections: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for entry in _mcp_config_entries():
        name = str(entry.get("name") or entry.get("id") or "").strip()
        if not name or name in seen_names:
            continue
        seen_names.add(name)
        endpoint = _mcp_endpoint(entry)
        connections.append(
            {
                "name": name,
                "provider": (
                    str(entry.get("provider")).strip() or None
                    if entry.get("provider") is not None
                    else None
                ),
                "status": "ready" if _mcp_endpoint_online(endpoint) else "offline",
                "tool_count": (
                    int(entry.get("tool_count"))
                    if isinstance(entry.get("tool_count"), (int, float))
                    else 0
                ),
            }
        )
    return {
        "status": "ready" if connections else "offline",
        "connections": connections,
    }


def _read_state_json(run_dir: Path, filename: str) -> dict[str, Any]:
    path = run_dir / ".state" / filename
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def read_workflow(run_dir: Path) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
    """Project the persisted attack and agent graphs into one lane-oriented graph.

    ``attack_graph.json`` describes planned work while ``agents.json`` describes
    the workers that actually carried it out.  Keeping those as two separate
    graphs made the UI lose the important relationship between a dispatch and
    its evidence.  This projection gives every agent a node and links it to the
    attack task it owns, while preserving dependency/source edges between tasks.
    """

    supervisor = _read_state_json(run_dir, "supervisor.json")
    graph = _read_state_json(run_dir, "attack_graph.json")
    agents_state = _read_state_json(run_dir, "agents.json")
    raw_tasks = graph.get("tasks")
    tasks = raw_tasks if isinstance(raw_tasks, dict) else {}
    lane_ids = {lane_id for lane_id, _ in _WORKFLOW_LANES}

    def lane_for(task: dict[str, Any]) -> str:
        phase = str(task.get("phase") or "execution").strip().lower()
        aliases = {
            "scope_check": "scope",
            "reconnaissance": "recon",
            "discovery": "recon",
            "recon_finalized": "recon",
            "plan": "planning",
            "testing": "execution",
            "validator": "validation",
            "verification": "validation",
            "chain": "chain_impact",
            "impact_review": "chain_impact",
            "impact": "chain_impact",
            "report": "reporting",
        }
        phase = aliases.get(phase, phase)
        return phase if phase in lane_ids else "execution"

    def agent_lane(metadata: dict[str, Any], name: str) -> str:  # noqa: PLR0911
        """Map persisted agent metadata to a visible workflow lane."""
        role = str(metadata.get("role") or "").strip().lower()
        phase = str(metadata.get("phase") or "").strip().lower()
        hint = f"{role} {phase} {name}".replace("_", "-")
        if role in {"recon", "source_mapper"} or any(
            value in hint for value in ("recon", "mapper", "mapping", "discovery")
        ):
            return "recon"
        if role in {"validator", "gap_closer", "verification"} or any(
            value in hint for value in ("validat", "verif", "recovery", "gap-closer")
        ):
            return "validation"
        if role in {"chain", "impact", "chain_reviewer", "impact_reviewer"} or any(
            value in hint for value in ("chain", "impact")
        ):
            return "chain_impact"
        if role in {"report", "reporting"} or any(
            value in hint for value in ("report", "triage")
        ):
            return "reporting"
        if role in {"root", "supervisor"} or any(
            value in name.lower() for value in ("root agent", "supervisor")
        ):
            return "scope"
        if role == "planner":
            return "planning"
        if phase in {"scope", "scope_check", "created"}:
            return "scope"
        if phase in {"planning", "plan"}:
            return "planning"
        if phase in {"validation", "verification"}:
            return "validation"
        if phase in {"impact", "impact_review", "chain"}:
            return "chain_impact"
        if phase in {"report", "reporting"}:
            return "reporting"
        return "execution"

    valid_ids = {str(task_id) for task_id in tasks}
    nodes: list[dict[str, Any]] = []
    for task_id, raw_task in tasks.items():
        if not isinstance(raw_task, dict):
            continue
        node_id = str(task_id)
        dependencies = [
            str(value)
            for value in raw_task.get("dependencies", [])
            if str(value) in valid_ids
        ]
        metadata = raw_task.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        generated_by = metadata.get("generated_by") or metadata.get("parent_task_id")
        source_nodes = metadata.get("source_node_ids")
        if not isinstance(source_nodes, list):
            source_nodes = dependencies
        source_information = metadata.get("source_information")
        if not isinstance(source_information, list):
            source_information = raw_task.get("evidence_ids", [])
        nodes.append(
            {
                "id": node_id,
                "label": str(raw_task.get("title") or node_id),
                "type": str(metadata.get("node_type") or raw_task.get("role") or "task"),
                "role": str(raw_task.get("role") or "specialist"),
                "phase": str(raw_task.get("phase") or "execution"),
                "lane": lane_for(raw_task),
                "status": str(raw_task.get("status") or "pending"),
                "risk": str(raw_task.get("risk") or "low"),
                "dispatch_key": str(raw_task.get("dispatch_key") or ""),
                "dependencies": dependencies,
                "source_nodes": [str(value) for value in source_nodes if str(value) in valid_ids],
                "source_information": [str(value) for value in source_information if str(value)],
                "generated_by": str(generated_by) if generated_by else None,
                "attempts": int(raw_task.get("attempts") or 0),
                "created_at": raw_task.get("created_at"),
                "updated_at": raw_task.get("updated_at"),
                "metadata": metadata,
            }
        )

    # Add the execution graph to the same node set.  Older runs can have no
    # attack graph at all; the agent graph still gives the operator useful
    # visibility into what actually ran.
    statuses = agents_state.get("statuses")
    statuses = statuses if isinstance(statuses, dict) else {}
    parent_of = agents_state.get("parent_of")
    parent_of = parent_of if isinstance(parent_of, dict) else {}
    names = agents_state.get("names")
    names = names if isinstance(names, dict) else {}
    agent_metadata = agents_state.get("metadata")
    agent_metadata = agent_metadata if isinstance(agent_metadata, dict) else {}
    agent_ids = {str(agent_id) for agent_id in statuses}
    for raw_agent_id in statuses:
        agent_id = str(raw_agent_id)
        metadata = agent_metadata.get(raw_agent_id)
        metadata = metadata if isinstance(metadata, dict) else {}
        name = str(names.get(raw_agent_id) or agent_id)
        parent = parent_of.get(raw_agent_id)
        parent = str(parent) if parent in agent_ids else None
        lane = agent_lane(metadata, name)
        nodes.append(
            {
                "id": f"agent:{agent_id}",
                "label": name,
                "type": "agent",
                "role": str(metadata.get("role") or "agent"),
                "phase": str(metadata.get("phase") or "execution"),
                "lane": lane,
                "status": str(statuses.get(raw_agent_id) or "unknown"),
                "risk": str(metadata.get("risk_area") or "medium"),
                "dispatch_key": str(metadata.get("dispatch_key") or ""),
                "dependencies": [f"agent:{parent}"] if parent else [],
                "source_nodes": [f"agent:{parent}"] if parent else [],
                "source_information": (
                    [str(value) for value in metadata.get("evidence_ids", []) if str(value)]
                    if isinstance(metadata.get("evidence_ids"), list)
                    else []
                ),
                "generated_by": f"agent:{parent}" if parent else None,
                "attempts": 0,
                "created_at": None,
                "updated_at": None,
                "metadata": {**metadata, "agent_id": agent_id, "task": metadata.get("task", "")},
            }
        )

    # Findings are the hand-off from testing into impact/reporting.  Including
    # them here makes a provenance chain visible (for example recon agent ->
    # source leak -> hardcoded secret) instead of leaving the final lanes empty.
    finding_nodes: list[dict[str, Any]] = []
    for raw_finding in read_vulnerabilities(run_dir):
        if not isinstance(raw_finding, dict):
            continue
        finding_id = str(raw_finding.get("id") or "").strip()
        if not finding_id:
            continue
        source_agent = str(raw_finding.get("agent_id") or "").strip()
        source_agent_id = f"agent:{source_agent}" if source_agent in agent_ids else None
        evidence = raw_finding.get("evidence")
        evidence_values = (
            [str(value) for value in evidence if str(value)]
            if isinstance(evidence, list)
            else ([str(evidence)] if evidence else [])
        )
        finding_nodes.append(
            {
                "id": f"finding:{finding_id}",
                "label": str(raw_finding.get("title") or finding_id),
                "type": "finding",
                "role": str(raw_finding.get("finding_class") or "finding"),
                "phase": "impact_review",
                "lane": "chain_impact",
                "status": "reported",
                "risk": str(raw_finding.get("severity") or "informational"),
                "dispatch_key": "",
                "dependencies": [source_agent_id] if source_agent_id else [],
                "source_nodes": [source_agent_id] if source_agent_id else [],
                "source_information": evidence_values,
                "generated_by": source_agent_id,
                "attempts": 1,
                "created_at": raw_finding.get("timestamp"),
                "updated_at": raw_finding.get("updated_at"),
                "metadata": raw_finding,
            }
        )
    nodes.extend(finding_nodes)

    chain_reviews: list[dict[str, Any]] = []
    try:
        raw_chain_reviews = json.loads((run_dir / "chain_review.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        raw_chain_reviews = []
    if isinstance(raw_chain_reviews, list):
        chain_reviews = [entry for entry in raw_chain_reviews if isinstance(entry, dict)]
    for index, review in enumerate(chain_reviews):
        outcome = str(review.get("outcome") or "reviewed")
        nodes.append(
            {
                "id": f"chain-review:{index}",
                "label": f"Chain review: {outcome.replace('_', ' ')}",
                "type": "chain_review",
                "role": "chain_reviewer",
                "phase": "impact_review",
                "lane": "chain_impact",
                "status": "completed",
                "risk": "informational",
                "dispatch_key": "",
                "dependencies": [],
                "source_nodes": [],
                "source_information": [str(review.get("analysis") or "")[:500]],
                "generated_by": "workflow",
                "attempts": 1,
                "created_at": None,
                "updated_at": None,
                "metadata": review,
            }
        )

    # A reporting marker gives the last lane a useful state even when no
    # report agent was spawned.  It is deliberately tied to a real run record
    # so small unit-test fixtures and legacy partial directories stay minimal.
    if run_record_path(run_dir).is_file():
        run_status = str(supervisor.get("phase") or supervisor.get("status") or "created")
        terminal = run_status in {"completed", "failed", "stopped", "interrupted", "reporting"}
        nodes.append(
            {
                "id": "stage:reporting",
                "label": "Findings & report",
                "type": "stage",
                "role": "reporting",
                "phase": "reporting",
                "lane": "reporting",
                "status": "completed" if terminal else "pending",
                "risk": "informational",
                "dispatch_key": "",
                "dependencies": [],
                "source_nodes": [],
                "source_information": [],
                "generated_by": "workflow",
                "attempts": 0,
                "created_at": None,
                "updated_at": None,
                "metadata": {"stage": "reporting"},
            }
        )

    node_by_id = {node["id"]: node for node in nodes}

    edges: list[dict[str, str]] = []
    for node in nodes:
        if node["id"].startswith(("agent:", "finding:", "stage:")):
            continue
        edges.extend(
            {
                "id": f"{source}->{node['id']}",
                "source": source,
                "target": node["id"],
                "type": "dependency",
            }
            for source in node["dependencies"]
        )
        edges.extend(
            {
                "id": f"{source}=>{node['id']}",
                "source": source,
                "target": node["id"],
                "type": "source",
            }
            for source in node["source_nodes"]
            if source not in node["dependencies"]
        )

    # Parent/child agent edges and ownership edges make the provenance visible
    # even when a task was created by a legacy caller without explicit source
    # node metadata.
    edge_ids = {edge["id"] for edge in edges}
    for node in nodes:
        if not node["id"].startswith("agent:"):
            continue
        for source in node["dependencies"]:
            edge = {
                "id": f"{source}->{node['id']}",
                "source": source,
                "target": node["id"],
                "type": "agent",
            }
            if source in node_by_id and edge["id"] not in edge_ids:
                edges.append(edge)
                edge_ids.add(edge["id"])

    for task_id, raw_task in tasks.items():
        if not isinstance(raw_task, dict):
            continue
        metadata = raw_task.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        owner = metadata.get("agent_id") or metadata.get("owner_agent_id")
        owner_id = f"agent:{owner}" if str(owner) in agent_ids else None
        if owner_id and str(task_id) in node_by_id:
            edge = {
                "id": f"{owner_id}=>{task_id}",
                "source": owner_id,
                "target": str(task_id),
                "type": "assignment",
            }
            if edge["id"] not in edge_ids:
                edges.append(edge)
                edge_ids.add(edge["id"])

    reporting_node = node_by_id.get("stage:reporting")
    for finding in finding_nodes:
        for source in finding["dependencies"]:
            edge = {
                "id": f"{source}=>{finding['id']}",
                "source": source,
                "target": finding["id"],
                "type": "impact",
            }
            if source in node_by_id and edge["id"] not in edge_ids:
                edges.append(edge)
                edge_ids.add(edge["id"])
    for index, review in enumerate(chain_reviews):
        chain_node_id = f"chain-review:{index}"
        reviewed_report_ids = review.get("reviewed_report_ids")
        if not isinstance(reviewed_report_ids, list):
            continue
        for report_id in reviewed_report_ids:
            source = f"finding:{report_id}"
            edge = {
                "id": f"{source}=>{chain_node_id}",
                "source": source,
                "target": chain_node_id,
                "type": "chain",
            }
            if source in node_by_id and edge["id"] not in edge_ids:
                edges.append(edge)
                edge_ids.add(edge["id"])
    if reporting_node:
        for finding in finding_nodes:
            edge = {
                "id": f"{finding['id']}=>stage:reporting",
                "source": finding["id"],
                "target": "stage:reporting",
                "type": "report",
            }
            if edge["id"] not in edge_ids:
                edges.append(edge)
                edge_ids.add(edge["id"])

    current_phase = str(supervisor.get("phase") or "created")
    active_lane = {
        "created": "scope",
        "scope_check": "scope",
        "sandbox_init": "scope",
        "agent_setup": "scope",
        "agent_loop": "execution",
        "recon_finalized": "planning",
        "plan": "planning",
        "completed": "reporting",
        "failed": "reporting",
        "stopped": "reporting",
        "interrupted": "reporting",
    }.get(current_phase, current_phase)
    # Do not render empty columns.  This keeps the graph focused on the stages
    # that contain real agents/tasks while preserving the canonical lane order.
    populated_lane_ids = {node["lane"] for node in nodes}
    lanes = [
        {
            "id": lane_id,
            "label": label,
            "order": index,
            "active": lane_id == active_lane,
            "node_count": sum(1 for node in nodes if node["lane"] == lane_id),
        }
        for index, (lane_id, label) in enumerate(_WORKFLOW_LANES)
        if lane_id in populated_lane_ids
    ]
    return {
        "schema_version": 1,
        "status": str(supervisor.get("status") or "unknown"),
        "phase": current_phase,
        "recon_finalized": (run_dir / "recon_complete.json").is_file(),
        "lanes": lanes,
        "nodes": nodes,
        "edges": edges,
    }


def resolve_run_dir(base_dir: Path, run_param: str | None, default_run_dir: Path) -> Path | None:
    """Resolve a ``?run=`` value to a real run directory under ``base_dir``.

    Returns ``default_run_dir`` when no run is requested. Rejects traversal and
    unknown runs (returns None) so the caller can answer 404.
    """
    if not run_param:
        return default_run_dir
    base = base_dir.resolve()
    candidate = (base / run_param).resolve()
    # The web UI normally sends the directory name. Keep that fast path
    # strict: only direct children with a run record are valid.
    if candidate.parent == base and run_record_path(candidate).is_file():
        return candidate

    # Older/project-migrated records can expose a persisted ``run_name`` or
    # ``run_id`` that differs from the physical directory name. Resolve those
    # by exact record equality, never by a glob or a path supplied by the
    # caller. This fixes legitimate history/recon requests without weakening
    # traversal isolation.
    for child in _iter_run_dirs(base):
        try:
            record = read_run_summary(child)
        except (OSError, ValueError, TypeError):
            continue
        if run_param in {record.get("run_name"), record.get("run_id")}:
            return child
    return None


# Prefix of the cookie carrying the per-process session capability. The bound
# port is appended (``strix_viewer_session_<port>``) because browsers scope
# cookies by host only, never by port: concurrent viewers on 127.0.0.1 would
# otherwise share one cookie slot and clobber each other's session.
SESSION_COOKIE_PREFIX = "strix_viewer_session"


class _ViewerState:
    def __init__(
        self,
        run_dir: Path,
        assets_dir: Path,
        steer_handler: Callable[[str, str], bool] | None = None,
        web_state_handler: Callable[[], dict[str, Any]] | None = None,
        web_command_handler: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        run_dir_provider: Callable[[], Path | None] | None = None,
        runs_base_dir_provider: Callable[[], Path] | None = None,
    ) -> None:
        self.run_dir = run_dir
        self.assets_dir = assets_dir
        # The strix_runs directory that holds the launched run; used to
        # enumerate and resolve other runs for the history list.
        self.base_dir = run_dir.parent
        # Set only when the viewer runs inside a live scan process (the TUI
        # launcher), which can deliver a message to a running agent. Absent for
        # standalone ``strix view`` / finished runs, so steering is unavailable.
        self.steer_handler = steer_handler
        # ``strix web`` starts before a run exists. These callbacks expose a
        # local control plane without making the report-only viewer responsible
        # for scan orchestration.
        self.web_state_handler = web_state_handler
        self.web_command_handler = web_command_handler
        self.run_dir_provider = run_dir_provider
        self.runs_base_dir_provider = runs_base_dir_provider
        # Unguessable per-process capability. It is minted here, printed/opened
        # for the operator who started the server (see ``authorized_url``), and
        # exchanged for a session cookie only when presented on the initial page
        # load. It is the request-level authorization the review asked for:
        # reachability of the port (e.g. when bound with ``--host``) is not
        # enough to read run data, steer a live scan, trigger a report, or
        # browse history -- the token is never handed to a caller who merely
        # reaches ``/``.
        self.session_token = secrets.token_urlsafe(32)
        # Finalized in ``serve()`` once the port is known (the server binds
        # after this state is constructed); see SESSION_COOKIE_PREFIX.
        self.cookie_name = SESSION_COOKIE_PREFIX

    def current_run_dir(self) -> Path | None:
        if self.run_dir_provider is not None:
            return self.run_dir_provider()
        return self.run_dir

    def current_runs_base_dir(self) -> Path:
        if self.runs_base_dir_provider is not None:
            return self.runs_base_dir_provider()
        return self.base_dir


def _make_handler(state: _ViewerState) -> type[BaseHTTPRequestHandler]:
    class ViewerHandler(BaseHTTPRequestHandler):
        server_version = f"{PRODUCT_DISPLAY_NAME}Viewer/1.0"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            logger.debug("viewer %s - %s", self.address_string(), format % args)

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            path = parts.path
            try:
                if path.startswith("/api/"):
                    self._handle_api(path, parse_qs(parts.query))
                else:
                    self._handle_static(path, parse_qs(parts.query))
            except BrokenPipeError:
                # The browser closed the connection mid-response (e.g. it
                # navigated away between polls). Not an error.
                logger.debug("viewer client disconnected during %s", path)
            except Exception:
                # A bad request must never kill the worker thread.
                logger.exception("viewer request failed: %s", path)
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            try:
                if path == "/api/event":
                    self._handle_event()
                elif path == "/api/auth/otp/start":
                    self._handle_otp_start()
                elif path == "/api/auth/otp/verify":
                    self._handle_otp_verify()
                elif path == "/api/auth/forget":
                    self._handle_forget()
                elif path == "/api/report/send":
                    self._handle_report_send()
                elif path == "/api/agents/steer":
                    self._handle_steer()
                elif path == "/api/web/command":
                    self._handle_web_command()
                else:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})
            except BrokenPipeError:
                logger.debug("viewer client disconnected during POST %s", path)
            except Exception:
                # A bad request must never kill the worker thread.
                logger.exception("viewer request failed: POST %s", path)
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

        def _read_body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw or b"{}")
            except json.JSONDecodeError:
                return {}
            return body if isinstance(body, dict) else {}

        # Funnel events the viewer is allowed to forward. This handler is the
        # trust boundary: only these event names, with only their known props,
        # ever reach PostHog. Everything else (including any PII) is dropped.
        _EMAIL_EVENTS = frozenset(
            {"email_submitted", "email_verified", "report_sent", "work_email_required"}
        )

        def _handle_event(self) -> None:
            body = self._read_body()
            # Forwarded as anonymous PostHog events that respect the global
            # telemetry opt-out. Never forward the email, code, or report body:
            # only the whitelisted event names and their known props are passed.
            event = body.get("event")
            if event == "cta_clicked":
                from strix.telemetry import posthog

                cta = str(body.get("cta") or "unknown")
                surface = body.get("surface")
                posthog.viewer_cta_clicked(cta, surface=str(surface) if surface else None)
            elif event in self._EMAIL_EVENTS:
                from strix.telemetry import posthog

                purpose = body.get("purpose")
                posthog.viewer_email_event(str(event), purpose=str(purpose) if purpose else None)
            elif event == "agent_steered":
                from strix.telemetry import posthog

                posthog.viewer_agent_steered()
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()

        def _handle_pre_run_api(self, path: str) -> bool:
            """Handle API routes that do not require an active run."""
            if path == "/api/web/state":
                if not self._has_session():
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                elif state.web_state_handler is None:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "web_unavailable"})
                else:
                    self._send_json(HTTPStatus.OK, state.web_state_handler())
                return True
            # Local history is available to the browser holding this process's
            # session capability. Merely reaching an exposed --host port still
            # does not reveal run names or metadata.
            if path == "/api/runs":
                unlocked = self._has_session()
                payload = build_runs_payload(state.current_runs_base_dir(), verified=unlocked)
                self._send_json(HTTPStatus.OK, payload)
                return True
            if path == "/api/capabilities":
                # Steering is only possible when the viewer shares a live scan's
                # coordinator + event loop (the TUI launcher wires a handler).
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "can_steer": state.steer_handler is not None,
                        "can_web_control": state.web_command_handler is not None,
                    },
                )
                return True
            if path == "/api/mcp/status":
                if not self._has_session():
                    self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                else:
                    self._send_json(HTTPStatus.OK, read_global_mcp_status())
                return True
            if path == "/api/auth/status":
                self._handle_auth_status()
                return True
            return False

        def _handle_api(self, path: str, query: dict[str, list[str]]) -> None:  # noqa: PLR0912
            if self._handle_pre_run_api(path):
                return

            # All remaining GET endpoints expose run metadata or scan output.
            # Require the capability even for the run used to launch the viewer;
            # reachability of an exposed --host port must not grant data access.
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return

            default_run_dir = state.current_run_dir()
            if default_run_dir is None:
                self._send_json(HTTPStatus.CONFLICT, {"error": "run_not_started"})
                return

            run_values = query.get("run")
            run_param = run_values[0] if run_values else None
            run_dir = resolve_run_dir(state.current_runs_base_dir(), run_param, default_run_dir)
            if run_dir is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown run"})
                return

            if path == "/api/run":
                self._send_json(HTTPStatus.OK, read_run_summary(run_dir))
            elif path == "/api/issues":
                self._send_json(HTTPStatus.OK, read_issues(run_dir))
            elif path == "/api/vulnerabilities":
                self._send_json(HTTPStatus.OK, read_vulnerabilities(run_dir))
            elif path == "/api/report":
                self._send_json(HTTPStatus.OK, {"markdown": read_report_markdown(run_dir)})
            elif path == "/api/export/overview":
                self._handle_overview_export(run_dir, query)
            elif path == "/api/export/finding":
                self._handle_finding_export(run_dir, query)
            elif path == "/api/transcript":
                self._send_json(HTTPStatus.OK, build_run_state(run_dir))
            elif path == "/api/workflow":
                self._send_json(HTTPStatus.OK, read_workflow(run_dir))
            elif path == "/api/recon":
                from strix.tools.recon.tools import read_recon

                self._send_json(HTTPStatus.OK, read_recon(run_dir))
            elif path == "/api/recon/screenshot":
                self._handle_recon_screenshot(run_dir, query)
            else:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown endpoint"})

        def _handle_recon_screenshot(self, run_dir: Path, query: dict[str, list[str]]) -> None:
            import re

            name = self._query_value(query, "name") or ""
            if not re.fullmatch(r"[a-f0-9]{64}\.(png|jpg)", name):
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown screenshot"})
                return
            root = (run_dir / "recon_screenshots").resolve()
            path = root / name
            if path.resolve().parent != root or not path.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown screenshot"})
                return
            payload = path.read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "image/png" if name.endswith(".png") else "image/jpeg")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        @staticmethod
        def _query_value(query: dict[str, list[str]], key: str) -> str | None:
            values = query.get(key)
            return values[0] if values else None

        @staticmethod
        def _download_name(value: str, *, fallback: str) -> str:
            """Return an ASCII-safe attachment name, never client-controlled."""
            clean = "".join(
                char if char.isascii() and (char.isalnum() or char in ".-_") else "_"
                for char in value
            ).strip("._")
            return clean[:120] or fallback

        def _send_download(self, payload: bytes, *, content_type: str, filename: str) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _handle_overview_export(self, run_dir: Path, query: dict[str, list[str]]) -> None:
            export_format = self._query_value(query, "format")
            run_name = self._download_name(run_dir.name, fallback="run")
            if export_format == "md":
                markdown = read_report_markdown(run_dir)
                if not markdown:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "report_unavailable"})
                    return
                self._send_download(
                    markdown.encode("utf-8"),
                    content_type="text/markdown; charset=utf-8",
                    filename=f"pent6d-overview-{run_name}.md",
                )
                return
            if export_format == "pdf":
                from strix.interface.viewer.report_pdf import generate_report_pdf

                self._send_download(
                    generate_report_pdf(run_dir),
                    content_type="application/pdf",
                    filename=f"pent6d-overview-{run_name}.pdf",
                )
                return
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_export_format"})

        def _handle_finding_export(self, run_dir: Path, query: dict[str, list[str]]) -> None:
            finding_id = self._query_value(query, "finding")
            export_format = self._query_value(query, "format")
            finding = next(
                (
                    report
                    for report in read_issues(run_dir)
                    if isinstance(report, dict) and report.get("id") == finding_id
                ),
                None,
            )
            if finding is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown_finding"})
                return
            safe_id = self._download_name(str(finding.get("id") or "finding"), fallback="finding")
            if export_format == "md":
                self._send_download(
                    render_vulnerability_md(finding).encode("utf-8"),
                    content_type="text/markdown; charset=utf-8",
                    filename=f"pent6d-finding-{safe_id}.md",
                )
                return
            if export_format == "pdf":
                from strix.interface.viewer.report_pdf import generate_finding_pdf

                self._send_download(
                    generate_finding_pdf(run_dir, str(finding["id"])),
                    content_type="application/pdf",
                    filename=f"pent6d-finding-{safe_id}.pdf",
                )
                return
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_export_format"})

        def _handle_auth_status(self) -> None:
            # The cached verified email is only disclosed to a caller holding this
            # process's session capability, so a cookie-less client on an exposed
            # --host port cannot read it; everyone else looks unverified.
            # Verification is reported through is_verified() so an expired record
            # is advertised as unverified -- otherwise the SPA would suppress
            # re-verification while history stays locked, stranding the user.
            if not self._has_session():
                self._send_json(HTTPStatus.OK, {"verified": False, "email": None})
                return
            record = auth.read_auth()
            self._send_json(
                HTTPStatus.OK,
                {
                    "verified": auth.is_verified(),
                    "email": record.get("email") if record else None,
                },
            )

        def _handle_otp_start(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            email = str(self._read_body().get("email") or "").strip()
            if not email:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_email"})
                return
            try:
                auth.otp_start(email)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            self._send_json(HTTPStatus.OK, {"ok": True})

        def _handle_otp_verify(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            body = self._read_body()
            email = str(body.get("email") or "").strip()
            code = str(body.get("code") or "").strip()
            if not email or not code:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_code"})
                return
            try:
                result = auth.otp_verify(email, code)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            auth.write_auth(
                email=result.get("email") or email,
                token=result["token"],
                verified_at=result.get("expires_at") or "",
            )
            verified_email = result.get("email") or email
            self._send_json(HTTPStatus.OK, {"verified": True, "email": verified_email})

        def _handle_forget(self) -> None:
            # Clearing the cached verification is a state change, so it requires
            # this process's session capability: a cookie-less caller on an
            # exposed --host port must not be able to log the operator out.
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            auth.forget()
            self._send_json(HTTPStatus.OK, {"ok": True})

        def _handle_report_send(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            record = auth.read_auth()
            if record is None:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "unverified"})
                return
            run_param = str(self._read_body().get("run") or "") or None
            run_dir = resolve_run_dir(
                state.current_runs_base_dir(), run_param, state.current_run_dir() or state.run_dir
            )
            if run_dir is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "unknown run"})
                return

            summary = read_run_summary(run_dir)
            # Emailing only makes sense for a completed run; a live scan would
            # send a partial report. The UI hides the entry point, but fail
            # closed here too so the endpoint can't be driven mid-scan.
            if not summary.get("finished", False):
                self._send_json(HTTPStatus.CONFLICT, {"error": "run_not_finished"})
                return

            from strix.interface.viewer.report_pdf import build_encrypted_report

            pdf_bytes, password, filename = build_encrypted_report(run_dir)
            run_name = str(summary.get("run_name") or run_dir.name)
            target = primary_target(summary) or "unknown target"
            try:
                # The password is intentionally NOT passed here; only the
                # encrypted PDF bytes reach the relay.
                auth.report_send(record["token"], pdf_bytes, filename, run_name, target)
            except auth.RelayError as exc:
                self._send_relay_error(exc)
                return
            # The password is returned only to a session-authorized browser.
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "password": password, "filename": filename},
            )

        # Cap on a steering message so a runaway client cannot flood the agent.
        _STEER_MESSAGE_MAX = 4000

        def _handle_steer(self) -> None:
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            body = self._read_body()
            agent_id = body.get("agent_id")
            message = body.get("message")
            if not isinstance(agent_id, str) or not agent_id.strip():
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_agent_id"})
                return
            if (
                not isinstance(message, str)
                or not message.strip()
                or len(message) > self._STEER_MESSAGE_MAX
            ):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_message"})
                return
            if state.steer_handler is None:
                # Standalone / finished-run viewing has no live scan to steer.
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "steering_unavailable"})
                return
            delivered = state.steer_handler(agent_id, message)
            if delivered:
                self._send_json(HTTPStatus.OK, {"ok": True})
            else:
                self._send_json(HTTPStatus.OK, {"ok": False, "error": "not_delivered"})

        def _handle_web_command(self) -> None:
            """Dispatch a capability-authorized local-web controller command."""
            if not self._has_session():
                self._send_json(HTTPStatus.FORBIDDEN, {"error": "forbidden"})
                return
            if state.web_command_handler is None:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "web_unavailable"})
                return
            body = self._read_body()
            command = body.get("command")
            payload = body.get("payload", {})
            if not isinstance(command, str) or not command or len(command) > 128:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_command"})
                return
            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_payload"})
                return
            try:
                result = state.web_command_handler(command, payload)
            except (TypeError, ValueError, RuntimeError) as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "result": result})

        def _send_relay_error(self, exc: auth.RelayError) -> None:
            status_by_code = {
                "rate_limited": HTTPStatus.TOO_MANY_REQUESTS,
                "invalid_email": HTTPStatus.BAD_REQUEST,
                "invalid_message": HTTPStatus.BAD_REQUEST,
                "work_email_required": HTTPStatus.BAD_REQUEST,
                "invalid_code": HTTPStatus.FORBIDDEN,
                "reverify": HTTPStatus.UNAUTHORIZED,
                "forbidden": HTTPStatus.FORBIDDEN,
                "too_large": HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "unavailable": HTTPStatus.BAD_GATEWAY,
            }
            status = status_by_code.get(exc.code, HTTPStatus.BAD_GATEWAY)
            self._send_json(status, {"error": exc.code})

        def _cookies(self) -> dict[str, str]:
            jar: dict[str, str] = {}
            for chunk in (self.headers.get("Cookie") or "").split(";"):
                name, sep, value = chunk.strip().partition("=")
                if sep:
                    jar[name] = value
            return jar

        def _has_session(self) -> bool:
            """True when the request carries this process's session capability.

            The cookie is set only when the SPA is served (index.html), so only
            the browser this process handed the page to can pass. A direct
            caller on an exposed port has no cookie and is rejected.
            """
            supplied = self._cookies().get(state.cookie_name, "")
            return bool(supplied) and secrets.compare_digest(supplied, state.session_token)

        def _token_presented(self, query: dict[str, list[str]]) -> bool:
            """True when the request carries the correct bootstrap token.

            The token reaches the operator's browser through the URL printed /
            opened by the process that started the server, a channel an
            arbitrary network caller on an exposed port cannot observe.
            """
            supplied = (query.get("token") or [""])[0]
            return bool(supplied) and secrets.compare_digest(supplied, state.session_token)

        def _handle_static(self, path: str, query: dict[str, list[str]]) -> None:
            target = self._resolve_asset(path)
            if target is None:
                # SPA fallback: unknown non-asset routes render index.html so
                # client-side deep links work.
                target = state.assets_dir / "index.html"
            is_index = target.name == "index.html"
            if not target.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            content = target.read_bytes()
            content_type, _ = mimetypes.guess_type(str(target))
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type or "application/octet-stream")
            self.send_header("Content-Length", str(len(content)))
            if is_index and self._token_presented(query):
                # Exchange the bootstrap token for the per-process session
                # capability. Issued only when the correct token is presented,
                # so a caller who merely reaches ``/`` never obtains it.
                # HttpOnly (JS never needs it; fetch sends it automatically) and
                # SameSite=Strict (never sent from a cross-site context).
                self.send_header(
                    "Set-Cookie",
                    f"{state.cookie_name}={state.session_token}; Path=/; HttpOnly; SameSite=Strict",
                )
            self.end_headers()
            self.wfile.write(content)

        def _resolve_asset(self, path: str) -> Path | None:
            rel = unquote(path).lstrip("/")
            if not rel or rel.endswith("/"):
                return None
            root = state.assets_dir.resolve()
            candidate = (root / rel).resolve()
            # Path-traversal guard: never serve outside the bundle root.
            if root != candidate and root not in candidate.parents:
                logger.warning("viewer rejected traversal attempt: %s", path)
                return None
            return candidate if candidate.is_file() else None

        def _send_json(self, status: HTTPStatus, payload: Any) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ViewerHandler


def authorized_url(base_url: str, token: str) -> str:
    """URL that bootstraps the viewer session for the operator.

    Presenting ``token`` on the initial page load is what mints the session
    cookie, so this URL is printed / opened only for the operator who started
    the server. Sharing it (rather than the bare ``base_url``) is what lets a
    trusted remote user authorize when the viewer is exposed with ``--host``.
    """
    return f"{base_url}/?{urlencode({'token': token})}"


def serve(
    run_dir: Path,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    open_browser: bool = True,
    steer_handler: Callable[[str, str], bool] | None = None,
    web_state_handler: Callable[[], dict[str, Any]] | None = None,
    web_command_handler: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    run_dir_provider: Callable[[], Path | None] | None = None,
    runs_base_dir_provider: Callable[[], Path] | None = None,
    allowed_client_networks: tuple[_ClientNetwork, ...] | None = None,
) -> tuple[ThreadingHTTPServer, str, str]:
    """Start the viewer server on a background thread; return (server, url, token).

    ``url`` is the bare base; pass it through ``authorized_url(url, token)`` to
    build the operator link that authorizes the browser.

    Binds an ephemeral port by default. If a fixed ``port`` is requested but in
    use, falls back to an ephemeral port. Reused by both the ``strix view``
    command and the in-TUI launcher; callers own the server's lifetime.

    ``steer_handler`` is supplied only by the in-TUI launcher, which runs inside
    the live scan process and can forward a message to a running agent. Left
    ``None`` (standalone ``strix view``), steering is reported unavailable.

    ``allowed_client_networks`` restricts remote clients at the TCP server;
    loopback is always retained for the operator on the host.
    """
    assets_dir = bundle_dir()
    state = _ViewerState(
        run_dir=run_dir,
        assets_dir=assets_dir,
        steer_handler=steer_handler,
        web_state_handler=web_state_handler,
        web_command_handler=web_command_handler,
        run_dir_provider=run_dir_provider,
        runs_base_dir_provider=runs_base_dir_provider,
    )
    handler = _make_handler(state)

    def create_server(bound_port: int) -> ThreadingHTTPServer:
        if allowed_client_networks is not None:
            return _NetworkRestrictedThreadingHTTPServer(
                (host, bound_port),
                handler,
                allowed_client_networks=allowed_client_networks,
            )
        return ThreadingHTTPServer((host, bound_port), handler)

    try:
        httpd = create_server(port)
    except OSError:
        if port == 0:
            raise
        logger.info("viewer port %s unavailable, falling back to an ephemeral port", port)
        httpd = create_server(0)

    httpd.daemon_threads = True
    bound_port = int(httpd.server_address[1])
    state.cookie_name = f"{SESSION_COOKIE_PREFIX}_{bound_port}"
    url = f"http://{host}:{bound_port}"

    thread = threading.Thread(target=httpd.serve_forever, name="strix-viewer", daemon=True)
    thread.start()

    if open_browser:
        _open_browser(authorized_url(url, state.session_token))

    return httpd, url, state.session_token


def _open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:  # noqa: BLE001 - launching the browser is best-effort
        logger.debug("could not open browser for %s", url, exc_info=True)


__all__ = ["authorized_url", "bundle_dir", "bundle_is_built", "serve"]
