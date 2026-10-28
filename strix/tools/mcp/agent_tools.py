"""The generic MCP discovery and dispatch tools every agent carries.

Under the generic-dispatch model an agent does not get one tool per MCP tool.
It gets four primary tools and discovers connections on demand:

- ``list_mcps()`` returns the connections available this run — each connection's
  id, name, description, and tool count, with no tool schemas — so the model can
  discover what it can reach without any inventory in the system prompt.
- ``search_mcp_tools(connection, query)`` returns a small ranked candidate set.
- ``get_mcp_tool_schema(connection, tool)`` returns one exact input schema.
- ``call_mcp(connection, tool, arguments)`` dispatches one call to a
  connection's tool and returns its result.

``describe_mcp`` remains as a compatibility path for older prompts, but current
agents use targeted search and one-schema lookup instead of receiving a whole
provider catalog in one model turn.

Successful dispatches also write a bounded, redacted evidence excerpt to the
run's shared memory. This keeps scanner output available to later agents
without replaying the full MCP transcript or copying credentials.

All four read the per-run :class:`~strix.tools.mcp.registry.McpRegistry` from the
run context under :data:`~strix.tools.mcp.registry.MCP_REGISTRY_CONTEXT_KEY`. They
are ordinary ``FunctionTool`` objects placed in the agent factory's base tool set,
so the factory's output-bounding and disk-spill wrapping apply to their results
automatically.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from strix.tools.mcp.client import _errored_tool_output
from strix.tools.mcp.naming import namespaced_tool_name
from strix.tools.mcp.registry import MCP_REGISTRY_CONTEXT_KEY, McpRegistry
from strix.tools.mcp.session import McpConnectionUnavailableError
from strix.tools.shared_memory.tools import _remember


if TYPE_CHECKING:
    from mcp.types import Tool as MCPTool


logger = logging.getLogger(__name__)


def _registry_from_ctx(ctx: RunContextWrapper) -> McpRegistry | None:
    context = ctx.context if isinstance(ctx.context, dict) else {}
    registry = context.get(MCP_REGISTRY_CONTEXT_KEY)
    return registry if isinstance(registry, McpRegistry) else None


_NO_CONNECTIONS = "No MCP connections are configured for this run."


def _unknown_connection(connection: str, registry: McpRegistry) -> str:
    available = ", ".join(registry.names()) or "(none)"
    return f"Unknown MCP connection {connection!r}. Available connections: {available}."


_SECRET_KEY_RE = re.compile(r"(?i)(token|secret|password|passwd|cookie|authorization|api[_-]?key)")


def _redact_mcp_value(value: Any) -> Any:
    """Keep MCP evidence useful without copying credentials into memory."""

    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if _SECRET_KEY_RE.search(str(key)) else _redact_mcp_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_mcp_value(item) for item in value[:100]]
    if isinstance(value, str):
        text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._-]+", r"\1[REDACTED]", value)
        return text[:12_000]
    return value


async def _persist_mcp_result(
    ctx: RunContextWrapper,
    *,
    connection: str,
    tool: str,
    result: Any,
) -> None:
    """Write a bounded MCP evidence excerpt to this run's shared memory."""

    context = ctx.context if isinstance(ctx.context, dict) else {}
    raw_state_dir = context.get("state_dir")
    if not raw_state_dir:
        return
    try:
        payload = json.dumps(
            _redact_mcp_value(result), ensure_ascii=False, sort_keys=True, default=str
        )
    except (TypeError, ValueError):
        payload = str(_redact_mcp_value(result))
    if not payload.strip():
        return
    agent_id = context.get("agent_id")
    agent_id = agent_id if isinstance(agent_id, str) else None
    agent_name = None
    coordinator = context.get("coordinator")
    names = getattr(coordinator, "names", {})
    if agent_id and isinstance(names, dict) and isinstance(names.get(agent_id), str):
        agent_name = names[agent_id]
    tags = ["mcp", tool]
    if connection.strip().lower() == "hexstrike":
        tags.append("hexstrike")
    await asyncio.to_thread(
        _remember,
        Path(raw_state_dir) / "shared_memory.db",
        title=f"MCP evidence: {connection}/{tool}",
        content=payload[:20_000],
        kind="evidence",
        tags=tags,
        source=f"mcp://{connection}/{tool}",
        confidence="observed",
        agent_id=agent_id,
        agent_name=agent_name,
        metadata={"connection": connection, "tool": tool, "result_type": type(result).__name__},
    )


def _format_tool(tool: MCPTool) -> str:
    schema = json.dumps(tool.inputSchema or {"type": "object"}, indent=2, ensure_ascii=False)
    description = (tool.description or "").strip() or "(no description)"
    return f"- {tool.name}: {description}\n  input schema:\n{schema}"


@function_tool(timeout=60)
async def list_mcps(ctx: RunContextWrapper) -> dict[str, Any]:
    """List the MCP connections available this run, so you can discover them.

    Read-only. Returns one entry per connection with its ``id`` (the exact name
    you pass to the other MCP tools), ``name``, ``description``, and
    ``tool_count``. The response does not include tool schemas. Call
    ``search_mcp_tools`` next. Then call ``get_mcp_tool_schema`` for one selected
    tool before you call ``call_mcp``. Returns an empty ``connections`` list when
    the run has no MCP connections.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return {"connections": []}
    dead_by_name = {status.name: status.dead for status in registry.statuses()}
    return {
        "connections": [
            {
                "id": summary.name,
                "name": summary.name,
                "description": summary.purpose,
                "tool_count": summary.tool_count,
                "dead": dead_by_name.get(summary.name, False),
                "state": summary.state,
            }
            for summary in registry.summaries()
        ]
    }


@function_tool(timeout=60)
async def describe_mcp(ctx: RunContextWrapper, connection: str) -> str:
    """Return one connection's full tool catalog as a compatibility fallback.

    Read-only. This result can be large because it includes every tool schema.
    First use ``search_mcp_tools`` and ``get_mcp_tool_schema``. Use this fallback
    only when targeted search cannot identify an expected tool. Nothing is read
    from the connected account.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    try:
        tools = await entry.ensure_catalog()
    except McpConnectionUnavailableError as exc:
        return str(exc)
    if not tools:
        return f"MCP connection {connection!r} offers no tools."
    header = f"MCP connection {connection!r} offers {len(tools)} tool(s):"
    body = "\n".join(_format_tool(tool) for tool in tools)
    return f"{header}\n{body}"


def _search_score(tool: MCPTool, query_terms: list[str], active: bool) -> tuple[int, str]:
    name = tool.name.lower()
    description = (tool.description or "").lower()
    if not query_terms:
        return (100 if active else 0, name)
    score = 100 if active else 0
    matched_terms = 0
    for term in query_terms:
        if name == term:
            score += 60
            matched_terms += 1
        elif name.startswith(term):
            score += 35
            matched_terms += 1
        elif term in name:
            score += 25
            matched_terms += 1
        elif term in description:
            score += 10
            matched_terms += 1
    if matched_terms == 0:
        return (-1, name)
    return (score + (matched_terms * 5), name)


@function_tool(timeout=60)
async def search_mcp_tools(
    ctx: RunContextWrapper,
    connection: str,
    query: str,
    limit: int = 8,
) -> dict[str, Any] | str:
    """Search one connection's tools without returning their full schemas.

    The first search lazily connects the provider and caches its catalog. Results
    contain only names, short descriptions, and whether each tool is in the
    scan's active set. Call ``get_mcp_tool_schema`` for the selected tool.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
        query: Capability words such as ``page content`` or ``workspace identity``.
        limit: Maximum candidates to return, from 1 through 20.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    try:
        tools = await entry.ensure_catalog()
    except McpConnectionUnavailableError as exc:
        return str(exc)
    terms = [term for term in query.lower().split() if term]
    bounded_limit = min(max(limit, 1), 20)
    ranked = [
        (score, tool)
        for tool in tools
        if (score := _search_score(tool, terms, tool.name in entry.active_tools))[0] >= 0
    ]
    if not ranked:
        ranked = [
            ((100, tool.name.lower()), tool) for tool in tools if tool.name in entry.active_tools
        ]
    ranked.sort(key=lambda item: (-item[0][0], item[0][1]))
    return {
        "connection": connection,
        "query": query,
        "matches": [
            {
                "name": tool.name,
                "description": (tool.description or "").strip() or None,
                "active": tool.name in entry.active_tools,
            }
            for _, tool in ranked[:bounded_limit]
        ],
    }


@function_tool(timeout=60)
async def get_mcp_tool_schema(
    ctx: RunContextWrapper,
    connection: str,
    tool: str,
) -> dict[str, Any] | str:
    """Return one MCP tool's exact input schema.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
        tool: One exact tool name returned by ``search_mcp_tools``.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    try:
        tools = await entry.ensure_catalog()
    except McpConnectionUnavailableError as exc:
        return str(exc)
    match = next((candidate for candidate in tools if candidate.name == tool), None)
    if match is None:
        return (
            f"Unknown tool {tool!r} on MCP connection {connection!r}. "
            "Call search_mcp_tools to find an available tool."
        )
    return {
        "connection": connection,
        "name": match.name,
        "description": (match.description or "").strip() or None,
        "input_schema": match.inputSchema or {"type": "object"},
    }


@function_tool(timeout=120, strict_mode=False)
async def call_mcp(
    ctx: RunContextWrapper,
    connection: str,
    tool: str,
    arguments: Any = None,
) -> Any:
    """Call one tool on one MCP connection and return its result.

    Use the connection id from ``list_mcps``. Use the tool name from
    ``search_mcp_tools``. Pass an object that matches the schema from
    ``get_mcp_tool_schema``. Omit the arguments for a tool that takes no
    arguments.

    Args:
        connection: The connection name exactly as reported by ``list_mcps``.
        tool: The tool name exactly as reported by ``search_mcp_tools``.
        arguments: The tool's arguments as a JSON object of names to values (for
            example ``{"path": "app.py"}``), or omitted/empty for a tool that
            takes none. Pass an object, not a stringified object. Match the shape
            that ``get_mcp_tool_schema`` returned.
    """
    registry = _registry_from_ctx(ctx)
    if registry is None or not registry:
        return _NO_CONNECTIONS
    entry = registry.get(connection)
    if entry is None:
        return _unknown_connection(connection, registry)
    invalid_arguments = (
        f"Invalid arguments for {connection!r}.{tool}: expected a JSON object of "
        "argument names to values, or none. Call get_mcp_tool_schema for the schema."
    )
    if isinstance(arguments, str):
        # The ``arguments`` parameter is schema-less (an open object is not
        # expressible as a strict tool schema), so some models serialize it as a
        # JSON string instead of a bare object. Accept a string that decodes to an
        # object so a correct call is not rejected over its encoding.
        stripped = arguments.strip()
        try:
            arguments = json.loads(stripped) if stripped else {}
        except json.JSONDecodeError:
            return invalid_arguments
    if arguments is not None and not isinstance(arguments, dict):
        return invalid_arguments
    try:
        available = await entry.ensure_catalog()
    except McpConnectionUnavailableError as exc:
        return _errored_tool_output(str(exc))
    valid_names = {mcp_tool.name for mcp_tool in available}
    if tool not in valid_names:
        return (
            f"Unknown tool {tool!r} on MCP connection {connection!r}. "
            "Call search_mcp_tools, then get_mcp_tool_schema."
        )
    session = await entry.ensure_connected()
    result = await session.dispatch(
        tool,
        arguments or {},
        label=namespaced_tool_name(connection, tool),
        result_transform=entry.result_transform,
    )
    # Preserve a compact hand-off for downstream agents. Recon specialists
    # still normalize actionable rows with record_recon; this memory record
    # ensures the raw MCP response is not lost between agent sessions.
    try:
        await _persist_mcp_result(ctx, connection=connection, tool=tool, result=result)
    except Exception:  # noqa: BLE001 - persistence must never break an MCP call
        logger.debug("Could not persist MCP result for %s/%s", connection, tool, exc_info=True)
    return result
