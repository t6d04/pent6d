"""Persistent, run-scoped memory shared by all agents.

Agent SDK sessions intentionally remain private to each agent.  This module is
the small, queryable bridge between those sessions: facts are stored in the
run's ``.state/shared_memory.db`` and agents retrieve only the few records
relevant to their current task.  Keeping retrieval separate from conversation
history prevents one agent's entire transcript from being replayed into every
other agent's context.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)

_DB_NAME = "shared_memory.db"
_MAX_CONTENT_CHARS = 24_000
_MAX_QUERY_CHARS = 500
_DEFAULT_LIMIT = 8
_MAX_LIMIT = 20
_VALID_KINDS = {
    "fact",
    "observation",
    "endpoint",
    "credential",
    "hypothesis",
    "decision",
    "task",
    "attempt",
    "evidence",
    "finding",
    "chain_edge",
    "coverage",
    "artifact",
    "session",
}
_TOKEN_RE = re.compile(r"[a-zA-Z0-9_:-]{2,}")


def _context(ctx: RunContextWrapper) -> dict[str, Any]:
    value = ctx.context
    return value if isinstance(value, dict) else {}


def _db_path(ctx: RunContextWrapper) -> Path | None:
    raw = _context(ctx).get("state_dir")
    if isinstance(raw, Path):
        state_dir = raw
    elif isinstance(raw, str) and raw.strip():
        state_dir = Path(raw)
    else:
        return None
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / _DB_NAME


def _identity(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    inner = _context(ctx)
    agent_id = inner.get("agent_id")
    agent_id = agent_id if isinstance(agent_id, str) else None
    name: str | None = None
    coordinator = inner.get("coordinator")
    names = getattr(coordinator, "names", {})
    if agent_id and isinstance(names, dict) and isinstance(names.get(agent_id), str):
        name = names[agent_id]
    return agent_id, name


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=15.0)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout=15000")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute(
        """CREATE TABLE IF NOT EXISTS memories (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            kind TEXT NOT NULL,
            tags TEXT NOT NULL DEFAULT '[]',
            source TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'medium',
            agent_id TEXT,
            agent_name TEXT,
            metadata TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )
    columns = {
        str(row[1]) for row in connection.execute("PRAGMA table_info(memories)").fetchall()
    }
    if "metadata" not in columns:
        # Existing runs predate the typed blackboard field. Migrate lazily when
        # a run is first opened instead of invalidating its memory database.
        connection.execute(
            "ALTER TABLE memories ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'"
        )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_memories_kind_updated ON memories(kind, updated_at DESC)"
    )
    connection.commit()
    return connection


def _row(row: sqlite3.Row, *, include_content: bool = True) -> dict[str, Any]:
    result: dict[str, Any] = {
        "memory_id": row["id"],
        "title": row["title"],
        "kind": row["kind"],
        "tags": json.loads(row["tags"] or "[]"),
        "source": row["source"],
        "confidence": row["confidence"],
        "agent_id": row["agent_id"],
        "agent_name": row["agent_name"],
        "metadata": json.loads(row["metadata"] or "{}"),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }
    if include_content:
        result["content"] = row["content"]
    else:
        content = str(row["content"])
        result["content_preview"] = content[:280] + ("..." if len(content) > 280 else "")
    return result


def _terms(query: str) -> list[str]:
    return list(dict.fromkeys(_TOKEN_RE.findall(query.lower())))[:24]


def _remember(
    path: Path,
    *,
    title: str,
    content: str,
    kind: str,
    tags: list[str],
    source: str,
    confidence: str,
    agent_id: str | None,
    agent_name: str | None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not title.strip() or not content.strip():
        return {"success": False, "error": "title and content are required"}
    if kind not in _VALID_KINDS:
        return {"success": False, "error": f"kind must be one of {sorted(_VALID_KINDS)}"}
    content = content.strip()
    if len(content) > _MAX_CONTENT_CHARS:
        return {"success": False, "error": f"content exceeds {_MAX_CONTENT_CHARS} characters"}
    typed_metadata = metadata or {}
    try:
        metadata_json = json.dumps(typed_metadata, ensure_ascii=False, separators=(",", ":"))
    except (TypeError, ValueError):
        return {"success": False, "error": "metadata must be JSON serializable"}
    if len(metadata_json) > 8_000:
        return {"success": False, "error": "metadata exceeds 8000 characters"}
    now = datetime.now(UTC).isoformat()
    memory_id = uuid.uuid4().hex[:10]
    with _connect(path) as db:
        db.execute(
            """INSERT INTO memories
            (id,title,content,kind,tags,source,confidence,agent_id,agent_name,metadata,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                memory_id,
                title.strip(),
                content,
                kind,
                json.dumps(list(dict.fromkeys(str(t).strip() for t in tags if str(t).strip()))),
                source.strip(),
                confidence.strip() or "medium",
                agent_id,
                agent_name,
                metadata_json,
                now,
                now,
            ),
        )
        db.commit()
    return {"success": True, "memory_id": memory_id, "message": "Shared memory saved"}


def _search(
    path: Path,
    *,
    query: str,
    kind: str | None,
    tags: list[str],
    limit: int,
    include_content: bool,
) -> dict[str, Any]:
    query = query.strip()[:_MAX_QUERY_CHARS]
    terms = _terms(query)
    if not terms:
        return {"success": True, "memories": [], "count": 0}
    limit = max(1, min(limit, _MAX_LIMIT))
    clauses: list[str] = []
    params: list[Any] = []
    for term in terms:
        like = f"%{term}%"
        clauses.append("(lower(title) LIKE ? OR lower(content) LIKE ? OR lower(tags) LIKE ?)")
        params.extend([like, like, like])
    if kind:
        clauses.append("kind = ?")
        params.append(kind)
    sql = (
        "SELECT * FROM memories WHERE "  # noqa: S608 - clauses are fixed literals
        + " AND ".join(clauses)
        + " ORDER BY updated_at DESC LIMIT ?"
    )
    params.append(limit * 4)
    with _connect(path) as db:
        rows = db.execute(sql, params).fetchall()
    # Rank by number of matched terms, then recency. This is deliberately
    # bounded: the model receives only the top-k relevant facts.
    scored: list[tuple[int, sqlite3.Row]] = []
    wanted_tags = {tag.lower() for tag in tags}
    for row in rows:
        row_tags = {str(tag).lower() for tag in json.loads(row["tags"] or "[]")}
        if wanted_tags and not wanted_tags.intersection(row_tags):
            continue
        haystack = " ".join((row["title"], row["content"], row["tags"])).lower()
        score = sum(term in haystack for term in terms)
        scored.append((score, row))
    scored.sort(key=lambda item: (item[0], item[1]["updated_at"]), reverse=True)
    return {
        "success": True,
        "memories": [_row(row, include_content=include_content) for _, row in scored[:limit]],
        "count": min(len(scored), limit),
    }


@function_tool(timeout=30)
async def remember_shared_memory(
    ctx: RunContextWrapper,
    title: str,
    content: str,
    kind: str = "fact",
    tags: list[str] | None = None,
    source: str = "",
    confidence: str = "medium",
    metadata_json: str = "{}",
) -> str:
    """Save a durable fact for every agent in this run.

    Store compact, reusable facts (endpoints, credentials, technology
    fingerprints, hypotheses, decisions, evidence and task state), not whole
    tool outputs or transcripts. ``metadata_json`` carries typed identifiers such as
    task_id, finding_id, parent_task_id and dependency information.
    The memory belongs to the current run and is not shared across projects.
    """
    path = _db_path(ctx)
    if path is None:
        return json.dumps({"success": False, "error": "run state directory unavailable"})
    try:
        metadata = json.loads(metadata_json or "{}")
    except (TypeError, ValueError):
        return json.dumps({"success": False, "error": "metadata_json must be valid JSON"})
    if not isinstance(metadata, dict):
        return json.dumps({"success": False, "error": "metadata_json must contain an object"})
    agent_id, agent_name = _identity(ctx)
    result = await asyncio.to_thread(
        _remember,
        path,
        title=title,
        content=content,
        kind=kind,
        tags=tags or [],
        source=source,
        confidence=confidence,
        agent_id=agent_id,
        agent_name=agent_name,
        metadata=metadata,
    )
    return json.dumps(result, ensure_ascii=False)


@function_tool(timeout=30)
async def search_shared_memory(
    ctx: RunContextWrapper,
    query: str,
    kind: str | None = None,
    tags: list[str] | None = None,
    limit: int = _DEFAULT_LIMIT,
    include_content: bool = True,
) -> str:
    """Retrieve only the most relevant shared facts for the current task."""
    path = _db_path(ctx)
    if path is None:
        return json.dumps({"success": False, "error": "run state directory unavailable"})
    result = await asyncio.to_thread(
        _search,
        path,
        query=query,
        kind=kind,
        tags=tags or [],
        limit=limit,
        include_content=include_content,
    )
    return json.dumps(result, ensure_ascii=False)


@function_tool(timeout=30)
async def get_shared_memory(ctx: RunContextWrapper, memory_id: str) -> str:
    """Read one shared memory record by ID."""
    path = _db_path(ctx)
    if path is None:
        return json.dumps({"success": False, "error": "run state directory unavailable"})
    def read() -> dict[str, Any]:
        with _connect(path) as db:
            row = db.execute("SELECT * FROM memories WHERE id = ?", (memory_id.strip(),)).fetchone()
        return {"success": True, "memory": _row(row)} if row else {
            "success": False,
            "error": "memory not found",
        }
    return json.dumps(await asyncio.to_thread(read), ensure_ascii=False)


@function_tool(timeout=30)
async def forget_shared_memory(ctx: RunContextWrapper, memory_id: str) -> str:
    """Delete a stale or incorrect shared memory record."""
    path = _db_path(ctx)
    if path is None:
        return json.dumps({"success": False, "error": "run state directory unavailable"})
    def delete() -> dict[str, Any]:
        with _connect(path) as db:
            cursor = db.execute("DELETE FROM memories WHERE id = ?", (memory_id.strip(),))
            db.commit()
        return {"success": bool(cursor.rowcount), "memory_id": memory_id}
    return json.dumps(await asyncio.to_thread(delete), ensure_ascii=False)
