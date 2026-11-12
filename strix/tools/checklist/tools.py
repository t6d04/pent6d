"""Run-scoped, evidence-aware methodology checklist.

The checklist is deliberately separate from the coverage ledger. Coverage
answers ``what surface/risk was reviewed``; this module answers ``which
methodology classes have been closed for this run``.  Items are discovered
from the repository's vulnerability and protocol skill packs, so adding a
skill automatically adds a stable checklist item without copying a second
taxonomy into the runtime.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


VALID_STATUSES: tuple[str, ...] = (
    "pending",
    "in_progress",
    "pass",
    "fail",
    "not_applicable",
    "blocked",
    "partial",
    "needs_validation",
)
_TERMINAL_STATUSES = frozenset({"pass", "fail", "not_applicable"})
_EVIDENCE_REQUIRED = frozenset({"pass", "fail"})

_storage: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None
_mirror_path: Path | None = None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _slug(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip()).strip("_")
    return value.upper() or "UNKNOWN"


def _skills_root() -> Path:
    return Path(__file__).resolve().parents[2] / "skills"


def _frontmatter(path: Path) -> tuple[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return path.stem, ""
    if not text.startswith("---"):
        return path.stem, ""
    block = text.split("---", 2)
    if len(block) < 3:
        return path.stem, ""
    name = path.stem
    description = ""
    for line in block[1].splitlines():
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = value.strip().strip('"').strip("'")
        if key.strip().lower() == "name" and value:
            name = value
        elif key.strip().lower() == "description":
            description = value
    return name, description


def _catalog() -> list[dict[str, Any]]:
    """Build the stable run catalog from vulnerability/protocol skills."""
    root = _skills_root()
    result: list[dict[str, Any]] = []
    for category, directory in (("vulnerability", "vulnerabilities"), ("protocol", "protocols")):
        folder = root / directory
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.md")):
            if path.name.lower() == "readme.md":
                continue
            name, description = _frontmatter(path)
            code = f"P6-{category.upper()}-{_slug(path.stem)}"
            result.append(
                {
                    "code": code,
                    "name": name,
                    "skill": f"{directory}/{path.stem}",
                    "category": category,
                    "description": description,
                }
            )
    # Keep a small fallback so installed/minimal distributions still expose a
    # useful checklist when optional skill packs were omitted.
    if not result:
        for stem, name in (
            ("authentication", "Authentication and session security"),
            ("authorization", "Object and function authorization"),
            ("injection", "Injection and parser boundaries"),
            ("business_logic", "Business logic and workflow security"),
            ("information_disclosure", "Information disclosure"),
        ):
            result.append(
                {
                    "code": f"P6-VULNERABILITY-{_slug(stem)}",
                    "name": name,
                    "skill": f"vulnerabilities/{stem}",
                    "category": "vulnerability",
                    "description": "Built-in fallback checklist item.",
                }
            )
    return result


def known_checklist_codes() -> set[str]:
    """Return the stable codes available to the current Pent6d build."""
    with _lock:
        _ensure_catalog_locked()
        return set(_storage)


def validate_checklist_codes(codes: list[str]) -> list[str]:
    """Return unknown checklist codes without mutating run state."""
    known = known_checklist_codes()
    return [code for code in codes if code not in known]


def _new_item(meta: dict[str, Any]) -> dict[str, Any]:
    return {
        **meta,
        "status": "pending",
        "reason": "",
        "evidence": "",
        "evidence_ids": [],
        "finding_ids": [],
        "coverage": [],
        "updated_at": None,
        "updated_by": None,
    }


def _ensure_catalog_locked() -> None:
    known = {str(item.get("code")) for item in _storage.values()}
    for meta in _catalog():
        if meta["code"] not in known:
            _storage[meta["code"]] = _new_item(meta)


def _write_atomic(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _persist_locked() -> None:
    paths = [path for path in (_path, _mirror_path) if path is not None]
    if not paths:
        return
    payload = json.dumps(
        {"schema_version": 1, "updated_at": _now(), "items": _storage},
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    for path in paths:
        try:
            _write_atomic(path, payload)
        except OSError:
            logger.exception("checklist persist failed: %s", path)


def hydrate_checklist_from_disk(state_dir: Path) -> None:
    """Hydrate one run's checklist and mirror it at the run artifact root."""
    global _path, _mirror_path  # noqa: PLW0603
    state_dir = Path(state_dir)
    _path = state_dir / "checklist.json"
    _mirror_path = state_dir.parent / "checklist.json"
    with _lock:
        _storage.clear()
        source = _path if _path.exists() else _mirror_path
        if source.exists():
            try:
                raw = json.loads(source.read_text(encoding="utf-8"))
                items = raw.get("items") if isinstance(raw, dict) else None
                if isinstance(items, dict):
                    _storage.update(
                        {str(code): item for code, item in items.items() if isinstance(item, dict)}
                    )
            except (OSError, json.JSONDecodeError):
                logger.exception("checklist file is unreadable: %s", source)
        _ensure_catalog_locked()
        _persist_locked()
    logger.info("checklist hydrated from %s (%d item(s))", _path, len(_storage))


def _caller(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    agent_id = inner.get("agent_id") if isinstance(inner.get("agent_id"), str) else None
    coordinator = inner.get("coordinator")
    name = None
    names = getattr(coordinator, "names", None)
    if agent_id and isinstance(names, dict) and isinstance(names.get(agent_id), str):
        name = names[agent_id]
    return agent_id, name


def _normalize_status(value: str) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "na": "not_applicable",
        "n_a": "not_applicable",
        "not_applicable": "not_applicable",
        "needs_follow_up": "needs_validation",
        "needs_validation": "needs_validation",
    }
    return aliases.get(normalized, normalized)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    return [str(item).strip() for item in values if str(item).strip()]


def _progress_locked() -> dict[str, Any]:
    counts = dict.fromkeys(VALID_STATUSES, 0)
    for item in _storage.values():
        status = str(item.get("status") or "pending")
        counts[status] = counts.get(status, 0) + 1
    total = len(_storage)
    terminal = sum(counts.get(status, 0) for status in _TERMINAL_STATUSES)
    return {
        "total": total,
        "filled": terminal,
        "complete": total > 0 and terminal == total,
        "counts": counts,
        "pending": [item["code"] for item in _storage.values() if item.get("status") == "pending"],
        "open": [
            item["code"]
            for item in _storage.values()
            if item.get("status") not in _TERMINAL_STATUSES
        ],
    }


def checklist_status_for_state_dir(state_dir: Path) -> dict[str, Any]:
    """Read progress for finish gates without requiring an agent context."""
    hydrate_checklist_from_disk(Path(state_dir))
    with _lock:
        return _progress_locked()


def _validate_update(
    *,
    code: str,
    status: str,
    reason: str,
    surface: str,
    evidence: str,
    evidence_ids: list[str],
    finding_ids: list[str],
    complete_for_item: bool,
) -> list[str]:
    errors: list[str] = []
    if code not in _storage:
        errors.append(f"unknown checklist code: {code}")
    if status not in VALID_STATUSES:
        errors.append(f"status must be one of: {', '.join(VALID_STATUSES)}")
    if not reason.strip():
        errors.append("reason is required for every checklist update")
    if status == "not_applicable" and len(reason.strip()) < 10:
        errors.append("not_applicable reason must contain at least 10 characters")
    if (
        status in {"in_progress", "pass", "fail", "blocked", "partial", "needs_validation"}
        and not surface.strip()
    ):
        errors.append(f"surface is required for status '{status}'")
    if status in _EVIDENCE_REQUIRED and not (evidence.strip() or evidence_ids or finding_ids):
        errors.append("pass/fail requires evidence text, evidence_ids, or finding_ids")
    if status == "pass" and not complete_for_item:
        errors.append(
            "pass requires complete_for_item=true; use partial while only part "
            "of the surface is covered"
        )
    return errors


def _update_impl(
    *,
    code: str,
    status: str,
    reason: str,
    surface: str,
    role: str,
    session: str,
    evidence: str,
    evidence_ids: list[str],
    finding_ids: list[str],
    complete_for_item: bool,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    normalized = _normalize_status(status)
    with _lock:
        errors = _validate_update(
            code=code,
            status=normalized,
            reason=reason,
            surface=surface,
            evidence=evidence,
            evidence_ids=evidence_ids,
            finding_ids=finding_ids,
            complete_for_item=complete_for_item,
        )
        if errors:
            return {"success": False, "error": "Validation failed", "errors": errors}
        item = _storage[code]
        coverage = item.setdefault("coverage", [])
        key = (surface.strip().lower(), role.strip().lower(), session.strip().lower())
        row = next(
            (
                entry
                for entry in coverage
                if (
                    str(entry.get("surface", "")).lower(),
                    str(entry.get("role", "")).lower(),
                    str(entry.get("session", "")).lower(),
                )
                == key
            ),
            None,
        )
        update = {
            "surface": surface.strip(),
            "role": role.strip(),
            "session": session.strip(),
            "status": normalized,
            "reason": reason.strip(),
            "evidence": evidence.strip(),
            "evidence_ids": evidence_ids,
            "finding_ids": finding_ids,
            "complete_for_item": bool(complete_for_item),
            "updated_at": _now(),
            "updated_by": agent_id,
        }
        if row is None:
            coverage.append(update)
        else:
            row.update(update)
        item["reason"] = reason.strip()
        item["evidence"] = evidence.strip()
        item["evidence_ids"] = sorted(set(_as_list(item.get("evidence_ids")) + evidence_ids))
        item["finding_ids"] = sorted(set(_as_list(item.get("finding_ids")) + finding_ids))
        item["updated_at"] = _now()
        item["updated_by"] = agent_id or agent_name

        if normalized == "not_applicable":
            item["status"] = normalized
        elif normalized == "fail":
            item["status"] = "fail"
        elif normalized in {"blocked", "needs_validation", "partial", "in_progress"}:
            # Never let an unresolved update erase a confirmed failure.
            if item.get("status") != "fail":
                item["status"] = normalized
        elif normalized == "pass" and complete_for_item:
            item["status"] = "pass"
        _persist_locked()
        return {
            "success": True,
            "code": code,
            "status": item["status"],
            "coverage_count": len(coverage),
            "progress": _progress_locked(),
        }


@function_tool(timeout=30)
async def checklist_progress(ctx: RunContextWrapper) -> str:
    """Return checklist progress and unresolved methodology classes."""
    del ctx
    return json.dumps(await asyncio.to_thread(_progress), ensure_ascii=False, default=str)


def _progress() -> dict[str, Any]:
    with _lock:
        _ensure_catalog_locked()
        return {"success": True, **_progress_locked()}


@function_tool(timeout=30)
async def checklist_list(
    ctx: RunContextWrapper,
    only_open: bool = True,
    status: str | None = None,
    limit: int = 100,
) -> str:
    """List checklist items; use this before dispatching or finishing work."""
    del ctx

    def _list() -> dict[str, Any]:
        normalized = _normalize_status(status) if status else None
        with _lock:
            _ensure_catalog_locked()
            rows = []
            for item in _storage.values():
                if only_open and item.get("status") in _TERMINAL_STATUSES:
                    continue
                if normalized and item.get("status") != normalized:
                    continue
                rows.append(
                    {
                        "code": item["code"],
                        "name": item["name"],
                        "skill": item["skill"],
                        "category": item["category"],
                        "status": item["status"],
                        "coverage_count": len(item.get("coverage", [])),
                        "reason": item.get("reason", ""),
                    }
                )
            return {
                "success": True,
                "items": rows[: max(1, min(limit, 500))],
                "progress": _progress_locked(),
            }

    return json.dumps(await asyncio.to_thread(_list), ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def checklist_get(ctx: RunContextWrapper, code: str) -> str:
    """Return one checklist item including all surface/role coverage rows."""
    del ctx

    def _get() -> dict[str, Any]:
        with _lock:
            item = _storage.get(str(code).strip())
            if item is None:
                return {"success": False, "error": f"unknown checklist code: {code}"}
            return {"success": True, "item": dict(item)}

    return json.dumps(await asyncio.to_thread(_get), ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def checklist_update(
    ctx: RunContextWrapper,
    code: str,
    status: str,
    reason: str,
    surface: str = "",
    role: str = "",
    session: str = "",
    evidence: str = "",
    evidence_ids: list[str] | None = None,
    finding_ids: list[str] | None = None,
    complete_for_item: bool = False,
) -> str:
    """Update a checklist class with evidence-aware surface coverage.

    Use ``partial`` while only one surface/role is tested.  Use ``pass`` only
    with ``complete_for_item=true`` after all applicable surfaces are covered.
    """
    agent_id, agent_name = _caller(ctx)
    result = await asyncio.to_thread(
        _update_impl,
        code=str(code).strip(),
        status=status,
        reason=reason,
        surface=surface,
        role=role,
        session=session,
        evidence=evidence,
        evidence_ids=_as_list(evidence_ids),
        finding_ids=_as_list(finding_ids),
        complete_for_item=complete_for_item,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def checklist_bulk_na(
    ctx: RunContextWrapper,
    codes: list[str],
    reason: str,
    evidence: str = "",
) -> str:
    """Mark explicitly inapplicable classes with a durable reason."""
    agent_id, agent_name = _caller(ctx)
    if len(reason.strip()) < 10:
        return json.dumps({"success": False, "error": "reason must contain at least 10 characters"})

    async def _one(code: str) -> dict[str, Any]:
        return await asyncio.to_thread(
            _update_impl,
            code=str(code).strip(),
            status="not_applicable",
            reason=reason,
            surface="",
            role="",
            session="",
            evidence=evidence,
            evidence_ids=[],
            finding_ids=[],
            complete_for_item=True,
            agent_id=agent_id,
            agent_name=agent_name,
        )

    results = [await _one(code) for code in codes]
    return json.dumps(
        {
            "success": all(item.get("success") for item in results),
            "results": results,
            "progress": _progress(),
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def checklist_integrity(ctx: RunContextWrapper) -> str:
    """Check checklist schema and report malformed or incomplete rows."""
    del ctx

    def _integrity() -> dict[str, Any]:
        errors: list[str] = []
        with _lock:
            for code, item in _storage.items():
                if not item.get("name") or item.get("status") not in VALID_STATUSES:
                    errors.append(f"{code}: invalid metadata or status")
                if (
                    item.get("status") in _TERMINAL_STATUSES
                    and not str(item.get("reason") or "").strip()
                ):
                    errors.append(f"{code}: terminal item has no reason")
            return {"success": not errors, "errors": errors[:50], "progress": _progress_locked()}

    return json.dumps(await asyncio.to_thread(_integrity), ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def checklist_export(ctx: RunContextWrapper, output_format: str = "markdown") -> str:
    """Export the run checklist as JSON or Markdown for the UI/report."""
    del ctx

    def _export() -> dict[str, Any]:
        with _lock:
            items = list(_storage.values())
            progress = _progress_locked()
            if output_format.lower() == "json":
                return {"success": True, "format": "json", "progress": progress, "items": items}
            lines = [
                "# Pent6d Methodology Checklist",
                "",
                f"Progress: {progress['filled']}/{progress['total']}",
                "",
            ]
            for item in items:
                lines.append(f"- **{item['code']}** — {item['name']}: `{item['status']}`")
                if item.get("reason"):
                    lines.append(f"  - Reason: {item['reason']}")
                if item.get("coverage"):
                    lines.append(f"  - Coverage rows: {len(item['coverage'])}")
            return {
                "success": True,
                "format": "markdown",
                "progress": progress,
                "markdown": "\n".join(lines),
            }

    return json.dumps(await asyncio.to_thread(_export), ensure_ascii=False, default=str)
