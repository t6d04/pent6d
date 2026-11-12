"""Evidence-backed validator records.

Validator output is deliberately separate from the narrative completion
message.  The finish gate can therefore require a durable verdict even when a
model forgets to mention validation in prose.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import tempfile
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from agents import RunContextWrapper, function_tool


VALID_VERDICTS: tuple[str, ...] = (
    "confirmed",
    "ruled_out",
    "informational",
    "open_proof_gap",
)
VALID_CONFIDENCE: tuple[str, ...] = ("low", "medium", "high")

_storage: dict[str, dict[str, Any]] = {}
_lock = threading.RLock()
_path: Path | None = None
_mirror_path: Path | None = None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _as_list(value: Any) -> list[str]:
    values = value if isinstance(value, list) else [value]
    return list(dict.fromkeys(str(item).strip() for item in values if str(item).strip()))


def _write_atomic(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    temporary.replace(path)


def _persist_locked() -> None:
    paths = [path for path in (_path, _mirror_path) if path is not None]
    payload = json.dumps(
        {"schema_version": 1, "updated_at": _now(), "records": _storage},
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    for path in paths:
        with contextlib.suppress(OSError):
            _write_atomic(path, payload)


def hydrate_validations_from_disk(state_dir: Path) -> None:
    """Load validation records for one run and mirror them at its artifact root."""
    global _path, _mirror_path  # noqa: PLW0603
    state_dir = Path(state_dir)
    _path = state_dir / "validations.json"
    _mirror_path = state_dir.parent / "validations.json"
    with _lock:
        _storage.clear()
        source = _path if _path.exists() else _mirror_path
        if source.exists():
            try:
                raw = json.loads(source.read_text(encoding="utf-8"))
                records = raw.get("records") if isinstance(raw, dict) else None
                if isinstance(records, dict):
                    _storage.update(
                        {
                            str(key): value
                            for key, value in records.items()
                            if isinstance(value, dict)
                        }
                    )
            except (OSError, json.JSONDecodeError):
                _storage.clear()
        _persist_locked()


def _caller(ctx: RunContextWrapper) -> tuple[str | None, str | None]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    agent_id = inner.get("agent_id") if isinstance(inner.get("agent_id"), str) else None
    coordinator = inner.get("coordinator")
    names = getattr(coordinator, "names", {})
    agent_name = names.get(agent_id) if isinstance(names, dict) and agent_id else None
    return agent_id, agent_name if isinstance(agent_name, str) else None


def _record_impl(
    *,
    task_id: str,
    verdict: str,
    confidence: str,
    summary: str,
    evidence: str,
    evidence_ids: list[str],
    target_identity: str,
    reproduced: bool,
    missing_evidence: str,
    agent_id: str | None,
    agent_name: str | None,
) -> dict[str, Any]:
    normalized_verdict = verdict.strip().lower().replace("-", "_").replace(" ", "_")
    normalized_confidence = confidence.strip().lower()
    errors: list[str] = []
    if normalized_verdict not in VALID_VERDICTS:
        errors.append(f"verdict must be one of: {', '.join(VALID_VERDICTS)}")
    if normalized_confidence not in VALID_CONFIDENCE:
        errors.append(f"confidence must be one of: {', '.join(VALID_CONFIDENCE)}")
    if not task_id.strip():
        errors.append("task_id is required")
    if not summary.strip():
        errors.append("summary is required")
    if not evidence.strip() and not evidence_ids:
        errors.append("evidence or evidence_ids is required")
    if not target_identity.strip():
        errors.append("target_identity is required")
    if normalized_verdict == "confirmed" and not reproduced:
        errors.append("confirmed requires reproduced=true")
    if normalized_verdict == "open_proof_gap" and not missing_evidence.strip():
        errors.append("open_proof_gap requires missing_evidence")
    if errors:
        return {"success": False, "error": "Validation record rejected", "errors": errors}

    record_id = f"validation-{uuid.uuid4().hex[:12]}"
    record = {
        "id": record_id,
        "task_id": task_id.strip(),
        "verdict": normalized_verdict,
        "confidence": normalized_confidence,
        "summary": summary.strip(),
        "evidence": evidence.strip(),
        "evidence_ids": list(evidence_ids),
        "target_identity": target_identity.strip(),
        "reproduced": bool(reproduced),
        "missing_evidence": missing_evidence.strip(),
        "created_at": _now(),
        "agent_id": agent_id,
        "agent_name": agent_name,
    }
    with _lock:
        _storage[record_id] = record
        _persist_locked()
    return {"success": True, "record": record, "record_id": record_id}


def validation_status_for_state_dir(state_dir: Path) -> dict[str, Any]:
    hydrate_validations_from_disk(Path(state_dir))
    with _lock:
        records = list(_storage.values())
    return {
        "success": True,
        "total": len(records),
        "by_verdict": {
            verdict: sum(1 for record in records if record.get("verdict") == verdict)
            for verdict in VALID_VERDICTS
        },
        "records": records,
    }


@function_tool(timeout=30)
async def record_validation(
    ctx: RunContextWrapper,
    task_id: str,
    verdict: Literal["confirmed", "ruled_out", "informational", "open_proof_gap"],
    confidence: Literal["low", "medium", "high"],
    summary: str,
    evidence: str,
    target_identity: str,
    reproduced: bool = False,
    evidence_ids: list[str] | None = None,
    missing_evidence: str = "",
) -> str:
    """Persist an independent validator verdict and bind it to its graph task."""
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    graph = inner.get("attack_graph")
    if graph is None or not hasattr(graph, "snapshot"):
        return json.dumps({"success": False, "error": "attack graph unavailable"})
    snapshot = await graph.snapshot()
    task = snapshot.get("tasks", {}).get(task_id) if isinstance(snapshot, dict) else None
    if not isinstance(task, dict) or task.get("role") != "validator":
        return json.dumps({"success": False, "error": "task_id is not a validator task"})
    agent_id, agent_name = _caller(ctx)
    owner_id = (task.get("metadata") or {}).get("agent_id")
    if owner_id and owner_id != agent_id:
        return json.dumps(
            {"success": False, "error": "validator task is assigned to another agent"}
        )
    result = await asyncio.to_thread(
        _record_impl,
        task_id=task_id,
        verdict=verdict,
        confidence=confidence,
        summary=summary,
        evidence=evidence,
        evidence_ids=_as_list(evidence_ids),
        target_identity=target_identity,
        reproduced=reproduced,
        missing_evidence=missing_evidence,
        agent_id=agent_id,
        agent_name=agent_name,
    )
    if result.get("success"):
        binding = await graph.bind_validation(task_id, str(result["record_id"]))
        if not binding.get("success"):
            return json.dumps({"success": False, "error": binding.get("error", "bind failed")})
    return json.dumps(result, ensure_ascii=False, default=str)


@function_tool(timeout=30)
async def list_validations(ctx: RunContextWrapper) -> str:
    """List durable validator records for the current run."""
    del ctx
    with _lock:
        records = list(_storage.values())
    return json.dumps({"success": True, "records": records}, ensure_ascii=False, default=str)


__all__ = [
    "hydrate_validations_from_disk",
    "list_validations",
    "record_validation",
    "validation_status_for_state_dir",
]
