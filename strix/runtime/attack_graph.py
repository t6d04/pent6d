"""Persistent task/dependency graph used by the Pent6d planner.

This module is intentionally model-agnostic.  The Planner may propose tasks,
but the graph owns identity, dependency checks and status transitions so a
malformed LLM response cannot silently create duplicate or impossible work.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import uuid
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


class TaskStatus(StrEnum):
    PENDING = "pending"
    READY = "ready"
    BLOCKED = "blocked"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


_TERMINAL_TASK_STATUSES = {
    TaskStatus.SUCCEEDED,
    TaskStatus.FAILED,
    TaskStatus.SKIPPED,
    TaskStatus.CANCELLED,
}


@dataclass(slots=True)
class AttackTask:
    task_id: str
    title: str
    role: str
    phase: str
    risk: str = "low"
    dispatch_key: str = ""
    dependencies: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    status: TaskStatus = TaskStatus.PENDING
    attempts: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "role": self.role,
            "phase": self.phase,
            "risk": self.risk,
            "dispatch_key": self.dispatch_key,
            "dependencies": list(self.dependencies),
            "evidence_ids": list(self.evidence_ids),
            "status": self.status.value,
            "attempts": self.attempts,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AttackTask:
        try:
            status = TaskStatus(str(raw.get("status", TaskStatus.PENDING.value)))
        except ValueError:
            status = TaskStatus.PENDING
        metadata_raw = raw.get("metadata")
        metadata = dict(metadata_raw) if isinstance(metadata_raw, dict) else {}
        return cls(
            task_id=str(raw.get("task_id") or ""),
            title=str(raw.get("title") or ""),
            role=str(raw.get("role") or "specialist"),
            phase=str(raw.get("phase") or "execution"),
            risk=str(raw.get("risk") or "low"),
            dispatch_key=str(raw.get("dispatch_key") or ""),
            dependencies=[str(item) for item in raw.get("dependencies", []) if str(item)],
            evidence_ids=[str(item) for item in raw.get("evidence_ids", []) if str(item)],
            status=status,
            attempts=max(0, int(raw.get("attempts", 0))),
            metadata=metadata,
            created_at=str(raw.get("created_at") or ""),
            updated_at=str(raw.get("updated_at") or ""),
        )


class AttackGraph:
    """Run-scoped, durable graph with bounded task identity and dependencies."""

    filename = "attack_graph.json"
    max_tasks = 5_000

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.path = state_dir / self.filename
        self._lock = asyncio.Lock()
        self.tasks: dict[str, AttackTask] = {}
        self._load()

    async def add_task(
        self,
        *,
        title: str,
        role: str,
        phase: str,
        risk: str = "low",
        dispatch_key: str = "",
        dependencies: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        task_id: str | None = None,
    ) -> dict[str, Any]:
        """Add or return a task identified by ``dispatch_key``.

        A stable dispatch key makes repeated Planner calls idempotent during
        recovery and prevents duplicate specialists for the same responsibility.
        """

        clean_title = title.strip()
        if not clean_title:
            return {"success": False, "error": "title is required"}
        clean_dependencies = list(dict.fromkeys(str(item) for item in (dependencies or []) if item))
        async with self._lock:
            if dispatch_key:
                existing = next(
                    (task for task in self.tasks.values() if task.dispatch_key == dispatch_key),
                    None,
                )
                if existing is not None:
                    return {"success": True, "created": False, "task": existing.to_dict()}
            if len(self.tasks) >= self.max_tasks:
                return {"success": False, "error": "attack graph task limit reached"}
            now = _now()
            new_task = AttackTask(
                task_id=task_id or f"task-{uuid.uuid4().hex[:12]}",
                title=clean_title,
                role=role.strip() or "specialist",
                phase=phase.strip() or "execution",
                risk=risk.strip() or "low",
                dispatch_key=dispatch_key.strip(),
                dependencies=clean_dependencies,
                evidence_ids=list(
                    dict.fromkeys(str(item) for item in (evidence_ids or []) if item)
                ),
                status=(TaskStatus.READY if not clean_dependencies else TaskStatus.BLOCKED),
                metadata=dict(metadata or {}),
                created_at=now,
                updated_at=now,
            )
            missing = [item for item in clean_dependencies if item not in self.tasks]
            if missing:
                return {"success": False, "error": "unknown task dependencies", "missing": missing}
            self.tasks[new_task.task_id] = new_task
            self._persist_locked()
            return {"success": True, "created": True, "task": new_task.to_dict()}

    async def set_status(
        self,
        task_id: str,
        status: TaskStatus | str,
        *,
        increment_attempt: bool = False,
    ) -> dict[str, Any]:
        try:
            next_status = status if isinstance(status, TaskStatus) else TaskStatus(str(status))
        except ValueError:
            return {"success": False, "error": f"unknown task status: {status}"}
        async with self._lock:
            task = self.tasks.get(task_id)
            if task is None:
                return {"success": False, "error": "task not found"}
            task.status = next_status
            if increment_attempt:
                task.attempts += 1
            task.updated_at = _now()
            self._refresh_blocked_locked()
            self._persist_locked()
            return {"success": True, "task": task.to_dict()}

    async def ready_tasks(self, *, role: str | None = None) -> list[dict[str, Any]]:
        async with self._lock:
            self._refresh_blocked_locked()
            tasks = [
                task.to_dict()
                for task in self.tasks.values()
                if task.status == TaskStatus.READY and (role is None or task.role == role)
            ]
            return deepcopy(tasks)

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "schema_version": 1,
                "tasks": deepcopy(
                    {task_id: task.to_dict() for task_id, task in self.tasks.items()}
                ),
            }

    def _refresh_blocked_locked(self) -> None:
        for task in self.tasks.values():
            if task.status not in {TaskStatus.PENDING, TaskStatus.BLOCKED, TaskStatus.READY}:
                continue
            dependencies = [self.tasks.get(item) for item in task.dependencies]
            if all(
                item is not None and item.status == TaskStatus.SUCCEEDED
                for item in dependencies
            ):
                task.status = TaskStatus.READY
            else:
                task.status = TaskStatus.BLOCKED if task.dependencies else TaskStatus.READY

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        raw_tasks = raw.get("tasks") if isinstance(raw, dict) else None
        if isinstance(raw_tasks, dict):
            self.tasks = {
                task_id: task
                for task_id, value in raw_tasks.items()
                if isinstance(value, dict)
                for task in [AttackTask.from_dict({**value, "task_id": task_id})]
                if task.task_id and task.title
            }

    def _persist_locked(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=self.state_dir,
            delete=False,
        ) as handle:
            json.dump(
                {
                    "schema_version": 1,
                    "tasks": {task_id: task.to_dict() for task_id, task in self.tasks.items()},
                },
                handle,
                ensure_ascii=False,
                indent=2,
            )
            handle.write("\n")
            temporary = Path(handle.name)
        temporary.replace(self.path)


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = ["AttackGraph", "AttackTask", "TaskStatus"]
