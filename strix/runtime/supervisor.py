"""Deterministic run lifecycle supervision.

The supervisor is deliberately independent from the LLM planner.  It owns a
small, durable state machine for a run and records phase transitions so the
UI, recovery code and future schedulers have one source of truth.  It does not
decide which vulnerability to test; that remains the planner's job.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


class RunPhase(StrEnum):
    """Observable lifecycle phases for a Pent6d run."""

    CREATED = "created"
    SCOPE_CHECK = "scope_check"
    SANDBOX_INIT = "sandbox_init"
    AGENT_SETUP = "agent_setup"
    AGENT_LOOP = "agent_loop"
    RECON = "recon"
    RECON_FINALIZED = "recon_finalized"
    PLANNING = "planning"
    EXECUTION = "execution"
    VALIDATION = "validation"
    CHAIN_IMPACT = "chain_impact"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    INTERRUPTED = "interrupted"


class RunStatus(StrEnum):
    """High-level run status, separate from the more detailed phase."""

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    INTERRUPTED = "interrupted"


_TERMINAL_PHASES = {
    RunPhase.COMPLETED,
    RunPhase.FAILED,
    RunPhase.STOPPED,
    RunPhase.INTERRUPTED,
}
_TERMINAL_STATUSES = {
    RunStatus.COMPLETED,
    RunStatus.FAILED,
    RunStatus.STOPPED,
    RunStatus.INTERRUPTED,
}


@dataclass(slots=True)
class SupervisorState:
    """JSON-serializable state persisted under the run's state directory."""

    schema_version: int = 1
    scan_id: str = ""
    status: RunStatus = RunStatus.CREATED
    phase: RunPhase = RunPhase.CREATED
    started_at: str | None = None
    updated_at: str | None = None
    completed_at: str | None = None
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "scan_id": self.scan_id,
            "status": self.status.value,
            "phase": self.phase.value,
            "started_at": self.started_at,
            "updated_at": self.updated_at,
            "completed_at": self.completed_at,
            "reason": self.reason,
            "metadata": self.metadata,
            "history": self.history,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any], *, scan_id: str) -> SupervisorState:
        try:
            status = RunStatus(str(raw.get("status", RunStatus.CREATED.value)))
        except ValueError:
            status = RunStatus.CREATED
        try:
            phase = RunPhase(str(raw.get("phase", RunPhase.CREATED.value)))
        except ValueError:
            phase = RunPhase.CREATED
        history = raw.get("history")
        metadata = raw.get("metadata")
        return cls(
            schema_version=int(raw.get("schema_version", 1)),
            scan_id=str(raw.get("scan_id") or scan_id),
            status=status,
            phase=phase,
            started_at=raw.get("started_at"),
            updated_at=raw.get("updated_at"),
            completed_at=raw.get("completed_at"),
            reason=str(raw.get("reason") or ""),
            metadata=dict(metadata) if isinstance(metadata, dict) else {},
            history=list(history) if isinstance(history, list) else [],
        )


class RunSupervisor:
    """Persisted lifecycle state and transition guard for one run.

    ``strict=False`` is intentional during the migration: existing runs can
    enter the LLM loop from more than one recovery path.  The same class can
    be switched to strict mode once all phase transitions are emitted by the
    runtime rather than inferred from prompts.
    """

    filename = "supervisor.json"

    def __init__(
        self,
        *,
        scan_id: str,
        state_dir: Path,
        metadata: dict[str, Any] | None = None,
        strict: bool = False,
    ) -> None:
        self.scan_id = scan_id
        self.state_dir = state_dir
        self.path = state_dir / self.filename
        self.strict = strict
        self.state = SupervisorState(scan_id=scan_id, metadata=dict(metadata or {}))
        self._lock = asyncio.Lock()

    async def start(self, *, resume: bool = False) -> None:
        """Create or reopen the durable state for a run."""

        async with self._lock:
            if self.path.exists():
                self.state = self._load_locked()
            now = _now()
            if self.state.started_at is None:
                self.state.started_at = now
            if self.state.scan_id == "":
                self.state.scan_id = self.scan_id
            if resume or self.state.status in _TERMINAL_STATUSES:
                self._append_history_locked(
                    "resume",
                    previous_status=self.state.status.value,
                    previous_phase=self.state.phase.value,
                )
            self.state.status = RunStatus.RUNNING
            self.state.reason = "resumed" if resume else "started"
            self.state.updated_at = now
            self._persist_locked()

    async def transition(
        self,
        phase: RunPhase | str,
        *,
        reason: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Record a phase transition without making the run brittle.

        In migration mode invalid backward transitions are recorded rather
        than raising.  Strict mode is available for tests and for the future
        fully event-driven scheduler.
        """

        next_phase = _coerce_phase(phase)
        async with self._lock:
            previous_phase = self.state.phase
            if self.strict and previous_phase in _TERMINAL_PHASES and next_phase not in {
                RunPhase.AGENT_LOOP,
                RunPhase.COMPLETED,
            }:
                raise ValueError(
                    f"Cannot transition terminal phase {previous_phase.value} "
                    f"to {next_phase.value}"
                )
            self._append_history_locked(
                "phase",
                previous_phase=previous_phase.value,
                phase=next_phase.value,
                reason=reason,
            )
            self.state.phase = next_phase
            if next_phase in _TERMINAL_PHASES:
                self.state.status = RunStatus(next_phase.value)
                self.state.completed_at = _now()
            elif self.state.status not in _TERMINAL_STATUSES:
                self.state.status = RunStatus.RUNNING
            if reason:
                self.state.reason = reason
            if metadata:
                self.state.metadata.update(metadata)
            self.state.updated_at = _now()
            self._persist_locked()

    async def mark_status(
        self,
        status: RunStatus | str,
        *,
        reason: str = "",
    ) -> None:
        """Record a terminal or running status used by recovery and UI."""

        next_status = _coerce_status(status)
        phase = {
            RunStatus.COMPLETED: RunPhase.COMPLETED,
            RunStatus.FAILED: RunPhase.FAILED,
            RunStatus.STOPPED: RunPhase.STOPPED,
            RunStatus.INTERRUPTED: RunPhase.INTERRUPTED,
        }.get(next_status)
        async with self._lock:
            self._append_history_locked(
                "status",
                previous_status=self.state.status.value,
                status=next_status.value,
                reason=reason,
            )
            self.state.status = next_status
            if phase is not None:
                self.state.phase = phase
                self.state.completed_at = _now()
            if reason:
                self.state.reason = reason
            self.state.updated_at = _now()
            self._persist_locked()

    async def snapshot(self) -> dict[str, Any]:
        """Return a detached snapshot suitable for API/UI responses."""

        async with self._lock:
            return deepcopy(self.state.to_dict())

    def _load_locked(self) -> SupervisorState:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Unable to read supervisor state %s: %s", self.path, exc)
            return SupervisorState(scan_id=self.scan_id)
        if not isinstance(raw, dict):
            return SupervisorState(scan_id=self.scan_id)
        return SupervisorState.from_dict(raw, scan_id=self.scan_id)

    def _persist_locked(self) -> None:
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.state_dir,
                delete=False,
            ) as handle:
                json.dump(self.state.to_dict(), handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                temporary = Path(handle.name)
            temporary.replace(self.path)
        except OSError as exc:
            # Lifecycle telemetry must never make a security scan fail.
            logger.warning("Unable to persist supervisor state %s: %s", self.path, exc)

    def _append_history_locked(self, event: str, **payload: Any) -> None:
        self.state.history.append({"at": _now(), "event": event, **payload})
        # Keep the durable lifecycle file bounded even for long interactive runs.
        if len(self.state.history) > 2000:
            del self.state.history[:-2000]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _coerce_phase(value: RunPhase | str) -> RunPhase:
    if isinstance(value, RunPhase):
        return value
    return RunPhase(str(value))


def _coerce_status(value: RunStatus | str) -> RunStatus:
    if isinstance(value, RunStatus):
        return value
    return RunStatus(str(value))


__all__ = ["RunPhase", "RunStatus", "RunSupervisor", "SupervisorState"]
