"""Tests for the deterministic run supervisor lifecycle state."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from strix.runtime.supervisor import RunPhase, RunStatus, RunSupervisor


@pytest.mark.asyncio
async def test_supervisor_persists_phase_and_terminal_status(tmp_path: Path) -> None:
    supervisor = RunSupervisor(scan_id="run-1", state_dir=tmp_path)

    await supervisor.start()
    await supervisor.transition(RunPhase.SANDBOX_INIT)
    await supervisor.transition(
        RunPhase.RECON_FINALIZED,
        reason="recon_snapshot_persisted",
        metadata={"recon_entry_count": 3},
    )
    await supervisor.mark_status(RunStatus.COMPLETED, reason="finish_scan")

    payload = json.loads((tmp_path / "supervisor.json").read_text(encoding="utf-8"))
    assert payload["scan_id"] == "run-1"
    assert payload["status"] == "completed"
    assert payload["phase"] == "completed"
    assert payload["metadata"]["recon_entry_count"] == 3
    assert [item["event"] for item in payload["history"]] == [
        "phase",
        "phase",
        "status",
    ]


@pytest.mark.asyncio
async def test_supervisor_resume_reopens_terminal_run(tmp_path: Path) -> None:
    first = RunSupervisor(scan_id="run-2", state_dir=tmp_path)
    await first.start()
    await first.mark_status(RunStatus.COMPLETED, reason="initial_finish")

    resumed = RunSupervisor(scan_id="run-2", state_dir=tmp_path)
    await resumed.start(resume=True)
    snapshot = await resumed.snapshot()

    assert snapshot["status"] == "running"
    assert snapshot["phase"] == "completed"
    assert snapshot["history"][-1]["event"] == "resume"


@pytest.mark.asyncio
async def test_strict_supervisor_rejects_terminal_to_unrelated_phase(tmp_path: Path) -> None:
    supervisor = RunSupervisor(scan_id="run-3", state_dir=tmp_path, strict=True)
    await supervisor.start()
    await supervisor.mark_status(RunStatus.FAILED, reason="test")

    with pytest.raises(ValueError, match="terminal phase"):
        await supervisor.transition(RunPhase.RECON)
