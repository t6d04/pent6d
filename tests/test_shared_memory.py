from __future__ import annotations

from typing import TYPE_CHECKING

from strix.tools.shared_memory.tools import _remember, _search


if TYPE_CHECKING:
    from pathlib import Path


def test_shared_memory_is_queryable_and_bounded(tmp_path: Path) -> None:
    db = tmp_path / "shared_memory.db"
    saved = _remember(
        db,
        title="API inventory",
        content="The target exposes /api/v1/users and uses bearer authentication.",
        kind="endpoint",
        tags=["recon", "api"],
        source="recon-agent",
        confidence="high",
        agent_id="a1",
        agent_name="Recon",
    )
    assert saved["success"] is True

    result = _search(
        db,
        query="bearer users",
        kind="endpoint",
        tags=["api"],
        limit=4,
        include_content=True,
    )
    assert result["success"] is True
    assert result["count"] == 1
    assert result["memories"][0]["content"].startswith("The target")


def test_shared_memory_rejects_oversized_content(tmp_path: Path) -> None:
    result = _remember(
        tmp_path / "shared_memory.db",
        title="too large",
        content="x" * 24_001,
        kind="fact",
        tags=[],
        source="",
        confidence="medium",
        agent_id=None,
        agent_name=None,
    )
    assert result["success"] is False


def test_shared_memory_supports_typed_metadata(tmp_path: Path) -> None:
    db = tmp_path / "shared_memory.db"
    saved = _remember(
        db,
        title="Validated task evidence",
        content="The authenticated request returned another user's order.",
        kind="evidence",
        tags=["authz", "idor"],
        source="validator",
        confidence="high",
        agent_id="validator-1",
        agent_name="Authorization Validator",
        metadata={
            "task_id": "task-123",
            "finding_id": "finding-456",
            "parent_task_id": "task-100",
        },
    )
    assert saved["success"] is True

    result = _search(
        db,
        query="authenticated order",
        kind="evidence",
        tags=["idor"],
        limit=1,
        include_content=True,
    )
    assert result["memories"][0]["metadata"]["finding_id"] == "finding-456"
