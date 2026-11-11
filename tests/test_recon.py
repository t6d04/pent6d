from __future__ import annotations

import io
import json
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.tools.recon.tools import (
    ReconObservation,
    _copy_screenshot,
    _finalize_recon_sync,
    _required_coverage,
    _save,
    _save_coverage,
    finalize_recon,
    list_recon_coverage,
    read_recon,
    record_recon,
    record_recon_coverage,
    record_source_leak,
)


if TYPE_CHECKING:
    from pathlib import Path


def test_inventory_survives_restart_updates_and_isolates_runs(tmp_path: Path) -> None:
    entry = ReconObservation(
        kind="subdomain", value="https://api.example.com", source="httpx"
    ).model_dump()
    _save(tmp_path / "one", [{**entry, "screenshot": "capture.png"}], "a")
    _save(tmp_path / "one", [{**entry, "alive": "alive", "status_code": 403}], "b")
    document = read_recon(tmp_path / "one")
    assert len(document["entries"]) == 1
    assert document["entries"][0]["status_code"] == 403
    assert document["entries"][0]["screenshot"] == "capture.png"
    assert read_recon(tmp_path / "two")["entries"] == []


def test_post_form_observation_retains_body_metadata(tmp_path: Path) -> None:
    _save(
        tmp_path,
        [
            ReconObservation(
                kind="endpoint",
                value="https://example.test/hoi-dap",
                source="form inventory",
                scope="in_scope",
                method="POST",
                content_type="application/x-www-form-urlencoded",
                parameters=[
                    "ctrl_419845_1202$txtQuestionTitle",
                    "ctrl_419845_1202$txtVerifierValue",
                ],
            ).model_dump(),
        ],
        "recon",
    )

    entry = read_recon(tmp_path)["entries"][0]
    assert entry["method"] == "POST"
    assert entry["content_type"] == "application/x-www-form-urlencoded"
    assert entry["parameters"] == [
        "ctrl_419845_1202$txtQuestionTitle",
        "ctrl_419845_1202$txtVerifierValue",
    ]

    # A later sparse observation of the same endpoint must not erase the form
    # inventory that a POST-XSS specialist needs.
    _save(
        tmp_path,
        [
            ReconObservation(
                kind="endpoint",
                value="https://example.test/hoi-dap",
                source="live recheck",
                method="POST",
            ).model_dump(),
        ],
        "recon",
    )
    entry = read_recon(tmp_path)["entries"][0]
    assert entry["content_type"] == "application/x-www-form-urlencoded"
    assert entry["parameters"] == [
        "ctrl_419845_1202$txtQuestionTitle",
        "ctrl_419845_1202$txtVerifierValue",
    ]


def test_alive_is_service_state_and_projects_to_passive_host_record(tmp_path: Path) -> None:
    _save(
        tmp_path,
        [
            ReconObservation(
                kind="subdomain",
                value="https://api.example.com",
                source="crt.sh",
                scope="in_scope",
                alive="alive",
            ).model_dump(),
            ReconObservation(
                kind="service",
                value="https://api.example.com/health",
                source="direct probe",
                scope="in_scope",
                alive="alive",
                status_code=404,
            ).model_dump(),
        ],
        "recon",
    )

    entries = read_recon(tmp_path)["entries"]
    host = next(entry for entry in entries if entry["kind"] == "subdomain")
    assert host["alive"] == "alive"
    assert host["status_code"] == 404


def test_attribution_is_persisted_and_out_of_scope_is_consistent(tmp_path: Path) -> None:
    _save(
        tmp_path,
        [
            ReconObservation(
                kind="subdomain",
                value="api.example.com",
                source="crt.sh",
                scope="in_scope",
                attribution="likely",
                attribution_evidence="Certificate SAN matches the in-scope wildcard",
            ).model_dump(),
            ReconObservation(
                kind="subdomain",
                value="other.example.net",
                source="shared IP",
                scope="out_of_scope",
                attribution="confirmed",
            ).model_dump(),
        ],
        "recon",
    )

    entries = read_recon(tmp_path)["entries"]
    assert entries[0]["attribution"] == "likely"
    assert entries[0]["attribution_evidence"]
    assert entries[1]["attribution"] == "out_of_scope"


def test_proxy_error_does_not_mark_service_alive_or_dead(tmp_path: Path) -> None:
    _save(
        tmp_path,
        [
            ReconObservation(
                kind="service",
                value="https://api.example.com",
                source="Caido local proxy",
                alive="unreachable",
                status_code=502,
                evidence="Proxy error page; request never reached the origin",
            ).model_dump(),
        ],
        "recon",
    )

    assert read_recon(tmp_path)["entries"][0]["alive"] == "unknown"


@pytest.mark.asyncio
async def test_record_source_leak_persists_local_and_online_locations(tmp_path: Path) -> None:
    ctx = ToolContext(
        context={"state_dir": tmp_path / ".state", "agent_id": "recon"},
        tool_name="record_source_leak",
        tool_call_id="test",
        tool_arguments="{}",
    )
    result = json.loads(
        await record_source_leak.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "source_leaks_json": json.dumps([
                        {
                            "source": "source-map",
                            "source_location": "/workspace/dump/app-src",
                            "source_location_type": "local_path",
                            "source_download_status": "downloaded",
                        },
                        {
                            "source": "public repository link",
                            "source_location": "https://example.com/repository.zip",
                            "source_location_type": "web_url",
                            "source_download_status": "online_only",
                        },
                    ])
                }
            ),
        )
    )
    assert result["success"]
    entries = read_recon(tmp_path)["entries"]
    assert {entry["source_location_type"] for entry in entries} == {
        "local_path",
        "web_url",
    }
    assert {entry["kind"] for entry in entries} == {"source_leak"}


@pytest.mark.asyncio
async def test_record_source_leak_rejects_invalid_online_location(tmp_path: Path) -> None:
    ctx = ToolContext(
        context={"state_dir": tmp_path / ".state", "agent_id": "recon"},
        tool_name="record_source_leak",
        tool_call_id="test",
        tool_arguments="{}",
    )
    result = json.loads(
        await record_source_leak.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "source_leaks_json": json.dumps({
                        "source": "source-map",
                        "source_location": "not-a-url",
                        "source_location_type": "web_url",
                        "source_download_status": "online_only",
                    })
                }
            ),
        )
    )
    assert result["success"] is False
    assert "absolute http(s) URL" in result["error"]


def test_parallel_agents_do_not_lose_inventory(tmp_path: Path) -> None:
    def save(index: int) -> None:
        entry = ReconObservation(
            kind="subdomain", value=f"{index}.example.com", source="DNS"
        ).model_dump()
        _save(tmp_path, [entry], str(index))

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(save, range(30)))
    assert len(read_recon(tmp_path)["entries"]) == 30


def test_finalize_recon_snapshots_every_entry_into_shared_memory(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = run_dir / ".state"
    entry = ReconObservation(
        kind="endpoint", value="https://example.com/api", source="crawler", evidence="GET"
    ).model_dump()
    _save(run_dir, [entry], "recon")

    result = _finalize_recon_sync(
        run_dir,
        state_dir,
        agent_id="root",
        agent_name="Root Agent",
    )

    assert result["success"] is True
    assert result["entry_count"] == 1
    assert (run_dir / "recon_complete.json").is_file()
    assert len(result["memory_ids"]) == 1
    second = _finalize_recon_sync(
        run_dir,
        state_dir,
        agent_id="root",
        agent_name="Root Agent",
    )
    assert second["already_finalized"] is True


def test_finalize_recon_requires_screenshot_for_each_live_host(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = run_dir / ".state"
    _save(
        run_dir,
        [
            ReconObservation(
                kind="service",
                value="https://live.example.com/",
                source="direct probe",
                scope="in_scope",
                alive="alive",
                status_code=200,
            ).model_dump(),
        ],
        "recon",
    )

    result = _finalize_recon_sync(
        run_dir,
        state_dir,
        agent_id="root",
        agent_name="Root Agent",
    )

    assert result["success"] is False
    assert result["missing_screenshot_hosts"] == ["live.example.com"]


def test_required_coverage_is_target_aware() -> None:
    web = _required_coverage(scan_mode="deep", target_types=["web_application"])
    assert "web_surface" in web
    assert "javascript_analysis" in web
    assert "form_discovery" in web
    assert "visual_capture" in web

    ip = _required_coverage(scan_mode="standard", target_types=["ip_address"])
    assert "service_discovery" in ip
    assert "visual_capture" not in ip


def test_read_recon_exposes_required_coverage_from_run_record(tmp_path: Path) -> None:
    (tmp_path / "run.json").write_text(
        json.dumps(
            {
                "scan_mode": "standard",
                "scan_target_types": ["web_application"],
            }
        ),
        encoding="utf-8",
    )
    document = read_recon(tmp_path)
    assert document["required_coverage"] == _required_coverage(
        scan_mode="standard", target_types=["web_application"]
    )


@pytest.mark.asyncio
async def test_recon_coverage_is_persisted_and_reports_gaps(tmp_path: Path) -> None:
    ctx = ToolContext(
        context={
            "state_dir": tmp_path / ".state",
            "agent_id": "mapper",
            "scan_mode": "deep",
            "scan_target_types": ["web_application"],
        },
        tool_name="record_recon_coverage",
        tool_call_id="test",
        tool_arguments="{}",
    )
    result = json.loads(
        await record_recon_coverage.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "coverage_json": json.dumps(
                        [
                            {
                                "category": "asset_discovery",
                                "status": "completed",
                                "tools": ["subfinder", "crt.sh"],
                                "evidence": "12 candidates recorded",
                            },
                            {
                                "category": "javascript_analysis",
                                "status": "not_applicable",
                                "reason": "No JavaScript resources were returned by the API target",
                            },
                        ]
                    )
                }
            ),
        )
    )
    assert result["success"]

    missing_evidence = json.loads(
        await record_recon_coverage.on_invoke_tool(
            ctx,
            json.dumps(
                {
                    "coverage_json": json.dumps(
                        [
                            {
                                "category": "live_probe",
                                "status": "completed",
                                "tools": ["httpx"],
                            }
                        ]
                    )
                }
            ),
        )
    )
    assert missing_evidence["success"] is False
    assert "evidence summary" in missing_evidence["error"]

    listed = json.loads(await list_recon_coverage.on_invoke_tool(ctx, "{}"))
    assert listed["complete"] is False
    assert "live_probe" in listed["missing"]
    assert any(entry["category"] == "asset_discovery" for entry in listed["entries"])


def test_finalize_recon_requires_coverage_contract_for_live_deep_scan(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = run_dir / ".state"
    _save(
        run_dir,
        [
            ReconObservation(
                kind="endpoint", value="https://example.com", source="httpx"
            ).model_dump()
        ],
        "recon",
    )

    result = _finalize_recon_sync(
        run_dir,
        state_dir,
        agent_id="root",
        agent_name="Root Agent",
        required_coverage=["asset_discovery", "live_probe"],
    )

    assert result["success"] is False
    assert result["missing_coverage"] == ["asset_discovery", "live_probe"]


def test_finalize_recon_persists_coverage_in_completion_marker(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = run_dir / ".state"
    _save(
        run_dir,
        [
            ReconObservation(
                kind="endpoint", value="https://example.com", source="httpx"
            ).model_dump()
        ],
        "recon",
    )
    _save_coverage(
        run_dir,
        [
            {
                "category": "asset_discovery",
                "status": "completed",
                "tools": ["subfinder"],
                "evidence": "12 candidate hosts recorded in recon.json",
            }
        ],
        "mapper",
    )

    result = _finalize_recon_sync(
        run_dir,
        state_dir,
        agent_id="root",
        agent_name="Root Agent",
        required_coverage=["asset_discovery"],
    )

    assert result["success"] is True
    marker = json.loads((run_dir / "recon_complete.json").read_text(encoding="utf-8"))
    assert marker["required_coverage"] == ["asset_discovery"]
    assert marker["coverage"][0]["category"] == "asset_discovery"


def test_one_screenshot_covers_service_and_alias_records(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = run_dir / ".state"
    _save(
        run_dir,
        [
            ReconObservation(
                kind="service",
                value="https://live.example.com/",
                source="direct probe",
                scope="in_scope",
                alive="alive",
                status_code=200,
            ).model_dump()
            | {"screenshot": "capture.png"},
            ReconObservation(
                kind="endpoint",
                value="https://live.example.com/api/health",
                source="httpx",
                scope="in_scope",
                alive="alive",
                status_code=200,
            ).model_dump(),
        ],
        "recon",
    )

    result = _finalize_recon_sync(
        run_dir,
        state_dir,
        agent_id="root",
        agent_name="Root Agent",
    )

    assert result["success"] is True


@pytest.mark.asyncio
async def test_finalize_recon_is_root_only_and_sets_context_marker(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = run_dir / ".state"
    entry = ReconObservation(kind="service", value="443/tcp", source="scanner").model_dump()
    _save(run_dir, [entry], "recon")
    ctx = ToolContext(
        context={"state_dir": state_dir, "agent_id": "root", "parent_id": None},
        tool_name="finalize_recon",
        tool_call_id="test",
        tool_arguments="{}",
    )

    result = json.loads(await finalize_recon.on_invoke_tool(ctx, "{}"))

    assert result["success"] is True
    assert ctx.context["recon_finalized"] is True


@pytest.mark.asyncio
async def test_finalize_recon_waits_for_active_mapper(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    state_dir = run_dir / ".state"
    _save(
        run_dir,
        [ReconObservation(kind="service", value="443/tcp", source="recon").model_dump()],
        "recon",
    )
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root", parent_id=None, role="root")
    await coordinator.register("mapper", "Recon mapper", parent_id="root", role="recon")
    ctx = ToolContext(
        context={
            "state_dir": state_dir,
            "agent_id": "root",
            "parent_id": None,
            "coordinator": coordinator,
        },
        tool_name="finalize_recon",
        tool_call_id="test",
        tool_arguments="{}",
    )

    result = json.loads(await finalize_recon.on_invoke_tool(ctx, "{}"))

    assert result["success"] is False
    assert "still active" in result["error"]


@pytest.mark.asyncio
async def test_screenshot_is_copied_before_sandbox_disappears(tmp_path: Path) -> None:
    payload = b"\x89PNG\r\n\x1a\nimage"

    class Session:
        async def read(self, _path: Path) -> io.BytesIO:
            return io.BytesIO(payload)

    name = await _copy_screenshot(Session(), tmp_path, "/workspace/capture.png")
    assert (tmp_path / "recon_screenshots" / name).read_bytes() == payload
    for path in ["/etc/passwd", "C:/secret.png", "/workspace/../secret.png", "https://host/a.png"]:
        with pytest.raises(ValueError, match="under /workspace"):
            await _copy_screenshot(Session(), tmp_path, path)


@pytest.mark.asyncio
async def test_tool_retains_observation_when_capture_is_missing(tmp_path: Path) -> None:
    ctx = ToolContext(
        context={"state_dir": tmp_path / ".state", "agent_id": "recon"},
        tool_name="record_recon",
        tool_call_id="test",
        tool_arguments="{}",
    )
    entry = {
        "kind": "subdomain",
        "value": "https://example.com",
        "source": "browser",
        "alive": "alive",
        "screenshot_path": "/workspace/missing.png",
    }
    result = json.loads(
        await record_recon.on_invoke_tool(
            ctx, json.dumps({"observations_json": json.dumps([entry])})
        )
    )
    assert result["success"]
    assert result["warnings"]
    assert read_recon(tmp_path)["entries"][0]["alive"] == "alive"
