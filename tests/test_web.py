"""Tests for the browser-first local runtime."""

from __future__ import annotations

import asyncio
import json

import pytest

from strix.interface.web import WebRuntime, parse_web_arguments


def test_web_arguments_include_fresh_interactive_run_fields() -> None:
    """The setup path passes this Namespace to the shared scan preparation."""
    args, _server_args = parse_web_arguments([])

    assert args.resume is None
    assert args.non_interactive is False


def test_web_arguments_accept_a_restricted_lan_listener() -> None:
    args, _server_args = parse_web_arguments(
        ["--host", "0.0.0.0", "--allow-network", "192.168.16.0/24"]
    )

    assert args.host == "0.0.0.0"
    assert [str(network) for network in args.allowed_networks] == ["192.168.16.0/24"]


def test_web_projects_persist_their_separate_scope(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    args, _ = parse_web_arguments([])
    runtime = WebRuntime(args)

    created = runtime.web_command("project.create", {"name": "Portal staging"})
    project_id = created["project"]["id"]
    runtime.web_command("setup.add_target", {"target": "https://portal.example.test"})

    state = runtime.web_state()["state"]
    assert state["active_project_id"] == project_id
    assert state["targets"] == ["https://portal.example.test"]

    restored = WebRuntime(args).web_state()["state"]
    assert restored["active_project_name"] == "Portal staging"
    assert restored["targets"] == ["https://portal.example.test"]


def test_web_migrates_finished_project_runs_from_legacy_global_storage(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    run_name = "portal-example_1234"
    project_id = "legacy-project"
    legacy_run = tmp_path / "strix_runs" / run_name
    legacy_run.mkdir(parents=True)
    (legacy_run / "run.json").write_text(
        json.dumps({"status": "completed", "project_id": project_id}), encoding="utf-8"
    )
    (tmp_path / "strix_runs" / ".web-projects.json").write_text(
        json.dumps(
            {
                "active_project_id": project_id,
                "projects": [
                    {
                        "id": project_id,
                        "name": "Portal",
                        "targets": ["https://portal.example.test"],
                        "run_names": [run_name],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    args, _ = parse_web_arguments([])
    runtime = WebRuntime(args)

    assert (legacy_run / "run.json").is_file()  # Migration never removes the source artifact.
    assert (tmp_path / "strix_runs" / "projects" / project_id / run_name / "run.json").is_file()
    assert runtime._project_runs_dir() == tmp_path / "strix_runs" / "projects" / project_id
    assert runtime.web_state()["state"]["projects"][0]["isolated_storage"] is True


def test_web_hub_can_stop_its_own_active_worker(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    args, _ = parse_web_arguments(["--target", "https://example.test"])
    runtime = WebRuntime(args)
    project = runtime._active_project()
    assert project is not None
    project["run_names"].append("example-test_stop")

    class Process:
        pid = 4242

        def __init__(self) -> None:
            self.received: list[int] = []

        @staticmethod
        def poll() -> None:
            return None

        def send_signal(self, signum: int) -> None:
            self.received.append(signum)

        def terminate(self) -> None:
            self.received.append(-1)

    process = Process()
    runtime._workers["example-test_stop"] = process  # type: ignore[assignment]

    result = runtime.web_command("run.stop", {"run_name": "example-test_stop"})

    assert result == {"stopping": True, "run_name": "example-test_stop"}
    assert "example-test_stop" in runtime._stopping_workers
    assert process.received


@pytest.mark.asyncio
async def test_web_hub_starts_an_isolated_headless_worker(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The hub must keep serving while a fresh run is delegated to a worker."""
    monkeypatch.chdir(tmp_path)
    args, _ = parse_web_arguments(["--target", "https://example.test", "--scan-mode", "quick"])
    runtime = WebRuntime(args)
    runtime._loop = asyncio.get_running_loop()

    async def verified(_model: str) -> None:
        return None

    launched: list[list[str]] = []

    class Process:
        pid = 4242

        @staticmethod
        def poll() -> None:
            return None

    spawn_options: dict[str, object] = {}

    def spawn(command, **kwargs):
        launched.append(command)
        spawn_options.update(kwargs)
        return Process()

    monkeypatch.setattr("strix.interface.web.preflight_model_connection", verified)
    monkeypatch.setattr("strix.interface.web.subprocess.Popen", spawn)
    monkeypatch.setenv("STRIX_LLM", "test/model")

    result = await asyncio.to_thread(runtime.web_command, "setup.start", {})

    assert result["started"] is True
    assert result["pid"] == 4242
    assert launched[0][:4] == [
        launched[0][0],
        "-m",
        "strix.interface.main",
        "-n",
    ]
    assert "--run-name" in launched[0]
    assert launched[0][launched[0].index("--target") : launched[0].index("--target") + 2] == [
        "--target",
        "https://example.test",
    ]
    state = runtime.web_state()["state"]
    assert state["targets"] == ["https://example.test"]
    assert state["active_project_name"] == "Imported scope"
    assert spawn_options["env"]["STRIX_PROJECT_ID"] == state["active_project_id"]
    assert spawn_options["env"]["STRIX_RUNS_DIR"] == str(
        tmp_path / "strix_runs" / "projects" / state["active_project_id"]
    )


@pytest.mark.asyncio
async def test_web_hub_continues_a_finished_run_in_its_own_session(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    args, _ = parse_web_arguments(["--target", "https://example.test"])
    runtime = WebRuntime(args)
    runtime._loop = asyncio.get_running_loop()
    project = runtime._active_project()
    assert project is not None
    run_name = "example-test_finished"
    project["run_names"].append(run_name)
    run_dir = runtime._project_runs_dir(project) / run_name
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text('{"status": "completed"}', encoding="utf-8")
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    (state_dir / "agents.db").write_bytes(b"session")

    async def verified(_model: str) -> None:
        return None

    launched: list[list[str]] = []

    class Process:
        pid = 2026

        @staticmethod
        def poll() -> None:
            return None

    def spawn(command, **_kwargs):
        launched.append(command)
        return Process()

    monkeypatch.setattr("strix.interface.web.preflight_model_connection", verified)
    monkeypatch.setattr("strix.interface.web.subprocess.Popen", spawn)
    monkeypatch.setenv("STRIX_LLM", "test/model")

    result = await asyncio.to_thread(
        runtime.web_command,
        "run.chat",
        {"run_name": run_name, "message": "Explain the validated findings."},
    )

    assert result["started"] is True
    assert result["pid"] == 2026
    assert launched[0][1:] == [
        "-m",
        "strix.interface.main",
        "-n",
        "--resume",
        run_name,
        "--chat",
        "--instruction",
        "Explain the validated findings.",
        "--max-turns",
        str(runtime.max_turns),
    ]
