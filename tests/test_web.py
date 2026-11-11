"""Tests for the browser-first local runtime."""

from __future__ import annotations

import asyncio
import json

import pytest

from strix.config import loader
from strix.interface.web import WebRuntime, parse_web_arguments


def _clear_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start from a clean LLM connection and register teardown for every key.

    ``monkeypatch.delenv`` does not record an undo entry for an already-missing
    variable, so a value written by the code under test would leak into the
    next test. Setting a valid empty value always registers the restore.
    """
    monkeypatch.setenv("STRIX_LLM", "")
    monkeypatch.setenv("LLM_API_KEY", "")
    monkeypatch.setenv("LLM_API_BASE", "")
    monkeypatch.setenv("LLM_EXTRA_HEADERS", "{}")
    monkeypatch.setenv("STRIX_LLM_MAX_RETRIES", "5")
    monkeypatch.setenv("STRIX_LLM_RATE_LIMIT_REQUESTS", "0")
    monkeypatch.setenv("STRIX_LLM_RATE_LIMIT_UNIT", "minutes")


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


def test_web_add_target_creates_default_project_for_fresh_hub(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first Enter/Add target action works without opening Projects first."""
    monkeypatch.chdir(tmp_path)
    args, _ = parse_web_arguments([])
    runtime = WebRuntime(args)

    assert runtime.web_state()["state"]["active_project_id"] is None

    result = runtime.web_command("setup.add_target", {"target": "https://portal.example.test"})

    state = runtime.web_state()["state"]
    assert result == {"target": "https://portal.example.test", "total": 1}
    assert state["active_project_name"] == "New project"
    assert state["targets"] == ["https://portal.example.test"]


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


def test_web_hub_can_stop_its_own_active_worker(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
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


@pytest.mark.asyncio
async def test_web_hub_resumes_an_interrupted_run(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    args, _ = parse_web_arguments(["--target", "https://example.test"])
    runtime = WebRuntime(args)
    runtime._loop = asyncio.get_running_loop()
    project = runtime._active_project()
    assert project is not None
    run_name = "example-test_interrupted"
    project["run_names"].append(run_name)
    run_dir = runtime._project_runs_dir(project) / run_name
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text('{"status": "interrupted"}', encoding="utf-8")
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    (state_dir / "agents.db").write_bytes(b"session")

    async def verified(_model: str) -> None:
        return None

    launched: list[list[str]] = []

    class Process:
        pid = 2027

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
        "run.resume",
        {"run_name": run_name},
    )

    assert result["started"] is True
    assert result["pid"] == 2027
    assert launched[0][1:] == [
        "-m",
        "strix.interface.main",
        "-n",
        "--resume",
        run_name,
        "--max-turns",
        str(runtime.max_turns),
    ]


@pytest.mark.asyncio
async def test_web_hub_resumes_a_failed_run(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A provider-side failure must not force the operator to start over."""
    monkeypatch.chdir(tmp_path)
    args, _ = parse_web_arguments(["--target", "https://example.test"])
    runtime = WebRuntime(args)
    runtime._loop = asyncio.get_running_loop()
    project = runtime._active_project()
    assert project is not None
    run_name = "example-test_failed"
    project["run_names"].append(run_name)
    run_dir = runtime._project_runs_dir(project) / run_name
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text('{"status": "failed"}', encoding="utf-8")
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    (state_dir / "agents.db").write_bytes(b"session")

    async def verified(_model: str) -> None:
        return None

    launched: list[list[str]] = []

    class Process:
        pid = 2028

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
        "run.resume",
        {"run_name": run_name},
    )

    assert result["started"] is True
    assert result["pid"] == 2028
    assert launched[0][1:] == [
        "-m",
        "strix.interface.main",
        "-n",
        "--resume",
        run_name,
        "--max-turns",
        str(runtime.max_turns),
    ]


def test_web_resume_still_rejects_a_completed_run(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    args, _ = parse_web_arguments(["--target", "https://example.test"])
    runtime = WebRuntime(args)
    project = runtime._active_project()
    assert project is not None
    run_name = "example-test_completed"
    project["run_names"].append(run_name)
    run_dir = runtime._project_runs_dir(project) / run_name
    state_dir = run_dir / ".state"
    state_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text('{"status": "completed"}', encoding="utf-8")
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")
    (state_dir / "agents.db").write_bytes(b"session")

    with pytest.raises(ValueError, match="interrupted or failed"):
        runtime.web_command("run.resume", {"run_name": run_name})


def test_web_saves_custom_model_headers_without_echoing_values(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Header values stay in the hub; the setup screen only gets names back."""
    _clear_llm_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    config_path = tmp_path / "cli-config.json"
    monkeypatch.setattr(loader, "_override", config_path)
    monkeypatch.setattr(loader, "_cached", None)
    args, _ = parse_web_arguments([])
    runtime = WebRuntime(args)

    saved = runtime.web_command(
        "settings.save_llm",
        {
            "model": "openai/gpt-5",
            "extra_headers": [
                {"name": "X-Tenant", "value": "acme"},
                {"name": "X-Feature-Key", "value": "svc-secret"},
            ],
        },
    )

    assert saved["llm_extra_headers"] == ["X-Feature-Key", "X-Tenant"]
    state = runtime.web_state()["state"]
    assert state["llm_extra_headers"] == ["X-Feature-Key", "X-Tenant"]
    assert "acme" not in json.dumps(state)
    assert "svc-secret" not in json.dumps(state)

    persisted = json.loads(config_path.read_text(encoding="utf-8"))
    assert json.loads(persisted["env"]["LLM_EXTRA_HEADERS"]) == {
        "X-Tenant": "acme",
        "X-Feature-Key": "svc-secret",
    }

    # A new process reads the same headers back from the JSON file even though
    # the file stores every value as a string.
    monkeypatch.delenv("LLM_EXTRA_HEADERS")
    monkeypatch.delenv("STRIX_LLM")
    monkeypatch.setattr(loader, "_cached", None)
    assert loader.load_settings().llm.extra_headers == {
        "X-Tenant": "acme",
        "X-Feature-Key": "svc-secret",
    }


def test_web_keeps_stored_header_value_when_the_row_is_blank(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_llm_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(loader, "_override", tmp_path / "cli-config.json")
    monkeypatch.setattr(loader, "_cached", None)
    args, _ = parse_web_arguments([])
    runtime = WebRuntime(args)

    runtime.web_command(
        "settings.save_llm",
        {
            "model": "openai/gpt-5",
            "extra_headers": [{"name": "X-Tenant", "value": "acme"}],
        },
    )

    # A blank value means "keep the stored secret", not "clear the header".
    saved = runtime.web_command(
        "settings.save_llm",
        {
            "model": "openai/gpt-5",
            "extra_headers": [{"name": "X-Tenant", "value": ""}],
        },
    )
    assert saved["llm_extra_headers"] == ["X-Tenant"]
    assert loader.load_settings().llm.extra_headers == {"X-Tenant": "acme"}

    # Dropping the row removes the header entirely.
    saved = runtime.web_command("settings.save_llm", {"model": "openai/gpt-5", "extra_headers": []})
    assert saved["llm_extra_headers"] == []
    assert loader.load_settings().llm.extra_headers == {}

    # A fresh process must decode the persisted JSON string back to a mapping.
    monkeypatch.delenv("LLM_EXTRA_HEADERS")
    monkeypatch.delenv("STRIX_LLM")
    monkeypatch.setattr(loader, "_cached", None)
    assert loader.load_settings().llm.extra_headers == {}


def test_web_rejects_unsafe_custom_model_headers(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_llm_env(monkeypatch)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(loader, "_override", tmp_path / "cli-config.json")
    monkeypatch.setattr(loader, "_cached", None)
    args, _ = parse_web_arguments([])
    runtime = WebRuntime(args)

    with pytest.raises(ValueError, match="invalid header name"):
        runtime.web_command(
            "settings.save_llm",
            {
                "model": "openai/gpt-5",
                "extra_headers": [{"name": "X Tenant", "value": "acme"}],
            },
        )

    with pytest.raises(ValueError, match="needs a value"):
        runtime.web_command(
            "settings.save_llm",
            {
                "model": "openai/gpt-5",
                "extra_headers": [{"name": "X-Tenant", "value": ""}],
            },
        )

    with pytest.raises(ValueError, match="control characters"):
        runtime.web_command(
            "settings.save_llm",
            {
                "model": "openai/gpt-5",
                "extra_headers": [{"name": "X-Tenant", "value": "acme\r\nX-Injected: 1"}],
            },
        )
