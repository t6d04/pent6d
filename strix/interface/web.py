"""Browser-first local hub for starting and reviewing Pent6d scans.

``pent6d web`` owns one local Viewer server. Each requested scan is spawned as
an isolated headless worker, so a new scan never replaces the viewer or shares
the in-process agent/report state of another scan. The viewer reads every
worker's normal ``strix_runs/<name>`` artifacts, exactly like ``strix view``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import webbrowser
from copy import deepcopy
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from pathlib import Path
from typing import Any

from rich.console import Console

from strix.config import (
    apply_config_override,
    load_settings,
    native_web_search_supported,
    save_llm_connection,
    save_web_search_settings,
)
from strix.core.paths import run_record_path, runs_base_dir, runtime_state_dir
from strix.interface.scan_setup import build_targets_info, preflight_model_connection
from strix.interface.utils import generate_run_name
from strix.interface.viewer.server import authorized_url, bundle_is_built, serve


_SCAN_MODES = frozenset({"quick", "standard", "deep"})
_SCOPE_MODES = frozenset({"auto", "diff", "full"})
_PROJECTS_FILENAME = ".web-projects.json"
_TERMINAL_RUN_STATUSES = frozenset({"completed", "failed", "interrupted", "stopped"})
_ClientNetwork = IPv4Network | IPv6Network

logger = logging.getLogger(__name__)


class WebRuntime:
    """Local control plane for the persistent browser viewer.

    A scan is deliberately *not* run on this process's event loop. Strix uses
    module-level report state while a scan is active, which makes concurrent
    in-process runs unsafe. Worker processes give every run its own agent
    graph, Docker session, report state, and failure boundary.
    """

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.RLock()
        initial_targets = [
            str(target["original"])
            for target in args.targets_info
            if isinstance(target, dict) and target.get("original")
        ]
        self.max_turns = args.max_turns
        self.error: str | None = None
        self.messages: list[dict[str, str]] = []
        self._message_id = 1
        self._workers: dict[str, subprocess.Popen[bytes]] = {}
        self._stopping_workers: set[str] = set()
        self.projects, self.active_project_id = self._load_projects()
        created_project = self._migrate_legacy_project_artifacts()
        if not self.projects:
            legacy_runs = self._legacy_run_names()
            if legacy_runs:
                history = self._new_project("Imported history")
                history["run_names"] = legacy_runs
                history["legacy_storage"] = True
                self.projects.append(history)
                self.active_project_id = str(history["id"])
                created_project = True
        # ``strix web --target ...`` remains convenient, but the imported
        # scope is explicitly named and retained as a project from the start.
        if initial_targets:
            project = self._new_project(
                "Imported scope",
                targets=initial_targets,
                instruction=(args.instruction or "").strip(),
                scan_mode=args.scan_mode,
                max_budget_usd=args.max_budget_usd,
                scope_mode=args.scope_mode,
                diff_base=args.diff_base,
            )
            self.projects.append(project)
            self.active_project_id = str(project["id"])
            created_project = True
        if created_project:
            self._save_projects()

    @staticmethod
    def _project_path() -> Path:
        return runs_base_dir() / _PROJECTS_FILENAME

    @staticmethod
    def _legacy_run_names() -> list[str]:
        base = runs_base_dir()
        if not base.is_dir():
            return []
        return sorted(
            (child.name for child in base.iterdir() if run_record_path(child).is_file()),
            reverse=True,
        )

    def _project_runs_dir(self, project: dict[str, Any] | None = None) -> Path:
        """Return the isolated artifact root for one project.

        The imported-history project continues to point to the historic global
        root. Every newly created project gets a dedicated subtree from its
        first run; older projects are switched after safe artifact migration.
        """
        selected = project or self._active_project()
        if selected is None or selected.get("artifact_storage") != "project":
            return runs_base_dir()
        return runs_base_dir() / "projects" / str(selected["id"])

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def _new_project(
        self,
        name: str,
        *,
        targets: list[str] | None = None,
        instruction: str = "",
        scan_mode: str = "deep",
        max_budget_usd: float | None = None,
        scope_mode: str = "auto",
        diff_base: str | None = None,
    ) -> dict[str, Any]:
        now = self._now()
        return {
            "id": secrets.token_hex(8),
            "name": name,
            "targets": list(targets or []),
            "instruction": instruction,
            "scan_mode": scan_mode,
            "max_budget_usd": max_budget_usd,
            "scope_mode": scope_mode,
            "diff_base": diff_base,
            "run_names": [],
            # Old browser-project records predate physical artifact isolation.
            # New records are isolated from their very first run.
            "artifact_storage": "project",
            "created_at": now,
            "updated_at": now,
        }

    def _load_projects(self) -> tuple[list[dict[str, Any]], str | None]:
        path = self._project_path()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return [], None
        if not isinstance(data, dict):
            return [], None
        projects = data.get("projects")
        if not isinstance(projects, list):
            return [], None
        valid = [project for project in projects if self._valid_project(project)]
        for project in valid:
            project["targets"] = [
                target for target in project["targets"] if isinstance(target, str)
            ]
            project.setdefault("instruction", "")
            project.setdefault("scan_mode", "deep")
            project.setdefault("max_budget_usd", None)
            project.setdefault("scope_mode", "auto")
            project.setdefault("diff_base", None)
            project.setdefault("run_names", [])
            project.setdefault("created_at", self._now())
            project.setdefault("updated_at", self._now())
        active = data.get("active_project_id")
        active_id = active if isinstance(active, str) else None
        if active_id not in {str(project["id"]) for project in valid}:
            active_id = str(valid[0]["id"]) if valid else None
        return valid, active_id

    def _migrate_legacy_project_artifacts(self) -> bool:
        """Copy finished pre-isolation project runs into their project store.

        Releases that first introduced projects stored their artifacts at the
        global ``strix_runs/<run>`` root. Later releases correctly isolate new
        runs under ``projects/<project-id>``, but must not make existing
        projects appear empty. Copies leave the original artifacts untouched
        and a project starts reading the new location only after every listed
        run is present there. In-progress and malformed runs intentionally stay
        on legacy storage until they are terminal.
        """
        legacy_base = runs_base_dir()
        changed = False
        for project in self.projects:
            if (
                project.get("legacy_storage") is True
                or project.get("artifact_storage") == "project"
            ):
                continue
            run_names = [name for name in project.get("run_names", []) if isinstance(name, str)]
            if not run_names:
                project["artifact_storage"] = "project"
                self._touch(project)
                changed = True
                continue

            destination_base = legacy_base / "projects" / str(project["id"])
            sources: list[tuple[Path, Path]] = []
            ready = True
            for run_name in run_names:
                # Project records are local metadata, but still reject paths
                # that could escape either artifact root if manually edited.
                if Path(run_name).name != run_name or run_name in {"", ".", ".."}:
                    ready = False
                    break
                source = legacy_base / run_name
                destination = destination_base / run_name
                if run_record_path(destination).is_file():
                    continue
                try:
                    record = json.loads(run_record_path(source).read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    ready = False
                    break
                if (
                    not isinstance(record, dict)
                    or record.get("status") not in _TERMINAL_RUN_STATUSES
                ):
                    ready = False
                    break
                sources.append((source, destination))

            if not ready:
                continue
            try:
                for source, destination in sources:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    temporary = destination.with_name(
                        f".{destination.name}.migrating-{secrets.token_hex(4)}"
                    )
                    shutil.copytree(source, temporary)
                    temporary.replace(destination)
            except OSError:
                # The project keeps reading its historic root. A later hub
                # startup can retry without losing or replacing any artifact.
                continue

            project["artifact_storage"] = "project"
            self._touch(project)
            changed = True
        return changed

    @staticmethod
    def _valid_project(project: Any) -> bool:
        return (
            isinstance(project, dict)
            and isinstance(project.get("id"), str)
            and isinstance(project.get("name"), str)
            and isinstance(project.get("targets"), list)
        )

    def _save_projects(self) -> None:
        path = self._project_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"active_project_id": self.active_project_id, "projects": self.projects}
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        temporary.replace(path)

    def _active_project(self) -> dict[str, Any] | None:
        return next(
            (project for project in self.projects if project["id"] == self.active_project_id), None
        )

    def _require_project(self) -> dict[str, Any]:
        project = self._active_project()
        if project is None:
            raise ValueError("Create and select a project before configuring a scan")
        return project

    def _ensure_setup_project(self) -> dict[str, Any]:
        """Return the active setup project, creating one for a fresh hub.

        The browser setup screen is intentionally usable without a CLI
        ``--target``.  In that path there is no project yet, so the first
        ``Add target``/Enter action must not fail merely because the operator
        has not visited the Projects tab first.  Explicit project selection is
        still preserved when projects already exist.
        """
        project = self._active_project()
        if project is not None:
            return project

        project = self._new_project("New project")
        self.projects.append(project)
        self.active_project_id = str(project["id"])
        self._save_projects()
        self._add_message("Created project New project for the new scan.")
        return project

    def _project_summary(self, project: dict[str, Any]) -> dict[str, Any]:
        run_names = [name for name in project.get("run_names", []) if isinstance(name, str)]
        run_names.reverse()
        return {
            "id": project["id"],
            "name": project["name"],
            "targets": list(project.get("targets", [])),
            "run_names": run_names,
            "run_count": len(run_names),
            "updated_at": project.get("updated_at"),
            "isolated_storage": project.get("artifact_storage") == "project",
        }

    def _touch(self, project: dict[str, Any]) -> None:
        project["updated_at"] = self._now()

    def _add_message(self, text: str, level: str = "info") -> None:
        self.messages.append({"id": str(self._message_id), "text": text, "level": level})
        self._message_id += 1
        del self.messages[:-40]

    def _worker_state(self) -> list[dict[str, Any]]:
        workers: list[dict[str, Any]] = []
        for run_name, process in list(self._workers.items()):
            return_code = process.poll()
            workers.append(
                {
                    "run_name": run_name,
                    "pid": process.pid,
                    "state": (
                        "exited"
                        if return_code is not None
                        else "stopping"
                        if run_name in self._stopping_workers
                        else "running"
                    ),
                    "return_code": return_code,
                }
            )
        return workers

    def web_state(self) -> dict[str, Any]:
        """Return redacted setup state plus the workers known to this hub."""
        with self._lock:
            settings = load_settings()
            llm = settings.llm
            project = self._active_project()
            return {
                "enabled": True,
                "state": {
                    # Kept for compatibility with the original setup screen.
                    # This hub remains reusable after every submitted run.
                    "setup_mode": True,
                    "scan_started": False,
                    "scan_state": "hub",
                    "targets": list(project.get("targets", [])) if project else [],
                    "instruction": str(project.get("instruction", "")) if project else "",
                    "scan_mode": project.get("scan_mode", "deep") if project else "deep",
                    "max_budget_usd": project.get("max_budget_usd") if project else None,
                    "scope_mode": project.get("scope_mode", "auto") if project else "auto",
                    "diff_base": project.get("diff_base") if project else None,
                    "active_project_id": self.active_project_id,
                    "active_project_name": project.get("name") if project else None,
                    "projects": [self._project_summary(item) for item in self.projects],
                    "model": llm.model or "",
                    "api_key_configured": bool(llm.api_key),
                    "api_base": llm.api_base or "",
                    "llm_rate_limit_requests": llm.rate_limit_requests,
                    "llm_rate_limit_unit": llm.rate_limit_unit,
                    "llm_max_retries": llm.max_retries,
                    # Only names leave the hub: header values often carry
                    # credentials and are never echoed back to the browser.
                    "llm_extra_headers": sorted((llm.extra_headers or {}).keys()),
                    "web_search_provider": settings.integrations.web_search_provider,
                    "native_web_search_available": native_web_search_supported(llm),
                    "model_warning": "",
                    "messages": list(self.messages),
                    "error": self.error,
                    "workers": self._worker_state(),
                },
            }

    def web_command(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Handle a capability-authorized browser command on the hub loop."""
        handlers = {
            "setup.add_target": self._add_target,
            "setup.remove_target": self._remove_target,
            "setup.set_instruction": self._set_instruction,
            "setup.set_options": self._set_options,
            "project.create": self._create_project,
            "project.select": self._select_project,
            "run.chat": self._chat_run,
            "run.resume": self._resume_run,
            "run.stop": self._stop_run,
            "settings.save_llm": self._save_llm,
            "settings.save_web_search": self._save_web_search,
            "setup.start": self._start,
        }
        handler = handlers.get(command)
        if handler is None:
            raise ValueError(f"Unknown command: {command}")
        with self._lock:
            self.error = None
            return handler(payload)

    @staticmethod
    def _required_string(payload: dict[str, Any], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} is required")
        return value.strip()

    def _add_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        # Adding the first authorized target is the natural entry point for
        # the setup screen.  Do not require a separate project-creation step.
        project = self._ensure_setup_project()
        target = self._required_string(payload, "target")
        targets = project["targets"]
        if target not in targets:
            targets.append(target)
            self._touch(project)
            self._save_projects()
        return {"target": target, "total": len(targets)}

    def _remove_target(self, payload: dict[str, Any]) -> dict[str, Any]:
        project = self._require_project()
        target = self._required_string(payload, "target")
        try:
            project["targets"].remove(target)
        except ValueError:
            raise ValueError("Target is not part of this scan") from None
        self._touch(project)
        self._save_projects()
        return {"target": target, "total": len(project["targets"])}

    def _set_instruction(self, payload: dict[str, Any]) -> dict[str, Any]:
        project = self._require_project()
        instruction = payload.get("instruction", "")
        if not isinstance(instruction, str):
            raise TypeError("instruction must be a string")
        project["instruction"] = instruction.strip()
        self._touch(project)
        self._save_projects()
        return {"instruction": project["instruction"]}

    def _set_options(self, payload: dict[str, Any]) -> dict[str, Any]:
        project = self._require_project()
        scan_mode = payload.get("scan_mode")
        if scan_mode is not None:
            if not isinstance(scan_mode, str) or scan_mode not in _SCAN_MODES:
                raise ValueError("scan_mode must be one of: quick, standard, deep")
            project["scan_mode"] = scan_mode

        raw_budget = payload.get("max_budget_usd")
        if raw_budget is not None:
            if isinstance(raw_budget, bool) or not isinstance(raw_budget, int | float):
                raise TypeError("max_budget_usd must be a positive number or null")
            budget = float(raw_budget)
            if budget <= 0 or not budget < float("inf"):
                raise ValueError("max_budget_usd must be a positive finite number")
            project["max_budget_usd"] = budget

        scope_mode = payload.get("scope_mode")
        if scope_mode is not None:
            if not isinstance(scope_mode, str) or scope_mode not in _SCOPE_MODES:
                raise ValueError("scope_mode must be one of: auto, diff, full")
            project["scope_mode"] = scope_mode

        diff_base = payload.get("diff_base")
        if diff_base is not None:
            if not isinstance(diff_base, str):
                raise TypeError("diff_base must be a string or null")
            project["diff_base"] = diff_base.strip() or None

        self._touch(project)
        self._save_projects()

        return {
            "scan_mode": project["scan_mode"],
            "max_budget_usd": project["max_budget_usd"],
            "scope_mode": project["scope_mode"],
            "diff_base": project["diff_base"],
        }

    def _create_project(self, payload: dict[str, Any]) -> dict[str, Any]:
        name = self._required_string(payload, "name")
        if len(name) > 100:
            raise ValueError("Project name must be at most 100 characters")
        if any(str(project["name"]).casefold() == name.casefold() for project in self.projects):
            raise ValueError("A project with that name already exists")
        project = self._new_project(name)
        self.projects.append(project)
        self.active_project_id = str(project["id"])
        self._save_projects()
        self._add_message(f"Created project {name}.")
        return {"project": self._project_summary(project)}

    def _select_project(self, payload: dict[str, Any]) -> dict[str, Any]:
        project_id = self._required_string(payload, "project_id")
        project = next((item for item in self.projects if item["id"] == project_id), None)
        if project is None:
            raise ValueError("Unknown project")
        self.active_project_id = project_id
        self._save_projects()
        return {"project": self._project_summary(project)}

    def _stop_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Ask a worker started by this hub to exit and persist interruption.

        A hub intentionally only controls children it created in this process.
        Guessing a PID from an old artifact could terminate an unrelated process
        after a restart, so imported or previously launched runs remain view-only.
        """
        project = self._require_project()
        run_name = self._required_string(payload, "run_name")
        if run_name not in project.get("run_names", []):
            raise ValueError("This run is not part of the selected project")
        process = self._workers.get(run_name)
        if process is None:
            raise ValueError("Only runs started by this web hub can be stopped")
        if process.poll() is not None:
            self._stopping_workers.discard(run_name)
            raise ValueError("This run has already exited")
        if run_name in self._stopping_workers:
            return {"stopping": True, "run_name": run_name}

        self._stopping_workers.add(run_name)
        try:
            if os.name == "nt" and hasattr(signal, "CTRL_BREAK_EVENT"):
                # Workers have a separate process group, so Ctrl+Break reaches
                # just this scan and lets its SIGBREAK handler flush run.json.
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                # SIGTERM is handled by the normal CLI worker and records an
                # interrupted terminal status before it exits.
                process.terminate()
        except OSError as exc:
            self._stopping_workers.discard(run_name)
            raise RuntimeError(f"Could not stop run: {exc}") from exc
        self._add_message(f"Stopping {run_name}.")
        return {"stopping": True, "run_name": run_name}

    def _chat_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Resume one finished run for a single browser follow-up message."""
        project = self._require_project()
        run_name = self._required_string(payload, "run_name")
        message = self._required_string(payload, "message")
        if len(message) > 20_000:
            raise ValueError("message must be at most 20,000 characters")
        if run_name not in project.get("run_names", []):
            raise ValueError("This run is not part of the selected project")

        run_dir = self._project_runs_dir(project) / run_name
        # ``run_name`` comes from stored project metadata. Reject edited values
        # before composing a path, and require the persisted agent session that
        # makes a follow-up genuinely specific to this run.
        if Path(run_name).name != run_name or run_name in {"", ".", ".."}:
            raise ValueError("Invalid run name")
        if not run_record_path(run_dir).is_file():
            raise ValueError("The selected run has no saved record")
        state_dir = runtime_state_dir(run_dir)
        if not (state_dir / "agents.json").is_file() or not (state_dir / "agents.db").is_file():
            raise ValueError("This run does not have a saved agent session to continue")

        process = self._workers.get(run_name)
        if process is not None and process.poll() is None:
            raise ValueError("This run is still working. Wait for it to finish before chatting.")

        model = (load_settings().llm.model or "").strip()
        if not model:
            raise ValueError("No model configured. Save a model before sending a message.")
        loop = self._loop
        if loop is None or loop.is_closed():
            raise RuntimeError("Web runtime is not ready")
        future = asyncio.run_coroutine_threadsafe(preflight_model_connection(model), loop)
        try:
            future.result(timeout=310)
        except TimeoutError as exc:
            raise RuntimeError("Model connection timed out") from exc

        command = [
            sys.executable,
            "-m",
            "strix.interface.main",
            "-n",
            "--resume",
            run_name,
            "--chat",
            "--instruction",
            message,
        ]
        if self.max_turns:
            command.extend(["--max-turns", str(self.max_turns)])
        if self.args.config:
            command.extend(["--config", self.args.config])

        process = self._launch_worker(project, run_name, command, kind="chat")
        self._add_message(f"Continuing {run_name} with a follow-up message.")
        return {
            "started": True,
            "run_name": run_name,
            "pid": process.pid,
            "project_id": project["id"],
        }

    def _resume_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Resume an interrupted or failed scan from its persisted agent session.

        A failed run is often a provider-side model outage rather than a bad
        assessment. Its agent session is still on disk, so let the operator
        retry it once the model is back instead of forcing a fresh scan.
        """
        project = self._require_project()
        run_name = self._required_string(payload, "run_name")
        if run_name not in project.get("run_names", []):
            raise ValueError("This run is not part of the selected project")
        if Path(run_name).name != run_name or run_name in {"", ".", ".."}:
            raise ValueError("Invalid run name")

        run_dir = self._project_runs_dir(project) / run_name
        record_path = run_record_path(run_dir)
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ValueError("The selected run has no saved record") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("The selected run record is unreadable") from exc
        status = str(record.get("status", "")).lower() if isinstance(record, dict) else ""
        if status not in {"interrupted", "failed"}:
            raise ValueError("Only an interrupted or failed run can be continued")

        state_dir = runtime_state_dir(run_dir)
        if not (state_dir / "agents.json").is_file() or not (state_dir / "agents.db").is_file():
            raise ValueError("This run does not have a saved agent session to continue")

        process = self._workers.get(run_name)
        if process is not None and process.poll() is None:
            raise ValueError("This run is already being continued")

        model = (load_settings().llm.model or "").strip()
        if not model:
            raise ValueError("No model configured. Save a model before continuing the scan.")
        loop = self._loop
        if loop is None or loop.is_closed():
            raise RuntimeError("Web runtime is not ready")
        future = asyncio.run_coroutine_threadsafe(preflight_model_connection(model), loop)
        try:
            future.result(timeout=310)
        except TimeoutError as exc:
            raise RuntimeError("Model connection timed out") from exc

        command = [
            sys.executable,
            "-m",
            "strix.interface.main",
            "-n",
            "--resume",
            run_name,
        ]
        if self.max_turns:
            command.extend(["--max-turns", str(self.max_turns)])
        if self.args.config:
            command.extend(["--config", self.args.config])

        self._stopping_workers.discard(run_name)
        process = self._launch_worker(project, run_name, command, kind="resume")
        self._add_message(f"Continuing {status} run {run_name}.")
        return {
            "started": True,
            "run_name": run_name,
            "pid": process.pid,
            "project_id": project["id"],
        }

    def _save_llm(self, payload: dict[str, Any]) -> dict[str, Any]:
        model = self._required_string(payload, "model")
        api_key = payload.get("api_key")
        api_base = payload.get("api_base")
        current_llm = load_settings().llm
        rate_limit_requests = payload.get("rate_limit_requests", current_llm.rate_limit_requests)
        rate_limit_unit = payload.get("rate_limit_unit", current_llm.rate_limit_unit)
        max_retries = payload.get("max_retries", current_llm.max_retries)
        extra_headers = self._resolve_extra_headers(payload, current_llm.extra_headers)
        if api_key is not None and not isinstance(api_key, str):
            raise TypeError("api_key must be a string")
        if api_base is not None and not isinstance(api_base, str):
            raise TypeError("api_base must be a string")
        if isinstance(rate_limit_requests, bool) or not isinstance(rate_limit_requests, int):
            raise TypeError("rate_limit_requests must be a non-negative integer")
        if rate_limit_requests < 0:
            raise ValueError("rate_limit_requests must be non-negative")
        if rate_limit_unit not in {"seconds", "minutes", "hours"}:
            raise ValueError("rate_limit_unit must be one of: seconds, minutes, hours")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int):
            raise TypeError("max_retries must be a non-negative integer")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        save_llm_connection(
            model=model,
            api_key=api_key if api_key else None,
            api_base=api_base if api_base is not None else None,
            rate_limit_requests=rate_limit_requests,
            rate_limit_unit=rate_limit_unit,
            max_retries=max_retries,
            extra_headers=extra_headers,
        )
        llm = load_settings().llm
        return {
            "model": llm.model or "",
            "api_key_configured": bool(llm.api_key),
            "api_base": llm.api_base or "",
            "llm_rate_limit_requests": llm.rate_limit_requests,
            "llm_rate_limit_unit": llm.rate_limit_unit,
            "llm_max_retries": llm.max_retries,
            "llm_extra_headers": sorted((llm.extra_headers or {}).keys()),
        }

    @staticmethod
    def _resolve_extra_headers(
        payload: dict[str, Any], current: dict[str, str] | None
    ) -> dict[str, str] | None:
        """Merge the setup screen's header rows with the stored values.

        The browser only ever sees header names. A row with a blank value keeps
        the stored value for that name, which lets an operator remove a header
        (drop its row) or replace its secret without the old value being sent
        back to the page. ``None`` means "leave the stored headers untouched".
        """
        rows = payload.get("extra_headers")
        if rows is None:
            return None
        if not isinstance(rows, list):
            raise TypeError("extra_headers must be a list of {name, value} rows")

        stored = {name.casefold(): (name, value) for name, value in (current or {}).items()}
        resolved: dict[str, str] = {}
        seen: set[str] = set()
        for row in rows:
            if not isinstance(row, dict):
                raise TypeError("each extra header must be an object with name and value")
            raw_name = row.get("name")
            raw_value = row.get("value", "")
            if not isinstance(raw_name, str) or not raw_name.strip():
                raise ValueError("each extra header needs a name")
            if not isinstance(raw_value, str):
                raise TypeError(f"header {raw_name!r} value must be a string")
            name = raw_name.strip()
            folded = name.casefold()
            if folded in seen:
                raise ValueError(f"duplicate extra header: {name}")
            seen.add(folded)
            value = raw_value.strip()
            if value:
                resolved[name] = value
                continue
            existing = stored.get(folded)
            if existing is None:
                raise ValueError(f"extra header {name!r} needs a value")
            resolved[existing[0]] = existing[1]
        return resolved

    def _save_web_search(self, payload: dict[str, Any]) -> dict[str, Any]:
        provider = self._required_string(payload, "provider")
        if provider not in {"auto", "native", "ddgs", "exa", "perplexity"}:
            raise ValueError("provider must be one of: auto, native, ddgs, exa, perplexity")
        save_web_search_settings(provider=provider)  # type: ignore[arg-type]
        settings = load_settings()
        return {
            "web_search_provider": settings.integrations.web_search_provider,
            "native_web_search_available": native_web_search_supported(settings.llm),
        }

    def _start(self, payload: dict[str, Any]) -> dict[str, Any]:
        project = self._require_project()
        if payload.get("mount_working_dir", False):
            raise ValueError("The web hub requires at least one explicit target")
        targets = [target for target in project["targets"] if isinstance(target, str)]
        if not targets:
            raise ValueError("No target set. Add a target first.")
        model = (load_settings().llm.model or "").strip()
        if not model:
            raise ValueError("No model configured. Save a model before starting the scan.")

        loop = self._loop
        if loop is None or loop.is_closed():
            raise RuntimeError("Web runtime is not ready")
        future = asyncio.run_coroutine_threadsafe(preflight_model_connection(model), loop)
        try:
            future.result(timeout=310)
        except TimeoutError as exc:
            raise RuntimeError("Model connection timed out") from exc

        run_name, command = self._build_worker_command(project, targets)

        process = self._launch_worker(project, run_name, command, kind="scan")
        project.setdefault("run_names", []).append(run_name)
        self._touch(project)
        self._save_projects()
        self._add_message(f"Started {run_name}; its progress will appear in the run list.")
        return {
            "started": True,
            "run_name": run_name,
            "pid": process.pid,
            "project_id": project["id"],
        }

    def _launch_worker(
        self, project: dict[str, Any], run_name: str, command: list[str], *, kind: str
    ) -> subprocess.Popen[bytes]:
        """Start an isolated scan/chat process with the selected project root."""
        project_runs_dir = self._project_runs_dir(project)
        log_dir = project_runs_dir / ".web-workers"
        log_dir.mkdir(parents=True, exist_ok=True)
        suffix = "" if kind == "scan" else f".{kind}-{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}"
        log_path = log_dir / f"{run_name}{suffix}.log"
        environment = os.environ.copy()
        environment["STRIX_PROJECT_ID"] = str(project["id"])
        environment["STRIX_PROJECT_NAME"] = str(project["name"])
        environment["STRIX_RUNS_DIR"] = str(project_runs_dir)
        with log_path.open("ab") as log_file:
            creationflags = (
                getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) if os.name == "nt" else 0
            )
            process = subprocess.Popen(  # noqa: S603 - fixed Python module; targets are argv data
                command,
                cwd=Path.cwd(),
                stdin=subprocess.DEVNULL,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                close_fds=os.name != "nt",
                env=environment,
                creationflags=creationflags,
            )
        self._workers[run_name] = process
        return process

    def _build_worker_command(
        self, project: dict[str, Any], targets: list[str]
    ) -> tuple[str, list[str]]:
        """Validate a project scope and render its headless worker command."""
        candidate = deepcopy(self.args)
        candidate.target = targets
        candidate.target_list = []
        build_targets_info(candidate)
        run_name = generate_run_name(candidate.targets_info)
        command = [sys.executable, "-m", "strix.interface.main", "-n", "--run-name", run_name]
        for target in targets:
            command.extend(["--target", target])
        command.extend(
            ["--scan-mode", str(project["scan_mode"]), "--scope-mode", str(project["scope_mode"])]
        )
        instruction = str(project.get("instruction", ""))
        if instruction:
            command.extend(["--instruction", instruction])
        if project.get("max_budget_usd") is not None:
            command.extend(["--max-budget", str(project["max_budget_usd"])])
        if self.max_turns:
            command.extend(["--max-turns", str(self.max_turns)])
        if project.get("diff_base"):
            command.extend(["--diff-base", str(project["diff_base"])])
        if self.args.config:
            command.extend(["--config", self.args.config])
        return run_name, command

    def current_run_dir(self) -> Path | None:
        """Use the newest persisted worker artifact as the viewer default."""
        base = self._project_runs_dir()
        if not base.is_dir():
            return None
        candidates = [child for child in base.iterdir() if run_record_path(child).is_file()]
        if not candidates:
            return None
        return max(candidates, key=lambda child: run_record_path(child).stat().st_mtime)

    def current_runs_base_dir(self) -> Path:
        """Constrain the viewer API to the selected project's artifact root."""
        return self._project_runs_dir()

    async def run(self, *, host: str, port: int, open_browser: bool) -> None:
        if not bundle_is_built():
            raise RuntimeError(
                "Viewer UI is not built. Run `cd strix/interface/viewer/frontend "
                "&& npm ci && npm run build`."
            )
        self._loop = asyncio.get_running_loop()
        placeholder = runs_base_dir() / ".web-pending"
        httpd, url, token = serve(
            placeholder,
            host=host,
            port=port,
            # A wildcard bind is not a browser destination. Open the selected
            # LAN address after binding instead.
            open_browser=False,
            web_state_handler=self.web_state,
            web_command_handler=self.web_command,
            run_dir_provider=self.current_run_dir,
            runs_base_dir_provider=self.current_runs_base_dir,
            allowed_client_networks=tuple(self.args.allowed_networks) or None,
        )
        display_host = self._display_host(host)
        display_url = url.replace(f"://{host}:", f"://{display_host}:", 1)
        if open_browser:
            try:
                webbrowser.open(authorized_url(display_url, token))
            except Exception:  # noqa: BLE001 - opening a browser is best-effort
                logger.debug("could not open the web hub browser", exc_info=True)
        console = Console()
        console.print()
        console.print("Pent6d web hub is running at:")
        console.print(f"  {authorized_url(display_url, token)}", soft_wrap=True)
        console.print("Press Ctrl-C to stop the hub. Active scan workers continue running.")
        console.print()
        try:
            await asyncio.Event().wait()
        finally:
            httpd.shutdown()
            httpd.server_close()

    def _display_host(self, host: str) -> str:
        """Return a usable local address when the server binds a wildcard."""
        if host not in {"0.0.0.0", "::"}:
            return host
        networks = tuple(self.args.allowed_networks)
        if not networks:
            return "127.0.0.1" if host == "0.0.0.0" else "::1"
        addresses: set[str] = set()
        for name in {socket.gethostname(), socket.getfqdn()}:
            try:
                addresses.update(
                    info[4][0].split("%", 1)[0] for info in socket.getaddrinfo(name, None)
                )
            except OSError:
                continue
        for address in addresses:
            try:
                if any(ip_address(address) in network for network in networks):
                    return address
            except ValueError:
                continue
        return host


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _positive_budget(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _client_network(value: str) -> _ClientNetwork:
    try:
        network = ip_network(value, strict=True)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "must be a valid CIDR, for example 192.168.16.0/24"
        ) from exc
    if network.num_addresses <= 1:
        raise argparse.ArgumentTypeError("must include at least two addresses")
    return network


def parse_web_arguments(argv: list[str]) -> tuple[argparse.Namespace, argparse.Namespace]:
    """Parse browser-server options and the initial draft shown in setup."""
    parser = argparse.ArgumentParser(
        prog="pent6d web",
        description="Open the local browser hub for starting and reviewing Pent6d scans.",
    )
    parser.add_argument("-t", "--target", action="append", help="Optional initial scan target")
    parser.add_argument("--instruction", default="", help="Optional initial instructions")
    parser.add_argument("--scan-mode", choices=["quick", "standard", "deep"], default="deep")
    parser.add_argument("--scope-mode", choices=["auto", "diff", "full"], default="auto")
    parser.add_argument("--diff-base")
    parser.add_argument("--max-budget", type=_positive_budget, dest="max_budget_usd")
    parser.add_argument("--max-turns", type=_positive_int, default=500)
    parser.add_argument("--config", help="Alternative Pent6d JSON configuration file")
    parser.add_argument("--host", default="127.0.0.1", help="Local bind address")
    parser.add_argument(
        "--allow-network",
        action="append",
        type=_client_network,
        dest="allowed_networks",
        default=[],
        metavar="CIDR",
        help="Allow this LAN CIDR to access the web hub (repeatable)",
    )
    parser.add_argument("--port", type=int, default=0, help="Local port (default: available port)")
    parser.add_argument(
        "--no-open", action="store_true", help="Do not open a browser automatically"
    )
    args = parser.parse_args(argv)
    if args.config:
        config_path = Path(args.config).expanduser()
        if not config_path.is_file():
            parser.error(f"--config file not found: {args.config}")
        args.config = str(config_path)
        apply_config_override(config_path)

    # Keep the namespace shape shared by target preparation and older callers.
    args.needs_setup = True
    args.targets_info = []
    args.target_list = []
    args.local_sources = []
    args.workspace_files = []
    args.diff_scope = {"active": False}
    args.run_name = None
    args.resume = None
    args.non_interactive = False
    args.user_explicit_instruction = None
    args.user_instruction = args.instruction or None
    args.workspace_mount = None
    args.workspace_subdir = None
    if args.target:
        try:
            build_targets_info(args)
        except ValueError as exc:
            parser.error(str(exc))
    return args, args


def run_web(argv: list[str]) -> None:
    """Run the persistent local web hub."""
    scan_args, server_args = parse_web_arguments(argv)
    loopback_hosts = {"127.0.0.1", "localhost", "::1"}
    if server_args.host not in loopback_hosts and not server_args.allowed_networks:
        raise SystemExit(
            "A non-loopback --host requires --allow-network CIDR to protect scan controls"
        )
    asyncio.run(
        WebRuntime(scan_args).run(
            host=server_args.host,
            port=server_args.port,
            open_browser=not server_args.no_open,
        )
    )


__all__ = ["WebRuntime", "parse_web_arguments", "run_web"]
