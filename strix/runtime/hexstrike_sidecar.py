"""Lifecycle management for the optional local HexStrike sidecar.

Pent6d keeps HexStrike out of its Python environment.  This module only starts
the separately installed server, waits for its loopback health endpoint, and
generates a per-user MCP configuration that points at the sidecar's stdio
bridge.  A missing or unhealthy sidecar is fail-open: Pent6d can still run
with its native tools and reports the integration status in its logs.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8889
_HEALTH_TIMEOUT_SECONDS = 5.0
_STARTUP_TIMEOUT_SECONDS = 45.0
_LOCK_TIMEOUT_SECONDS = 8.0
_SAFE_TOOLS = [
    "server_health",
    "nmap_scan",
    "amass_scan",
    "subfinder_scan",
    "httpx_probe",
    "nuclei_scan",
    "dirsearch_scan",
    "ffuf_scan",
    "wafw00f_scan",
    "katana_crawl",
    "arjun_parameter_discovery",
    "dalfox_xss_scan",
]


@dataclass(frozen=True)
class HexStrikeSidecarStatus:
    """Non-secret lifecycle information for logs and future UI telemetry."""

    enabled: bool
    running: bool
    started: bool
    host: str
    port: int
    base_dir: str | None = None
    pid: int | None = None
    mcp_config_path: str | None = None
    error: str | None = None


def _default_base_dir() -> Path:
    configured = os.environ.get("PENT6D_HEXSTRIKE_HOME")
    if configured:
        return Path(configured).expanduser()
    # The default checkout created by the Pent6d installer lives beside the
    # repository, not inside the git worktree.  This keeps nested .git data out
    # of Pent6d while still making the zero-configuration path convenient.
    return Path(__file__).resolve().parents[2].parent / "hexstrike-ai"


def _configured_endpoint() -> tuple[str, int]:
    host = os.environ.get("PENT6D_HEXSTRIKE_HOST", _DEFAULT_HOST).strip() or _DEFAULT_HOST
    try:
        port = int(os.environ.get("PENT6D_HEXSTRIKE_PORT", str(_DEFAULT_PORT)))
    except ValueError:
        port = _DEFAULT_PORT
    if not 1 <= port <= 65535:
        port = _DEFAULT_PORT
    return host, port


def _port_available(host: str, port: int) -> bool:
    """Return whether a local listener can bind the requested endpoint."""

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind((host, port))
    except OSError:
        return False
    finally:
        probe.close()
    return True


def _select_available_port(host: str, port: int) -> int:
    if _port_available(host, port):
        return port
    # 8889 is Pent6d's default.  A local service (or a Windows
    # service reservation) may already own it, so use the first nearby free
    # port unless the user explicitly pinned a port.
    if os.environ.get("PENT6D_HEXSTRIKE_PORT"):
        return port
    for candidate in range(port + 1, port + 21):
        if _port_available(host, candidate):
            logger.warning("HexStrike port %d is unavailable; selecting %d", port, candidate)
            return candidate
    return port


def _remembered_port(base_dir: Path) -> int | None:
    if os.environ.get("PENT6D_HEXSTRIKE_PORT"):
        return None
    path = base_dir / ".pent6d" / "hexstrike-port"
    try:
        port = int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _remember_port(base_dir: Path, port: int) -> None:
    path = base_dir / ".pent6d" / "hexstrike-port"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(port), encoding="ascii")


def _health_url(host: str, port: int) -> str:
    return f"http://{host}:{port}/health"


def _is_healthy(host: str, port: int) -> bool:
    try:
        with urllib.request.urlopen(  # noqa: S310 - endpoint is explicitly local/configured
            _health_url(host, port), timeout=_HEALTH_TIMEOUT_SECONDS
        ) as response:
            return 200 <= int(response.status) < 300
    except (OSError, urllib.error.URLError, ValueError):
        return False


def _python_executable(base_dir: Path) -> Path | None:
    override = os.environ.get("PENT6D_HEXSTRIKE_PYTHON")
    candidates = [Path(override).expanduser()] if override else []
    candidates.extend(
        [
            base_dir / ".venv312" / "Scripts" / "python.exe",
            base_dir / ".venv312" / "bin" / "python",
            base_dir / ".venv" / "Scripts" / "python.exe",
            base_dir / ".venv" / "bin" / "python",
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


@contextlib.contextmanager
def _startup_lock(lock_path: Path):
    """Acquire a small cross-process lock without an extra dependency."""

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    handle = None
    while handle is None:
        try:
            handle = lock_path.open("x", encoding="ascii")
            handle.write(f"{os.getpid()}\n")
            handle.flush()
        except FileExistsError:
            # A crashed launcher must not permanently prevent future starts.
            with contextlib.suppress(OSError):
                if time.time() - lock_path.stat().st_mtime > 60:
                    lock_path.unlink()
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"timed out waiting for HexStrike startup lock: {lock_path}"
                ) from None
            time.sleep(0.1)
    try:
        yield
    finally:
        handle.close()
        with contextlib.suppress(OSError):
            lock_path.unlink()


def _spawn_server(base_dir: Path, python: Path, host: str, port: int) -> subprocess.Popen[bytes]:
    log_dir = base_dir / ".pent6d"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = (log_dir / "hexstrike-server.log").open("ab")
    environment = os.environ.copy()
    environment.update(
        {
            "HEXSTRIKE_HOST": host,
            "HEXSTRIKE_PORT": str(port),
            "HEXSTRIKE_ENV_DIR": str(Path(tempfile.gettempdir()) / "hexstrike_envs"),
            "HEXSTRIKE_FILES_DIR": str(Path(tempfile.gettempdir()) / "hexstrike_files"),
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0) | getattr(
            subprocess, "CREATE_NO_WINDOW", 0
        )
    try:
        return subprocess.Popen(  # noqa: S603 - executable is the reviewed sidecar venv
            [str(python), str(base_dir / "hexstrike_server.py")],
            cwd=str(base_dir),
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            close_fds=os.name != "nt",
            creationflags=creationflags,
            start_new_session=os.name != "nt",
            env=environment,
        )
    except BaseException:
        log_file.close()
        raise


def ensure_started() -> HexStrikeSidecarStatus:  # noqa: PLR0911 - explicit lifecycle states
    """Start HexStrike once per host and wait until its API is healthy."""

    if os.environ.get("PENT6D_HEXSTRIKE_AUTOSTART", "1").strip().lower() in {
        "0",
        "false",
        "no",
        "off",
    }:
        return HexStrikeSidecarStatus(
            enabled=False,
            running=False,
            started=False,
            host=_DEFAULT_HOST,
            port=_DEFAULT_PORT,
            error="disabled by PENT6D_HEXSTRIKE_AUTOSTART",
        )

    base_dir = _default_base_dir()
    host, port = _configured_endpoint()
    server_file = base_dir / "hexstrike_server.py"
    if not server_file.is_file():
        return HexStrikeSidecarStatus(
            enabled=True,
            running=False,
            started=False,
            host=host,
            port=port,
            base_dir=str(base_dir),
            error=f"HexStrike checkout not found: {server_file}",
        )
    python = _python_executable(base_dir)
    if python is None:
        return HexStrikeSidecarStatus(
            enabled=True,
            running=False,
            started=False,
            host=host,
            port=port,
            base_dir=str(base_dir),
            error="HexStrike Python environment not found (expected .venv312 or .venv)",
        )

    remembered = _remembered_port(base_dir)
    if remembered is not None and _is_healthy(host, remembered):
        port = remembered
    if _is_healthy(host, port):
        _remember_port(base_dir, port)
        return HexStrikeSidecarStatus(
            enabled=True,
            running=True,
            started=False,
            host=host,
            port=port,
            base_dir=str(base_dir),
        )

    port = _select_available_port(host, port)
    lock_path = base_dir / ".pent6d" / "hexstrike-start.lock"
    try:
        with _startup_lock(lock_path):
            if _is_healthy(host, port):
                _remember_port(base_dir, port)
                return HexStrikeSidecarStatus(
                    enabled=True,
                    running=True,
                    started=False,
                    host=host,
                    port=port,
                    base_dir=str(base_dir),
                )
            process = _spawn_server(base_dir, python, host, port)
            deadline = time.monotonic() + _STARTUP_TIMEOUT_SECONDS
            while time.monotonic() < deadline:
                if _is_healthy(host, port):
                    _remember_port(base_dir, port)
                    logger.info(
                        "HexStrike sidecar is ready at %s:%d (pid=%d)",
                        host,
                        port,
                        process.pid,
                    )
                    return HexStrikeSidecarStatus(
                        enabled=True,
                        running=True,
                        started=True,
                        host=host,
                        port=port,
                        base_dir=str(base_dir),
                        pid=process.pid,
                    )
                if process.poll() is not None:
                    break
                time.sleep(0.25)
            error = f"HexStrike did not become healthy within {_STARTUP_TIMEOUT_SECONDS:.0f}s"
            logger.warning("%s; see %s", error, base_dir / ".pent6d" / "hexstrike-server.log")
            return HexStrikeSidecarStatus(
                enabled=True,
                running=False,
                started=True,
                host=host,
                port=port,
                base_dir=str(base_dir),
                pid=process.pid,
                error=error,
            )
    except (OSError, TimeoutError) as exc:
        logger.warning("Could not start HexStrike sidecar: %s", exc)
        return HexStrikeSidecarStatus(
            enabled=True,
            running=False,
            started=False,
            host=host,
            port=port,
            base_dir=str(base_dir),
            error=str(exc),
        )


def _load_entries(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.warning("Ignoring unreadable MCP config while adding HexStrike: %s", path)
        return []
    if not isinstance(raw, list):
        logger.warning("Ignoring non-list MCP config while adding HexStrike: %s", path)
        return []
    return [entry for entry in raw if isinstance(entry, dict) and entry.get("name") != "hexstrike"]


def prepare_mcp_config(
    status: HexStrikeSidecarStatus,
    base_config: str | None = None,
) -> Path | None:
    """Create a merged MCP config and point this process at it."""

    if not status.running or not status.base_dir:
        return None
    sidecar = Path(status.base_dir)
    python = _python_executable(sidecar)
    bridge = sidecar / "hexstrike_mcp.py"
    if python is None or not bridge.is_file():
        return None

    configured_base = base_config or os.environ.get("STRIX_MCP_CONFIG")
    base_path = (
        Path(configured_base).expanduser()
        if configured_base
        else Path.home() / ".strix" / "mcp-servers.json"
    )
    entries = _load_entries(base_path)
    allow_all = os.environ.get("PENT6D_HEXSTRIKE_ALLOW_ALL", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    tool_entry: dict[str, Any] = {
        "name": "hexstrike",
        "transport": "stdio",
        "command": str(python),
        "args": [str(bridge), "--server", f"http://{status.host}:{status.port}"],
        "env": {"HEXSTRIKE_MCP_SKIP_HEALTH": "1"},
        "allowed_tools": None if allow_all else list(_SAFE_TOOLS),
        "active_tools": list(_SAFE_TOOLS),
        "notes": "Local HexStrike sidecar; Pent6d Supervisor remains the workflow authority.",
        "http_timeout_seconds": 30,
        "sse_read_timeout_seconds": 300,
        "session_timeout_seconds": 300,
        "max_concurrent_calls": 2,
    }
    entries.append(tool_entry)
    destination = Path(
        os.environ.get(
            "PENT6D_HEXSTRIKE_MCP_CONFIG",
            str(Path.home() / ".strix" / "pent6d-hexstrike-mcp.json"),
        )
    ).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    temporary.replace(destination)
    os.environ["STRIX_MCP_CONFIG"] = str(destination)
    return destination


def ensure_integration(base_config: str | None = None) -> HexStrikeSidecarStatus:
    """Start the sidecar and install its MCP connection for this process."""

    status = ensure_started()
    if status.running:
        config_path = prepare_mcp_config(status, base_config=base_config)
        status = replace(status, mcp_config_path=str(config_path) if config_path else None)
    if status.error:
        logger.warning("HexStrike sidecar unavailable: %s", status.error)
    return status

