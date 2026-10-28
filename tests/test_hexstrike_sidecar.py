from __future__ import annotations

import json

from strix.runtime.hexstrike_sidecar import (
    HexStrikeSidecarStatus,
    _configured_endpoint,
    _load_entries,
    prepare_mcp_config,
)


def test_prepare_mcp_config_merges_existing_servers(tmp_path, monkeypatch) -> None:
    base = tmp_path / "mcp.json"
    base.write_text(
        json.dumps(
            [
                {
                    "name": "existing",
                    "transport": "http",
                    "url": "http://127.0.0.1:9999/mcp",
                },
                {
                    "name": "hexstrike",
                    "transport": "http",
                    "url": "http://old.example.invalid",
                },
            ]
        ),
        encoding="utf-8",
    )
    destination = tmp_path / "generated.json"
    monkeypatch.setenv("PENT6D_HEXSTRIKE_MCP_CONFIG", str(destination))
    status = HexStrikeSidecarStatus(
        enabled=True,
        running=True,
        started=False,
        host="127.0.0.1",
        port=8889,
        base_dir=str(tmp_path),
    )
    (tmp_path / "hexstrike_mcp.py").write_text("# test bridge", encoding="utf-8")
    venv_python = tmp_path / ".venv312" / "Scripts" / "python.exe"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_bytes(b"test")

    result = prepare_mcp_config(status, str(base))

    assert result == destination
    entries = json.loads(destination.read_text(encoding="utf-8"))
    assert [entry["name"] for entry in entries] == ["existing", "hexstrike"]
    assert entries[-1]["transport"] == "stdio"
    assert entries[-1]["args"][-1] == "http://127.0.0.1:8889"
    assert entries[-1]["env"]["HEXSTRIKE_MCP_SKIP_HEALTH"] == "1"


def test_load_entries_missing_file_is_empty(tmp_path) -> None:
    assert _load_entries(tmp_path / "missing.json") == []


def test_hexstrike_default_endpoint_uses_port_8889(monkeypatch) -> None:
    monkeypatch.delenv("PENT6D_HEXSTRIKE_HOST", raising=False)
    monkeypatch.delenv("PENT6D_HEXSTRIKE_PORT", raising=False)

    assert _configured_endpoint() == ("127.0.0.1", 8889)
