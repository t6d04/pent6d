# HexStrike sidecar

Pent6d can start a local HexStrike server automatically and expose its MCP
bridge to the agents. HexStrike is deliberately installed outside the Pent6d
virtual environment so its heavy security-tool dependencies cannot conflict
with the scan engine.

## Installed layout

The default Windows layout is:

```text
D:\Resources\hexstrike-ai\
  hexstrike_server.py
  hexstrike_mcp.py
  .venv312\Scripts\python.exe
```

Pent6d checks the HexStrike health endpoint at startup. If no healthy process
is found it starts the server on loopback, writes its log to
`D:\Resources\hexstrike-ai\.pent6d\hexstrike-server.log`, and generates:

```text
%USERPROFILE%\.strix\pent6d-hexstrike-mcp.json
```

The generated MCP file is merged with the user's existing
`%USERPROFILE%\.strix\mcp-servers.json` configuration. The initial allowlist is
limited to recon and validation tools. Set `PENT6D_HEXSTRIKE_ALLOW_ALL=1` only
for an explicitly authorized test environment.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PENT6D_HEXSTRIKE_AUTOSTART` | `1` | Set to `0` to disable automatic startup. |
| `PENT6D_HEXSTRIKE_HOME` | sibling `hexstrike-ai` directory | Sidecar checkout. |
| `PENT6D_HEXSTRIKE_PYTHON` | `.venv312` then `.venv` | Sidecar Python executable. |
| `PENT6D_HEXSTRIKE_HOST` | `127.0.0.1` | Bind address. Keep loopback unless authentication is added. |
| `PENT6D_HEXSTRIKE_PORT` | `8889` | Fixed port. If unset and busy, Pent6d selects a nearby port. |
| `PENT6D_HEXSTRIKE_ALLOW_ALL` | `0` | Expose all MCP tools instead of the safe allowlist. |

Only authorized targets should be supplied to HexStrike. The HexStrike API can
execute external commands, so do not expose it to an untrusted network.

## Quick start (PowerShell)

```powershell
$env:PENT6D_HEXSTRIKE_HOME = 'D:\Resources\hexstrike-ai'
$env:PENT6D_HEXSTRIKE_PORT = '8889'
pent6d web
```

Pent6d starts or reuses the sidecar before opening the web UI. Verify the
sidecar independently when diagnosing an integration:

```powershell
Invoke-RestMethod http://127.0.0.1:8889/health
```

If port `8889` is already occupied and was not explicitly pinned, Pent6d
selects and remembers a nearby port in
`D:\Resources\hexstrike-ai\.pent6d\hexstrike-port`; the generated MCP config
at `%USERPROFILE%\.strix\pent6d-hexstrike-mcp.json` is the authoritative endpoint.

## How agents use HexStrike

The agent prompt loads `tooling/hexstrike` automatically. The normal sequence
is:

1. `list_mcps()` confirms that the `hexstrike` connection is available.
2. `search_mcp_tools()` finds a capability and
   `get_mcp_tool_schema()` obtains its exact arguments.
3. `call_mcp()` runs one bounded, in-scope operation. Agents should start with
   recon (`subfinder`/`amass`, `httpx`, `katana`), then use content discovery or
   focused validators only when recon provides a concrete signal.
4. Recon agents convert useful rows to `record_recon` and call
   `finalize_recon` after the complete inventory and screenshots are ready.
   Scanner output is a lead until a target-side request/response or source
   trace validates it.

Every successful `call_mcp()` is also copied to the run's
`.state/shared_memory.db` as a bounded `evidence` record. The excerpt is
redacted (tokens, cookies, passwords, API keys and bearer values are removed)
and tagged with `mcp`, the tool name, and `hexstrike` when applicable. This
record is a hand-off safety net; structured recon facts still belong in
`record_recon`, and agents can retrieve both with `search_shared_memory`.

If the sidecar is unavailable, agents use Pent6d's native tools and record the
missing integration as a coverage note rather than treating the target as
clean. Restart Pent6d after changing the skill or MCP configuration so new
runs receive the updated prompt.
