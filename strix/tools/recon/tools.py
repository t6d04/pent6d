"""Run-scoped recon artifacts, independent of compacted conversation history."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Literal
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool
from pydantic import BaseModel, ConfigDict, Field

from strix.tools.shared_memory.tools import _remember


_LOCK = threading.RLock()
_MAX_IMAGE_BYTES = 10 * 1024 * 1024
_MAX_MEMORY_CHUNK = 20_000
_MAX_SNAPSHOT_CHUNKS = 2_000

# A Caido/proxy error is not a service response.  Keep this deliberately
# narrow: a real origin may legitimately return HTTP 500/502, while these
# phrases identify the proxy-generated error pages seen by recon agents.
_PROXY_ERROR_MARKERS = (
    "<title>caido</title>",
    "caido proxy",
    "proxy-side",
    "proxy error page",
    "request never reached",
    "local proxy",
)
_HOST_RE = re.compile(r"(?i)([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z0-9.-]+)")

_RECON_COVERAGE_CATEGORIES = (
    "asset_discovery",
    "dns_resolution",
    "live_probe",
    "service_discovery",
    "web_surface",
    "javascript_analysis",
    "content_discovery",
    "parameter_discovery",
    "technology_fingerprint",
    "authentication_surface",
    "visual_capture",
)
class ReconCoverageRecord(BaseModel):
    """Auditable status for one recon workstream."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    category: Literal[
        "asset_discovery",
        "dns_resolution",
        "live_probe",
        "service_discovery",
        "web_surface",
        "javascript_analysis",
        "content_discovery",
        "parameter_discovery",
        "technology_fingerprint",
        "authentication_surface",
        "visual_capture",
    ]
    status: Literal["completed", "not_applicable", "blocked", "not_run"]
    tools: list[str] = Field(default_factory=list, max_length=20)
    evidence: str = Field(default="", max_length=4000)
    reason: str = Field(default="", max_length=2000)


def _coverage_path(run_dir: Path) -> Path:
    return run_dir / "recon_coverage.json"


def _read_coverage(run_dir: Path) -> list[dict[str, Any]]:
    path = _coverage_path(run_dir)
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise TypeError("Invalid recon coverage artifact")
    return [item for item in data["entries"] if isinstance(item, dict)]


def _required_coverage(
    *, scan_mode: str | None, target_types: list[str] | tuple[str, ...] | set[str] | None
) -> list[str]:
    """Return workstreams required before a live recon can be finalized."""

    mode = (scan_mode or "").strip().lower()
    target_set = {str(value).strip().lower() for value in (target_types or ()) if value}
    if mode not in {"standard", "deep"}:
        return []
    if not target_set & {"web_application", "api_spec", "ip_address"}:
        return []

    required = {"asset_discovery", "live_probe", "technology_fingerprint"}
    if "web_application" in target_set:
        required.update(
            {
                "dns_resolution",
                "service_discovery",
                "web_surface",
                "javascript_analysis",
                "content_discovery",
                "parameter_discovery",
                "authentication_surface",
                "visual_capture",
            }
        )
    elif "api_spec" in target_set:
        required.update(
            {
                "dns_resolution",
                "service_discovery",
                "web_surface",
                "parameter_discovery",
                "authentication_surface",
            }
        )
    elif "ip_address" in target_set:
        required.add("service_discovery")
    return [category for category in _RECON_COVERAGE_CATEGORIES if category in required]


def _coverage_gaps(
    entries: list[dict[str, Any]], required: list[str]
) -> tuple[list[str], list[str]]:
    by_category = {str(entry.get("category")): entry for entry in entries}
    missing: list[str] = []
    blocked: list[str] = []
    for category in required:
        status = str(by_category.get(category, {}).get("status") or "")
        if status in {"", "not_run"}:
            missing.append(category)
        elif status == "blocked":
            blocked.append(category)
    return missing, blocked


def _save_coverage(
    run_dir: Path,
    records: list[dict[str, Any]],
    agent_id: str | None,
) -> dict[str, Any]:
    with _LOCK:
        existing = {entry["category"]: entry for entry in _read_coverage(run_dir)}
        now = datetime.now(UTC).isoformat()
        for record in records:
            existing[record["category"]] = {
                **existing.get(record["category"], {}),
                **record,
                "agent_id": agent_id,
                "updated_at": now,
            }
        payload = {
            "schema_version": 1,
            "entries": [existing[key] for key in _RECON_COVERAGE_CATEGORIES if key in existing],
            "updated_at": now,
        }
        run_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=run_dir, delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(payload, handle, ensure_ascii=False)
        try:
            temporary.replace(_coverage_path(run_dir))
        finally:
            temporary.unlink(missing_ok=True)
        return {"success": True, "saved": [record["category"] for record in records]}


class ReconObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    kind: Literal[
        "subdomain",
        "javascript",
        "js_leak",
        "source_leak",
        "endpoint",
        "service",
        "technology",
    ]
    value: str = Field(min_length=1, max_length=2048)
    source: str = Field(min_length=1, max_length=2000)
    scope: Literal["in_scope", "out_of_scope", "unknown"] = "unknown"
    attribution: Literal["confirmed", "likely", "unknown", "out_of_scope"] = "unknown"
    attribution_evidence: str = Field(default="", max_length=4000)
    alive: Literal["alive", "unreachable", "unknown"] = "unknown"
    status_code: int | None = Field(default=None, ge=100, le=599)
    title: str = Field(default="", max_length=1000)
    ip_addresses: list[str] = Field(default_factory=list, max_length=50)
    technologies: list[str] = Field(default_factory=list, max_length=50)
    method: str = Field(default="", max_length=20)
    evidence: str = Field(default="", max_length=8000)
    confidence: Literal["observed", "inferred", "unverified"] = "unverified"
    screenshot_path: str = Field(default="", max_length=2048)
    finding_id: str = Field(default="", max_length=100)
    source_location: str = Field(default="", max_length=4096)
    source_location_type: Literal["", "local_path", "web_url"] = ""
    source_download_status: Literal["", "downloaded", "online_only"] = ""


def _validate_source_leak(entry: dict[str, Any]) -> None:
    """Validate the durable location metadata for a source-leak record."""

    if entry.get("kind") != "source_leak":
        return
    location = str(entry.get("source_location") or "").strip()
    location_type = str(entry.get("source_location_type") or "")
    download_status = str(entry.get("source_download_status") or "")
    if not location:
        raise ValueError("source_leak requires source_location")
    if location_type not in {"local_path", "web_url"}:
        raise ValueError("source_leak source_location_type must be local_path or web_url")
    if download_status not in {"downloaded", "online_only"}:
        raise ValueError(
            "source_leak source_download_status must be downloaded or online_only"
        )
    if location_type == "web_url":
        parsed = urlsplit(location)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("source_leak web_url must be an absolute http(s) URL")
        if download_status != "online_only":
            raise ValueError("web_url source leaks must use online_only status")
    elif download_status != "downloaded":
        raise ValueError("local_path source leaks must use downloaded status")


def _host_key(value: str) -> str:
    """Return a stable hostname for URL/host values used in recon records."""

    raw = value.strip()
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    if parsed.hostname:
        return parsed.hostname.rstrip(".").lower()
    match = _HOST_RE.search(raw)
    return match.group(1).rstrip(".").lower() if match else ""


def _is_proxy_error(entry: dict[str, Any]) -> bool:
    haystack = " ".join(
        str(entry.get(field) or "")
        for field in ("source", "title", "evidence")
    ).lower()
    return any(marker in haystack for marker in _PROXY_ERROR_MARKERS)


def _normalize_alive(entry: dict[str, Any]) -> dict[str, Any]:
    """Normalize ``alive`` so it means an observed, operating service.

    Passive hostname discovery is never enough to claim that a service is
    running.  A real HTTP response (including 4xx/5xx) is positive evidence;
    proxy-generated error pages are not and remain ``unknown`` until a direct
    probe establishes the state.
    """

    normalized = dict(entry)
    normalized["attribution"] = str(normalized.get("attribution") or "unknown")
    if normalized.get("scope") == "out_of_scope":
        normalized["attribution"] = "out_of_scope"
    if _is_proxy_error(normalized):
        normalized["alive"] = "unknown"
        return normalized

    kind = str(normalized.get("kind") or "")
    has_http_response = normalized.get("status_code") is not None
    source = str(normalized.get("source") or "").lower()
    evidence = str(normalized.get("evidence") or "").lower()
    active_probe = any(
        marker in f"{source} {evidence}"
        for marker in (
            "direct probe",
            "httpx",
            "curl",
            "browser",
            "http probe",
            "tcp open",
            "port open",
            "connected",
            "nmap",
            "naabu",
        )
    )

    # A hostname obtained from CT/DNS/a portal link is a candidate, not a
    # running service.  Keep it unknown until an active observation exists.
    if kind == "subdomain" and not (has_http_response or active_probe):
        normalized["alive"] = "unknown"
    elif has_http_response:
        # Any response from the origin proves that the service is operating;
        # status code alone must not be used to declare it dead.
        normalized["alive"] = "alive"
    return normalized


def _normalize_inventory(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize records and project service state back onto host records."""

    normalized = [_normalize_alive(entry) for entry in entries]
    service_state: dict[str, str] = {}
    service_status: dict[str, int] = {}
    state_rank = {"unknown": 0, "unreachable": 1, "alive": 2}
    for entry in normalized:
        if entry.get("kind") not in {"service", "endpoint"}:
            continue
        if entry.get("scope") != "in_scope":
            continue
        host = _host_key(str(entry.get("value") or ""))
        if not host:
            continue
        state = str(entry.get("alive") or "unknown")
        # A positive service observation wins over a failed observation for
        # the same host; this handles one dead port alongside a live HTTPS
        # service without marking the hostname as dead.
        previous = service_state.get(host)
        if previous is None or state_rank.get(state, 0) > state_rank.get(previous, 0):
            service_state[host] = state
            if entry.get("status_code") is not None:
                service_status[host] = int(entry["status_code"])

    for entry in normalized:
        if entry.get("kind") != "subdomain":
            continue
        if entry.get("scope") != "in_scope":
            continue
        host = _host_key(str(entry.get("value") or ""))
        service_state_value = service_state.get(host)
        if service_state_value:
            entry["alive"] = service_state_value
            if service_state_value == "alive" and entry.get("status_code") is None:
                entry["status_code"] = service_status.get(host)
    return normalized


def _missing_live_host_screenshots(entries: list[dict[str, Any]]) -> list[str]:
    """Return canonical live hosts without any durable screenshot evidence."""

    live_hosts: set[str] = set()
    captured_hosts: set[str] = set()
    for entry in entries:
        if entry.get("kind") not in {"subdomain", "service", "endpoint"}:
            continue
        if entry.get("scope") != "in_scope":
            continue
        host = _host_key(str(entry.get("value") or ""))
        if not host:
            continue
        if entry.get("alive") == "alive":
            live_hosts.add(host)
        if entry.get("screenshot"):
            captured_hosts.add(host)
    return sorted(live_hosts - captured_hosts)


def read_recon(run_dir: Path) -> dict[str, Any]:
    run_record: dict[str, Any] = {}
    run_record_path = run_dir / "run.json"
    if run_record_path.exists():
        try:
            loaded = json.loads(run_record_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                run_record = loaded
        except (OSError, json.JSONDecodeError):
            # Recon remains readable even if a partially-written run record is
            # observed while the worker is updating its status.
            run_record = {}
    required_coverage = _required_coverage(
        scan_mode=str(run_record.get("scan_mode") or ""),
        target_types=run_record.get("scan_target_types"),
    )
    path = run_dir / "recon.json"
    if not path.exists():
        return {
            "schema_version": 1,
            "entries": [],
            "coverage": _read_coverage(run_dir),
            "required_coverage": required_coverage,
            "updated_at": None,
        }
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        raise TypeError("Invalid recon artifact")
    data["entries"] = _normalize_inventory(list(data["entries"]))
    data["coverage"] = _read_coverage(run_dir)
    data["required_coverage"] = required_coverage
    return data


def _save(run_dir: Path, entries: list[dict[str, Any]], agent_id: str | None) -> dict[str, Any]:
    with _LOCK:
        document = read_recon(run_dir)
        indexed = {item["id"]: item for item in document["entries"]}
        now = datetime.now(UTC).isoformat()
        ids = []
        for entry in entries:
            identity = json.dumps([entry["kind"], entry["value"], entry["method"]])
            key = hashlib.sha256(identity.encode()).hexdigest()[:24]
            old = indexed.get(key, {})
            # Sparse re-observations must not erase a persisted screenshot.
            indexed[key] = {
                **old,
                **entry,
                "id": key,
                "agent_id": agent_id,
                "first_seen": old.get("first_seen", now),
                "last_seen": now,
                "screenshot": entry.get("screenshot") or old.get("screenshot"),
            }
            ids.append(key)
        if len(indexed) > 10000:
            raise ValueError("Recon inventory limit of 10000 entries reached")
        document.update(entries=_normalize_inventory(list(indexed.values())), updated_at=now)
        run_dir.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=run_dir, delete=False
        ) as handle:
            temporary = Path(handle.name)
            json.dump(document, handle, ensure_ascii=False)
        try:
            temporary.replace(run_dir / "recon.json")
        finally:
            temporary.unlink(missing_ok=True)
        return {"success": True, "saved_ids": ids, "total": len(indexed)}


def _recon_complete_path(run_dir: Path) -> Path:
    return run_dir / "recon_complete.json"


def _snapshot_chunks(entries: list[dict[str, Any]]) -> list[str]:
    """Serialize every observation into bounded shared-memory chunks."""
    chunks: list[str] = []
    current = ""
    for entry in entries:
        encoded = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        candidate = f"{current}\n{encoded}" if current else encoded
        if current and len(candidate) > _MAX_MEMORY_CHUNK:
            chunks.append(current)
            current = encoded
        else:
            current = candidate
    if current:
        chunks.append(current)
    return chunks


def _finalize_recon_sync(  # noqa: PLR0911
    run_dir: Path,
    state_dir: Path,
    *,
    agent_id: str | None,
    agent_name: str | None,
    required_coverage: list[str] | None = None,
) -> dict[str, Any]:
    state_dir.mkdir(parents=True, exist_ok=True)
    complete_path = _recon_complete_path(run_dir)
    if complete_path.is_file():
        return {
            "success": True,
            "already_finalized": True,
            "marker": str(complete_path.name),
        }
    document = read_recon(run_dir)
    entries = _normalize_inventory(list(document.get("entries") or []))
    if not entries:
        return {
            "success": False,
            "error": (
                "No structured recon observations exist; mapper must record recon "
                "before finalizing."
            ),
        }
    required = list(required_coverage or [])
    missing_coverage, blocked_coverage = _coverage_gaps(
        list(document.get("coverage") or []), required
    )
    if missing_coverage or blocked_coverage:
        gaps = missing_coverage + blocked_coverage
        return {
            "success": False,
            "error": (
                "Recon coverage contract is incomplete. Record each required workstream "
                "with record_recon_coverage; blocked workstreams must be resolved or "
                "explicitly marked not_applicable before retrying."
            ),
            "required_coverage": required,
            "missing_coverage": missing_coverage,
            "blocked_coverage": blocked_coverage,
            "coverage_gaps": gaps,
        }
    missing_screenshots = _missing_live_host_screenshots(entries)
    if missing_screenshots:
        preview = ", ".join(missing_screenshots[:25])
        suffix = (
            ""
            if len(missing_screenshots) <= 25
            else f" (+{len(missing_screenshots) - 25} more)"
        )
        return {
            "success": False,
            "error": (
                "Every live in-scope host requires at least one durable screenshot "
                f"before recon can be finalized. Missing: {preview}{suffix}. "
                "Capture the host root (or record a screenshot_error barrier) and "
                "retry finalize_recon."
            ),
            "missing_screenshot_hosts": missing_screenshots,
        }
    chunks = _snapshot_chunks(entries)
    if len(chunks) > _MAX_SNAPSHOT_CHUNKS:
        return {
            "success": False,
            "error": f"Recon snapshot requires too many shared-memory chunks ({len(chunks)}).",
        }
    memory_ids: list[str] = []
    for index, chunk in enumerate(chunks, start=1):
        result = _remember(
            state_dir / "shared_memory.db",
            title=f"Recon inventory snapshot {index}/{len(chunks)}",
            content=chunk,
            kind="observation",
            tags=["recon", "recon_snapshot", f"chunk:{index}"],
            source="recon.json",
            confidence="observed",
            agent_id=agent_id,
            agent_name=agent_name,
        )
        if not result.get("success"):
            return {"success": False, "error": result.get("error", "shared memory write failed")}
        memory_ids.append(str(result["memory_id"]))
    now = datetime.now(UTC).isoformat()
    marker = {
        "schema_version": 1,
        "finalized_at": now,
        "entry_count": len(entries),
        "required_coverage": required,
        "coverage": document.get("coverage", []),
        "memory_ids": memory_ids,
        "agent_id": agent_id,
        "agent_name": agent_name,
    }
    run_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=run_dir, delete=False
    ) as handle:
        temporary = Path(handle.name)
        json.dump(marker, handle, ensure_ascii=False)
    try:
        temporary.replace(complete_path)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "success": True,
        "finalized": True,
        "entry_count": len(entries),
        "memory_chunks": len(memory_ids),
        "memory_ids": memory_ids,
        "coverage": document.get("coverage", []),
        "marker": str(complete_path.name),
    }


async def _copy_screenshot(session: Any, run_dir: Path, path: str) -> str:
    # Read only a sandbox workspace image; never accept a host path or URL.
    candidate = PurePosixPath(path)
    if (
        not candidate.is_absolute()
        or not candidate.is_relative_to("/workspace")
        or ".." in candidate.parts
    ):
        raise ValueError("screenshot_path must be an absolute path under /workspace")
    handle = await session.read(Path(path))
    try:
        payload = handle.read(_MAX_IMAGE_BYTES + 1)
    finally:
        handle.close()
    if not isinstance(payload, bytes) or len(payload) > _MAX_IMAGE_BYTES:
        raise ValueError("Screenshot must be binary and no larger than 10 MiB")
    if payload.startswith(b"\x89PNG\r\n\x1a\n"):
        suffix = "png"
    elif payload.startswith(b"\xff\xd8\xff"):
        suffix = "jpg"
    else:
        raise ValueError("Screenshot must be PNG or JPEG")
    name = f"{hashlib.sha256(payload).hexdigest()}.{suffix}"
    destination = run_dir / "recon_screenshots" / name
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Content-addressed: concurrent identical captures have identical bytes.
    await asyncio.to_thread(destination.write_bytes, payload)
    return name


@function_tool
async def record_recon(ctx: RunContextWrapper, observations_json: str) -> str:
    """Persist a batch of up to 100 recon observations for the current run.

    observations_json is a JSON array. Required fields: kind, value, source.
    kind: subdomain/javascript/js_leak/source_leak/endpoint/service/technology.
    Source leaks must also include source_location, source_location_type
    (local_path or web_url), and source_download_status (downloaded or
    online_only). Optional:
    scope (in_scope/out_of_scope/unknown), attribution
    (confirmed/likely/unknown/out_of_scope), attribution_evidence,
    alive (alive/unreachable/unknown),
    status_code, title, ip_addresses, technologies, method, evidence,
    confidence (observed/inferred/unverified), finding_id, screenshot_path.
    screenshot_path is a PNG/JPEG already captured in /workspace; it is copied
    to durable host storage immediately. Every live host/subdomain must have at
    least one screenshot across its canonical host records; aliases and routes
    may share the same capture. Record the actual final URL as value
    for screenshots. ``alive`` means that the service was observed operating:
    any real origin response (including 401/403/404/5xx) is alive. Passive
    discovery alone is unknown. Proxy-generated Caido error pages are unknown,
    not target responses; a genuine timeout/refusal after a direct probe is
    unreachable. Redact secrets, tokens, cookies and personal data in evidence,
    URLs and captures. Link validated issues with finding_id. This tool does
    not probe or expand authorization.
    """
    try:
        if len(observations_json) > 1_000_000:
            return json.dumps({"success": False, "error": "Batch exceeds 1 MB"})
        raw = json.loads(observations_json)
        if not isinstance(raw, list) or not 1 <= len(raw) <= 100:
            return json.dumps({"success": False, "error": "Provide 1-100 observations"})
        observations = [ReconObservation.model_validate(item) for item in raw]
        inner = ctx.context
        run_dir = Path(inner["state_dir"]).parent
        entries, warnings = [], []
        for observation in observations:
            entry = observation.model_dump(exclude={"screenshot_path"})
            _validate_source_leak(entry)
            if observation.screenshot_path:
                try:
                    entry["screenshot"] = await _copy_screenshot(
                        inner["sandbox_session"],
                        run_dir,
                        observation.screenshot_path,
                    )
                except Exception as exc:  # noqa: BLE001 - SDK/backend failures must retain the observation
                    entry["screenshot_error"] = type(exc).__name__
                    warnings.append(f"Screenshot for {observation.value}: {type(exc).__name__}")
            entries.append(entry)
        result = await asyncio.to_thread(_save, run_dir, entries, inner.get("agent_id"))
        result["warnings"] = warnings
        return json.dumps(result)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return json.dumps({"success": False, "error": str(exc)})


@function_tool
async def record_recon_coverage(  # noqa: PLR0911
    ctx: RunContextWrapper, coverage_json: str
) -> str:
    """Record completion or an explicit exception for each recon workstream.

    coverage_json is a JSON array of objects with ``category`` and ``status``.
    A completed category must include a concise evidence summary (and should
    name the tools used).  A not-applicable or
    blocked category must explain why, so the root can distinguish a deliberate
    scope decision from an accidentally skipped phase.
    """
    try:
        raw = json.loads(coverage_json)
        if not isinstance(raw, list) or not 1 <= len(raw) <= len(_RECON_COVERAGE_CATEGORIES):
            return json.dumps(
                {
                    "success": False,
                    "error": f"Provide 1-{len(_RECON_COVERAGE_CATEGORIES)} coverage records",
                }
            )
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw:
            record = ReconCoverageRecord.model_validate(item)
            if record.category in seen:
                return json.dumps(
                    {"success": False, "error": "Each category may appear once per batch"}
                )
            seen.add(record.category)
            if record.status == "completed" and not record.evidence:
                return json.dumps(
                    {
                        "success": False,
                        "error": (
                            f"Completed category {record.category!r} requires an evidence summary"
                        ),
                    }
                )
            if record.status != "completed" and not record.reason:
                return json.dumps(
                    {
                        "success": False,
                        "error": (
                            f"Category {record.category!r} requires a reason for {record.status}"
                        ),
                    }
                )
            records.append(record.model_dump())
        inner = ctx.context if isinstance(ctx.context, dict) else {}
        coordinator = inner.get("coordinator")
        agent_id = inner.get("agent_id") if isinstance(inner.get("agent_id"), str) else None
        if inner.get("parent_id") is not None and coordinator is not None and agent_id:
            metadata = getattr(coordinator, "metadata", {}).get(agent_id, {})
            role = metadata.get("role") if isinstance(metadata, dict) else None
            if role not in {"recon", "source_mapper"}:
                return json.dumps(
                    {
                        "success": False,
                        "error": "Only recon/source_mapper agents may record recon coverage",
                    }
                )
        result = await asyncio.to_thread(
            _save_coverage, Path(inner["state_dir"]).parent, records, agent_id
        )
        return json.dumps(result, ensure_ascii=False)
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        return json.dumps({"success": False, "error": str(exc)})


@function_tool
async def list_recon_coverage(ctx: RunContextWrapper) -> str:
    """Return the recon coverage contract and currently unresolved workstreams."""
    try:
        inner = ctx.context if isinstance(ctx.context, dict) else {}
        run_dir = Path(inner["state_dir"]).parent
        entries = await asyncio.to_thread(_read_coverage, run_dir)
        required = _required_coverage(
            scan_mode=str(inner.get("scan_mode") or ""),
            target_types=inner.get("scan_target_types"),
        )
        missing, blocked = _coverage_gaps(entries, required)
        return json.dumps(
            {
                "categories": list(_RECON_COVERAGE_CATEGORIES),
                "required": required,
                "entries": entries,
                "missing": missing,
                "blocked": blocked,
                "complete": not missing and not blocked,
            },
            ensure_ascii=False,
        )
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        return json.dumps({"success": False, "error": str(exc)})


@function_tool
async def record_source_leak(ctx: RunContextWrapper, source_leaks_json: str) -> str:
    """Record source-code leaks with a durable local path or online URL.

    Each item must contain ``source`` and either a local downloaded path or an
    absolute HTTP(S) URL that remains readable online. ``value`` is optional
    and defaults to the same source location for easy inventory search.
    """

    try:
        if len(source_leaks_json) > 500_000:
            return json.dumps({"success": False, "error": "Batch exceeds 500 KB"})
        raw = json.loads(source_leaks_json)
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list) or not 1 <= len(raw) <= 100:
            return json.dumps({"success": False, "error": "Provide 1-100 source leaks"})
        entries: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                return json.dumps({"success": False, "error": "Each source leak must be an object"})
            candidate = dict(item)
            candidate["kind"] = "source_leak"
            if not candidate.get("value"):
                candidate["value"] = candidate.get("source_location", "")
            observation = ReconObservation.model_validate(candidate)
            entry = observation.model_dump(exclude={"screenshot_path"})
            _validate_source_leak(entry)
            entries.append(entry)
        inner = ctx.context
        result = await asyncio.to_thread(
            _save,
            Path(inner["state_dir"]).parent,
            entries,
            inner.get("agent_id"),
        )
        return json.dumps(result, ensure_ascii=False)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return json.dumps({"success": False, "error": str(exc)})


@function_tool
async def list_recon(ctx: RunContextWrapper, query: str = "", limit: int = 30) -> str:
    """Search this run's durable recon inventory before repeating discovery.

    Returns up to 100 observations; query matches URL, host, kind, title and
    technology. An empty result means no structured record, not a clean scan.
    """
    try:
        document = await asyncio.to_thread(read_recon, Path(ctx.context["state_dir"]).parent)
        matched = [
            entry for entry in document["entries"] if query.lower() in json.dumps(entry).lower()
        ]
        return json.dumps({"entries": matched[: max(1, min(limit, 100))], "total": len(matched)})
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return json.dumps({"success": False, "error": str(exc)})


@function_tool
async def finalize_recon(ctx: RunContextWrapper) -> str:
    """Finalize the complete recon inventory and snapshot it into shared memory.

    Root-only lifecycle step. Specialists must not be spawned until this tool
    succeeds. The operation is idempotent for a run and writes a durable marker
    so the ordering survives process recovery. Standard/deep live scans also
    require the mapper's recon coverage contract to be complete.
    """
    try:
        inner = ctx.context
        if inner.get("parent_id") is not None:
            return json.dumps({"success": False, "error": "Only the root agent can finalize recon"})
        state_dir = Path(inner["state_dir"])
        run_dir = state_dir.parent
        coordinator = inner.get("coordinator")
        if coordinator is not None:
            statuses = getattr(coordinator, "statuses", {})
            parents = getattr(coordinator, "parent_of", {})
            metadata_by_agent = getattr(coordinator, "metadata", {})
            active_mapper = any(
                status in {"running", "waiting"}
                and parents.get(agent_id) is not None
                and isinstance(metadata_by_agent.get(agent_id), dict)
                and metadata_by_agent[agent_id].get("role")
                in {"recon", "source_mapper"}
                for agent_id, status in statuses.items()
            )
            if active_mapper:
                return json.dumps(
                    {
                        "success": False,
                        "error": "Recon mapper is still active; wait for its complete handoff.",
                    }
                )
        names = getattr(coordinator, "names", {})
        agent_id = inner.get("agent_id") if isinstance(inner.get("agent_id"), str) else None
        agent_name = names.get(agent_id) if isinstance(names, dict) and agent_id else None
        result = await asyncio.to_thread(
            _finalize_recon_sync,
            run_dir,
            state_dir,
            agent_id=agent_id,
            agent_name=agent_name if isinstance(agent_name, str) else None,
            required_coverage=_required_coverage(
                scan_mode=str(inner.get("scan_mode") or ""),
                target_types=inner.get("scan_target_types"),
            ),
        )
        if result.get("success"):
            inner["recon_finalized"] = True
            if coordinator is not None:
                coordinator.recon_finalized = True
            supervisor = inner.get("supervisor")
            if supervisor is not None:
                with contextlib.suppress(Exception):
                    await supervisor.transition(
                        "recon_finalized",
                        reason="recon_snapshot_persisted",
                        metadata={
                            "recon_entry_count": result.get("entry_count", 0),
                            "recon_memory_chunks": result.get("memory_chunks", 0),
                        },
                    )
        return json.dumps(result, ensure_ascii=False)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return json.dumps({"success": False, "error": str(exc)})
