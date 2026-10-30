"""Bounded HupSMS connector for authorized phone-verification workflows.

The provider API uses an API key in the query string.  The key is loaded from
the process environment or ``.env.hupsms.local`` and is never returned in a
tool result.  Agents receive only the data needed to complete the current
test (number, order state, OTP/SMS content, and expiration).
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from agents import RunContextWrapper, function_tool


_DEFAULT_ENV_FILE = ".env.hupsms.local"
_DEFAULT_BASE_URL = "https://hupsms.com/api/v1"
_ENV_KEYS = {"PENT6D_HUPSMS_API_KEY", "PENT6D_HUPSMS_BASE_URL"}
_REQUEST_TIMEOUT = (5, 30)
_ORDER_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_PHONE_RE = re.compile(r"^\+?[0-9]{8,15}$")
_NETWORK_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
_PREFIX_RE = re.compile(r"^[0-9]{1,15}(?:,[0-9]{1,15})*$")


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in _ENV_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def _config() -> dict[str, str]:
    env_file = Path(os.environ.get("PENT6D_HUPSMS_ENV_FILE", _DEFAULT_ENV_FILE))
    values = _parse_env_file(env_file)
    for key in _ENV_KEYS:
        if os.environ.get(key) is not None:
            values[key] = os.environ[key]
    return values


def _connection_config() -> tuple[str, str]:
    values = _config()
    api_key = values.get("PENT6D_HUPSMS_API_KEY", "").strip()
    if not api_key:
        raise ValueError(
            "PENT6D_HUPSMS_API_KEY is not configured; set it in .env.hupsms.local "
            "or the process environment"
        )
    base_url = values.get("PENT6D_HUPSMS_BASE_URL", _DEFAULT_BASE_URL).strip().rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username:
        raise ValueError("PENT6D_HUPSMS_BASE_URL must be an HTTP(S) URL without credentials")
    return base_url, api_key


def _safe_text(value: Any, limit: int = 20_000) -> str:
    return str(value)[:limit]


def _redact_secret(value: Any, secret: str) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_secret(item, secret) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_secret(item, secret) for item in value[:100]]
    if isinstance(value, str):
        return value.replace(secret, "[REDACTED]")[:20_000]
    return value


def _request(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    base_url, api_key = _connection_config()
    query = dict(params or {})
    query["api_key"] = api_key
    try:
        response = requests.get(
            f"{base_url}/{path.lstrip('/')}",
            params=query,
            timeout=_REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"success": False, "provider": "hupsms", "error": _safe_text(exc)}

    try:
        payload = response.json()
    except ValueError:
        payload = {"message": response.text[:2_000]}

    if not isinstance(payload, dict):
        payload = {"data": payload}
    provider_status = payload.get("status")
    result: dict[str, Any] = {
        "success": response.ok and provider_status == "success",
        "provider": "hupsms",
        "http_status": response.status_code,
        **payload,
    }
    # The API key must never reach the model, logs, or an evidence artifact.
    redacted = _redact_secret(result, api_key)
    return (
        redacted
        if isinstance(redacted, dict)
        else {"success": False, "error": "invalid response"}
    )


async def _call(path: str, params: dict[str, Any] | None = None) -> str:
    try:
        result = await asyncio.to_thread(_request, path, params)
    except (OSError, ValueError) as exc:
        result = {"success": False, "provider": "hupsms", "error": str(exc)}
    return json.dumps(result, ensure_ascii=False)


def _validate_order_id(order_id: str) -> str:
    value = order_id.strip()
    if not _ORDER_ID_RE.fullmatch(value):
        raise ValueError("order_id contains unsupported characters")
    return value


def _validate_phone(phone: str) -> str:
    value = phone.strip().replace(" ", "")
    if not _PHONE_RE.fullmatch(value):
        raise ValueError("phone must contain 8-15 digits, with an optional leading +")
    return value


@function_tool(timeout=45)
async def hupsms_balance(ctx: RunContextWrapper) -> str:
    """Check the HupSMS account balance before reserving a test number."""
    return await _call("balance")


@function_tool(timeout=45)
async def hupsms_services(ctx: RunContextWrapper, server: int | None = None) -> str:
    """List available OTP services and prices; optionally filter by server id."""
    if server is not None and (server < 1 or server > 10_000):
        return json.dumps({"success": False, "error": "server must be between 1 and 10000"})
    return await _call("services", {"server": server} if server is not None else None)


@function_tool(timeout=45)
async def hupsms_rent(
    ctx: RunContextWrapper,
    service_id: int,
    network: str = "",
    prefix: str = "",
) -> str:
    """Rent a temporary number for an explicitly authorized signup/OTP test."""
    if service_id < 1 or service_id > 1_000_000:
        return json.dumps({"success": False, "error": "service_id must be positive"})
    params: dict[str, Any] = {"serviceId": service_id}
    if network:
        value = network.strip().lower()
        if not _NETWORK_RE.fullmatch(value):
            return json.dumps({"success": False, "error": "invalid network"})
        params["network"] = value
    if prefix:
        value = prefix.strip()
        if not _PREFIX_RE.fullmatch(value) or len(value.split(",")) > 15:
            return json.dumps({"success": False, "error": "invalid prefix list"})
        params["prefix"] = value
    return await _call("rent", params)


@function_tool(timeout=45)
async def hupsms_check(ctx: RunContextWrapper, order_id: str) -> str:
    """Check one rented number for a pending, received, cancelled, or expired OTP."""
    try:
        value = _validate_order_id(order_id)
    except ValueError as exc:
        return json.dumps({"success": False, "error": str(exc)})
    return await _call(f"check/{value}")


@function_tool(timeout=45)
async def hupsms_cancel(ctx: RunContextWrapper, order_id: str) -> str:
    """Cancel one still-pending rental; refund support depends on the provider server."""
    try:
        value = _validate_order_id(order_id)
    except ValueError as exc:
        return json.dumps({"success": False, "error": str(exc)})
    return await _call(f"cancel/{value}")


@function_tool(timeout=45)
async def hupsms_rerent(ctx: RunContextWrapper, phone: str) -> str:
    """Request a new OTP rental for a previously rented phone number."""
    try:
        value = _validate_phone(phone)
    except ValueError as exc:
        return json.dumps({"success": False, "error": str(exc)})
    return await _call("rerent", {"phone": value})
