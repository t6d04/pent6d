"""Read-only IMAP tools for a dedicated authentication-test mailbox.

The connector intentionally has no send, delete, move, or mutation operation.
Credentials are read from the process environment, with an optional local
``.env.mailbox.local`` fallback.  Secrets never appear in tool results or logs.
"""

from __future__ import annotations

import asyncio
import contextlib
import email
import email.header
import imaplib
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool


if TYPE_CHECKING:
    from email.message import Message


_DEFAULT_ENV_FILE = ".env.mailbox.local"
_DEFAULT_HOST = "imap.gmail.com"
_DEFAULT_PORT = 993
_MAX_RESULTS = 100
_MAX_BODY_CHARS = 100_000
_MAX_HEADER_CHARS = 2_000
_ENV_KEYS = {
    "PENT6D_TEST_MAILBOX_PROFILE",
    "PENT6D_TEST_MAILBOX_EMAIL",
    "PENT6D_TEST_MAILBOX_DOMAIN",
    "PENT6D_TEST_MAILBOX_FORWARDING",
    "PENT6D_TEST_MAILBOX_HOST",
    "PENT6D_TEST_MAILBOX_PORT",
    "PENT6D_TEST_MAILBOX_FOLDER",
    "PENT6D_TEST_MAILBOX_PASSWORD",
}


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
    env_file = Path(os.environ.get("PENT6D_MAILBOX_ENV_FILE", _DEFAULT_ENV_FILE))
    values = _parse_env_file(env_file)
    for key in _ENV_KEYS:
        if os.environ.get(key) is not None:
            values[key] = os.environ[key]
    return values


def _connection_config() -> tuple[str, int, str, str, str]:
    values = _config()
    host = values.get("PENT6D_TEST_MAILBOX_HOST") or _DEFAULT_HOST
    try:
        port = int(values.get("PENT6D_TEST_MAILBOX_PORT") or _DEFAULT_PORT)
    except ValueError as exc:
        raise ValueError("PENT6D_TEST_MAILBOX_PORT must be an integer") from exc
    username = values.get("PENT6D_TEST_MAILBOX_EMAIL", "").strip()
    password = values.get("PENT6D_TEST_MAILBOX_PASSWORD", "")
    folder = values.get("PENT6D_TEST_MAILBOX_FOLDER") or "INBOX"
    if not username:
        raise ValueError("PENT6D_TEST_MAILBOX_EMAIL is not configured")
    if not password:
        raise ValueError(
            "PENT6D_TEST_MAILBOX_PASSWORD is empty; configure the local secret or environment"
        )
    return host, port, username, password, folder


def _decode_header(value: str | None) -> str:
    if not value:
        return ""
    parts: list[str] = []
    for decoded, charset in email.header.decode_header(value):
        if isinstance(decoded, bytes):
            parts.append(decoded.decode(charset or "utf-8", errors="replace"))
        else:
            parts.append(decoded)
    return "".join(parts)[:_MAX_HEADER_CHARS]


def _header(message: Message, name: str) -> str:
    return _decode_header(message.get(name))


def _body(message: Message) -> str:
    chunks: list[str] = []
    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes):
            continue
        charset = part.get_content_charset() or "utf-8"
        chunks.append(payload.decode(charset, errors="replace"))
    return "\n\n".join(chunks)[:_MAX_BODY_CHARS]


def _search_sync(
    *,
    query: str,
    to_address: str,
    from_address: str,
    subject: str,
    since: str,
    limit: int,
) -> dict[str, Any]:
    host, port, username, password, folder = _connection_config()
    criteria = ["ALL"]
    if to_address.strip():
        criteria.extend(["TO", f'"{to_address.strip()}"'])
    if from_address.strip():
        criteria.extend(["FROM", f'"{from_address.strip()}"'])
    if subject.strip():
        criteria.extend(["SUBJECT", f'"{subject.strip()}"'])
    if since.strip():
        parsed = datetime.fromisoformat(since.strip().replace("Z", "+00:00"))
        criteria.extend(["SINCE", parsed.strftime("%d-%b-%Y")])
    # ``query`` is a local post-filter, avoiding provider-specific IMAP query
    # extensions and preventing arbitrary command fragments from being sent.
    wanted = query.strip().lower()
    connection = imaplib.IMAP4_SSL(host, port)
    try:
        connection.login(username, password)
        status, _ = connection.select(folder, readonly=True)
        if status != "OK":
            raise RuntimeError(f"Could not select mailbox folder {folder!r}")
        status, payload = connection.uid("search", None, *criteria)  # type: ignore[arg-type]
        if status != "OK" or not payload or not payload[0]:
            return {"success": True, "folder": folder, "messages": [], "count": 0}
        uids = payload[0].split()[-limit:]
        messages: list[dict[str, Any]] = []
        for uid in reversed(uids):
            status, fetched = connection.uid("fetch", uid, "(BODY.PEEK[HEADER])")
            if status != "OK" or not fetched:
                continue
            raw = next((item[1] for item in fetched if isinstance(item, tuple)), b"")
            if not isinstance(raw, bytes):
                continue
            parsed_message = email.message_from_bytes(raw)
            row = {
                "uid": uid.decode(errors="replace"),
                "message_id": _header(parsed_message, "Message-ID"),
                "date": _header(parsed_message, "Date"),
                "from": _header(parsed_message, "From"),
                "to": _header(parsed_message, "To"),
                "subject": _header(parsed_message, "Subject"),
            }
            if wanted and wanted not in str(row).lower():
                continue
            messages.append(row)
        return {"success": True, "folder": folder, "messages": messages, "count": len(messages)}
    finally:
        with contextlib.suppress(imaplib.IMAP4.error, OSError):
            connection.logout()


def _read_sync(*, uid: str, folder: str) -> dict[str, Any]:
    host, port, username, password, configured_folder = _connection_config()
    selected_folder = folder.strip() or configured_folder
    if not re.fullmatch(r"[A-Za-z0-9._ -]{1,80}", selected_folder):
        raise ValueError("folder contains unsupported characters")
    if not re.fullmatch(r"[0-9]{1,40}", uid.strip()):
        raise ValueError("uid must be a numeric IMAP UID")
    connection = imaplib.IMAP4_SSL(host, port)
    try:
        connection.login(username, password)
        status, _ = connection.select(selected_folder, readonly=True)
        if status != "OK":
            raise RuntimeError(f"Could not select mailbox folder {selected_folder!r}")
        status, fetched = connection.uid("fetch", uid.strip(), "(BODY.PEEK[])" )
        if status != "OK" or not fetched:
            return {"success": False, "error": "message not found"}
        raw = next((item[1] for item in fetched if isinstance(item, tuple)), b"")
        if not isinstance(raw, bytes):
            return {"success": False, "error": "message body unavailable"}
        message = email.message_from_bytes(raw)
        return {
            "success": True,
            "folder": selected_folder,
            "uid": uid.strip(),
            "message_id": _header(message, "Message-ID"),
            "date": _header(message, "Date"),
            "from": _header(message, "From"),
            "to": _header(message, "To"),
            "subject": _header(message, "Subject"),
            "body": _body(message),
        }
    finally:
        with contextlib.suppress(imaplib.IMAP4.error, OSError):
            connection.logout()


@function_tool(timeout=30)
async def mailbox_status(ctx: RunContextWrapper) -> str:
    """Check whether the dedicated test mailbox is configured and reachable."""
    try:
        host, port, username, _, folder = _connection_config()
        return json.dumps(
            await asyncio.to_thread(
                _status_sync, host=host, port=port, username=username, folder=folder
            ),
            ensure_ascii=False,
        )
    except (OSError, ValueError, imaplib.IMAP4.error) as exc:
        return json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False)


def _status_sync(*, host: str, port: int, username: str, folder: str) -> dict[str, Any]:
    _, _, _, password, _ = _connection_config()
    connection = imaplib.IMAP4_SSL(host, port)
    try:
        connection.login(username, password)
        status, _ = connection.select(folder, readonly=True)
        return {
            "success": status == "OK",
            "host": host,
            "folder": folder,
            "account": username,
            "read_only": True,
        }
    finally:
        with contextlib.suppress(imaplib.IMAP4.error, OSError):
            connection.logout()


@function_tool(timeout=90)
async def mailbox_search(
    ctx: RunContextWrapper,
    query: str = "",
    to_address: str = "",
    from_address: str = "",
    subject: str = "",
    since: str = "",
    limit: int = 20,
) -> str:
    """Search the dedicated mailbox without mutating it.

    ``since`` is an ISO-8601 timestamp. Search results include metadata only;
    call ``mailbox_read`` with a returned UID to retrieve one message body.
    """
    try:
        bounded_limit = max(1, min(int(limit), _MAX_RESULTS))
        result = await asyncio.to_thread(
            _search_sync,
            query=query,
            to_address=to_address,
            from_address=from_address,
            subject=subject,
            since=since,
            limit=bounded_limit,
        )
        return json.dumps(result, ensure_ascii=False)
    except (OSError, ValueError, imaplib.IMAP4.error) as exc:
        return json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False)


@function_tool(timeout=90)
async def mailbox_read(
    ctx: RunContextWrapper,
    uid: str,
    folder: str = "",
) -> str:
    """Read one message body by IMAP UID; mailbox remains read-only."""
    try:
        result = await asyncio.to_thread(_read_sync, uid=uid, folder=folder)
        return json.dumps(result, ensure_ascii=False)
    except (OSError, ValueError, imaplib.IMAP4.error) as exc:
        return json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False)
