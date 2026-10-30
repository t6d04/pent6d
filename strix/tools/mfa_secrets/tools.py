"""Private run-scoped MFA secret storage for authorized test identities.

The connector stores a TOTP seed as a local secret file and optionally keeps
the QR image used during enrollment.  It deliberately does not write either
value to shared memory, reports, logs, or tool output.  ``mfa_totp_code`` is
the only operation that returns a derived one-time code to the calling agent.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import re
import shutil
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from agents import RunContextWrapper, function_tool


_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SECRET_RE = re.compile(r"^[A-Z2-7]{8,256}$")
_IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".webp"}
_MAX_IMAGE_BYTES = 10 * 1024 * 1024
_DEFAULT_PERIOD = 30
_DEFAULT_DIGITS = 6
_DEFAULT_ALGORITHM = "SHA1"


def _state_dir(ctx: RunContextWrapper) -> Path:
    context = ctx.context if isinstance(ctx.context, dict) else {}
    raw = context.get("state_dir")
    if isinstance(raw, Path):
        state_dir = raw
    elif isinstance(raw, str) and raw.strip():
        state_dir = Path(raw)
    else:
        raise ValueError("run state_dir is unavailable; MFA secrets cannot be stored")
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


def _label(label: str) -> str:
    value = label.strip()
    if not _LABEL_RE.fullmatch(value):
        raise ValueError("label must contain only letters, numbers, '.', '-' or '_'")
    return value


def _paths(ctx: RunContextWrapper, label: str) -> tuple[Path, Path, Path]:
    safe_label = _label(label)
    root = _state_dir(ctx) / "mfa_secrets"
    return root, root / f"{safe_label}.secret", root / f"{safe_label}.json"


def _normalize_secret(value: str) -> tuple[str, dict[str, Any]]:
    raw = value.strip()
    metadata: dict[str, Any] = {
        "algorithm": _DEFAULT_ALGORITHM,
        "digits": _DEFAULT_DIGITS,
        "period": _DEFAULT_PERIOD,
    }
    if raw.lower().startswith("otpauth://"):
        parsed = urlparse(raw)
        if parsed.scheme.lower() != "otpauth" or parsed.netloc.lower() != "totp":
            raise ValueError("only otpauth://totp URIs are supported")
        query = parse_qs(parsed.query)
        raw = query.get("secret", [""])[0]
        metadata["algorithm"] = query.get("algorithm", [_DEFAULT_ALGORITHM])[0].upper()
        try:
            metadata["digits"] = int(query.get("digits", [str(_DEFAULT_DIGITS)])[0])
            metadata["period"] = int(query.get("period", [str(_DEFAULT_PERIOD)])[0])
        except ValueError as exc:
            raise ValueError("otpauth digits and period must be integers") from exc
    secret = re.sub(r"[\s-]", "", raw).upper()
    if not _SECRET_RE.fullmatch(secret):
        raise ValueError("TOTP secret must be a base32 value")
    if metadata["algorithm"] not in {"SHA1", "SHA256", "SHA512"}:
        raise ValueError("TOTP algorithm must be SHA1, SHA256, or SHA512")
    if metadata["digits"] not in {6, 8}:
        raise ValueError("TOTP digits must be 6 or 8")
    if not 10 <= metadata["period"] <= 300:
        raise ValueError("TOTP period must be between 10 and 300 seconds")
    return secret, metadata


def _validate_metadata(metadata: dict[str, Any]) -> None:
    if metadata.get("algorithm") not in {"SHA1", "SHA256", "SHA512"}:
        raise ValueError("TOTP algorithm must be SHA1, SHA256, or SHA512")
    if metadata.get("digits") not in {6, 8}:
        raise ValueError("TOTP digits must be 6 or 8")
    if not isinstance(metadata.get("period"), int) or not 10 <= metadata["period"] <= 300:
        raise ValueError("TOTP period must be between 10 and 300 seconds")


def _metadata_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError("stored MFA metadata must be an object")
    return value


def _write_private(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    with contextlib.suppress(OSError):
        # Windows ACLs are inherited from the run directory; do not fail a
        # test solely because chmod is not supported by the host filesystem.
        path.chmod(0o600)


def _store_sync(
    *,
    root: Path,
    secret_path: Path,
    metadata_path: Path,
    secret: str,
    metadata: dict[str, Any],
    qr_image_path: str,
) -> dict[str, Any]:
    root.mkdir(parents=True, exist_ok=True)
    _write_private(secret_path, secret + "\n")
    result: dict[str, Any] = {
        "success": True,
        "label": secret_path.stem,
        "secret_path": str(secret_path),
        "qr_image_path": "",
        "qr_image_saved": False,
    }
    if qr_image_path.strip():
        source = Path(qr_image_path.strip())
        if not source.is_absolute() or not source.is_file():
            raise ValueError("qr_image_path must be an existing absolute image path")
        if source.suffix.lower() not in _IMAGE_SUFFIXES:
            raise ValueError("qr_image_path must be PNG, JPEG, or WEBP")
        if source.stat().st_size > _MAX_IMAGE_BYTES:
            raise ValueError("QR image is larger than 10 MiB")
        image_path = root / f"{secret_path.stem}{source.suffix.lower()}"
        shutil.copyfile(source, image_path)
        with contextlib.suppress(OSError):
            image_path.chmod(0o600)
        result["qr_image_path"] = str(image_path)
        result["qr_image_saved"] = True
    _write_private(
        metadata_path,
        json.dumps(
            {
                "label": secret_path.stem,
                "algorithm": metadata["algorithm"],
                "digits": metadata["digits"],
                "period": metadata["period"],
                "qr_image_path": result["qr_image_path"],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
    )
    return result


def _load(ctx: RunContextWrapper, label: str) -> tuple[str, dict[str, Any], Path, Path]:
    root, secret_path, metadata_path = _paths(ctx, label)
    if not secret_path.is_file() or not metadata_path.is_file():
        raise ValueError(f"No stored MFA secret for label {label!r}")
    secret, metadata = _normalize_secret(secret_path.read_text(encoding="utf-8"))
    try:
        stored_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("stored MFA metadata is unreadable") from exc
    stored_metadata = _metadata_object(stored_metadata)
    for key in ("algorithm", "digits", "period"):
        if key in stored_metadata:
            metadata[key] = stored_metadata[key]
    _validate_metadata(metadata)
    return secret, metadata, root, metadata_path


def _totp(secret: str, metadata: dict[str, Any], timestamp: int) -> tuple[str, int]:
    try:
        algorithm = str(metadata["algorithm"]).lower()
        digest = getattr(hashlib, algorithm)
        digits = int(metadata["digits"])
        period = int(metadata["period"])
        _validate_metadata(
            {"algorithm": str(metadata["algorithm"]).upper(), "digits": digits, "period": period}
        )
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(padded, casefold=True)
    except (AttributeError, binascii.Error, KeyError, ValueError) as exc:
        raise ValueError("stored MFA secret metadata is invalid") from exc
    counter = timestamp // period
    message = counter.to_bytes(8, "big")
    digest_bytes = hmac.new(key, message, digest).digest()
    offset = digest_bytes[-1] & 0x0F
    code_int = int.from_bytes(digest_bytes[offset : offset + 4], "big") & 0x7FFFFFFF
    code = str(code_int % (10**digits)).zfill(digits)
    return code, period - (timestamp % period)


@function_tool(timeout=30)
async def mfa_secret_store(
    ctx: RunContextWrapper,
    secret: str,
    qr_image_path: str = "",
    label: str = "primary",
) -> str:
    """Store a test-account TOTP secret and optional QR image in this run only."""
    try:
        normalized, metadata = _normalize_secret(secret)
        root, secret_path, metadata_path = _paths(ctx, label)
        result = await asyncio.to_thread(
            _store_sync,
            root=root,
            secret_path=secret_path,
            metadata_path=metadata_path,
            secret=normalized,
            metadata=metadata,
            qr_image_path=qr_image_path,
        )
        return json.dumps(result, ensure_ascii=False)
    except (OSError, ValueError) as exc:
        return json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False)


@function_tool(timeout=30)
async def mfa_secret_status(ctx: RunContextWrapper, label: str = "primary") -> str:
    """Check whether a run-scoped MFA secret and QR image are available."""
    try:
        _, _, root, metadata_path = _load(ctx, label)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata = _metadata_object(metadata)
        image_path = str(metadata.get("qr_image_path") or "")
        return json.dumps(
            {
                "success": True,
                "label": _label(label),
                "secret_stored": True,
                "qr_image_stored": bool(image_path and Path(image_path).is_file()),
                "storage_dir": str(root),
            },
            ensure_ascii=False,
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False)


@function_tool(timeout=30)
async def mfa_totp_code(ctx: RunContextWrapper, label: str = "primary") -> str:
    """Generate the current TOTP code from a stored run-scoped test secret."""
    try:
        secret, metadata, _, _ = await asyncio.to_thread(_load, ctx, label)
        code, valid_for = _totp(secret, metadata, int(time.time()))
        return json.dumps(
            {
                "success": True,
                "label": _label(label),
                "code": code,
                "valid_for_seconds": valid_for,
            },
            ensure_ascii=False,
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False)
