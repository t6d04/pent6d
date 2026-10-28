"""Shared rate limiting for outbound model requests.

The web UI exposes the limit as ``N requests per seconds/minutes/hours``.
The state is kept in a small file under ``~/.strix`` so separate scan worker
processes also share the same limiter.  A disabled limit (the default) adds no
wait and does not create the state file.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from filelock import FileLock


if TYPE_CHECKING:
    from strix.config.settings import RateLimitUnit


logger = logging.getLogger(__name__)

_STATE_PATH = Path.home() / ".strix" / "llm-rate-limit.json"
_LOCK_PATH = _STATE_PATH.with_suffix(".lock")
_SECONDS_PER_UNIT: dict[str, float] = {
    "seconds": 1.0,
    "minutes": 60.0,
    "hours": 3600.0,
}


def _period_seconds(unit: RateLimitUnit | str) -> float:
    try:
        return _SECONDS_PER_UNIT[str(unit)]
    except KeyError as exc:
        raise ValueError(f"Unsupported rate-limit unit: {unit!r}") from exc


def _read_timestamps(path: Path) -> list[float]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, int | float)]


def _write_timestamps(path: Path, timestamps: list[float]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp-{time.time_ns()}")
    try:
        temporary.write_text(json.dumps(timestamps), encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _reserve_slot(requests: int, unit: RateLimitUnit | str, now: float) -> float:
    """Reserve one slot and return the required delay before the next try.

    The caller holds the inter-process lock while this function runs.  A
    sliding window is used, so bursts are allowed up to the configured count
    but the provider never receives more than that count in the selected
    period.
    """
    period = _period_seconds(unit)
    _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    with FileLock(str(_LOCK_PATH)):
        timestamps = [
            stamp for stamp in _read_timestamps(_STATE_PATH) if 0 <= now - stamp < period
        ]
        if len(timestamps) >= requests:
            oldest = min(timestamps)
            return max(0.0, oldest + period - now)
        timestamps.append(now)
        _write_timestamps(_STATE_PATH, timestamps)
    return 0.0


async def wait_for_model_slot(
    requests: int,
    unit: RateLimitUnit | str,
) -> None:
    """Wait until this process may issue one model request.

    ``requests == 0`` disables the limiter.  File I/O and lock acquisition are
    moved to a worker thread so the agent event loop remains responsive while
    several agents wait for the same provider quota.
    """
    if requests < 0:
        raise ValueError("rate-limit request count must be non-negative")
    if requests == 0:
        return
    period = _period_seconds(unit)
    while True:
        delay = await asyncio.to_thread(_reserve_slot, requests, unit, time.time())
        if delay <= 0:
            return
        logger.debug(
            "model rate limit reached (%d per %.0fs); waiting %.2fs",
            requests,
            period,
            delay,
        )
        await asyncio.sleep(delay)


__all__ = ["wait_for_model_slot"]
