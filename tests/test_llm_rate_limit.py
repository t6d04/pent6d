"""Tests for the shared model-request rate limiter."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from strix.llm import rate_limit


if TYPE_CHECKING:
    from pathlib import Path

    from pytest import MonkeyPatch


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    state = tmp_path / "llm-rate-limit.json"
    monkeypatch.setattr(rate_limit, "_STATE_PATH", state)
    monkeypatch.setattr(rate_limit, "_LOCK_PATH", tmp_path / "llm-rate-limit.lock")


def test_reserve_slot_uses_sliding_window() -> None:
    assert rate_limit._reserve_slot(2, "minutes", 100.0) == 0.0
    assert rate_limit._reserve_slot(2, "minutes", 101.0) == 0.0
    assert rate_limit._reserve_slot(2, "minutes", 102.0) == pytest.approx(58.0)
    # Once the oldest request expires, the slot is available again.
    assert rate_limit._reserve_slot(2, "minutes", 160.0) == 0.0


def test_disabled_limit_does_not_create_state_file() -> None:
    asyncio.run(rate_limit.wait_for_model_slot(0, "minutes"))
    assert not rate_limit._STATE_PATH.exists()


def test_invalid_unit_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unsupported rate-limit unit"):
        rate_limit._reserve_slot(1, "days", 100.0)


def test_negative_limit_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-negative"):
        asyncio.run(rate_limit.wait_for_model_slot(-1, "minutes"))
