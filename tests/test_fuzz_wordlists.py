"""Tests for fixed content-discovery wordlists."""

from __future__ import annotations

from strix.fuzz_wordlists import bundled_fuzz_wordlists


def test_bundled_fuzz_wordlists_are_staged_at_stable_paths() -> None:
    entries = bundled_fuzz_wordlists()

    assert [entry["workspace_path"] for entry in entries] == [
        "/workspace/wordlists/seclists-common.txt",
        "/workspace/wordlists/dirsearch-dicc.txt",
    ]
    assert all(entry["content"] for entry in entries)
