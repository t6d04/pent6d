"""Fixed, versioned content-discovery wordlists for sandbox scans."""

from __future__ import annotations

from typing import Any

from strix.utils.resource_paths import get_strix_resource_path


_WORDLISTS = (
    ("seclists-common.txt", "/workspace/wordlists/seclists-common.txt"),
    ("dirsearch-dicc.txt", "/workspace/wordlists/dirsearch-dicc.txt"),
)


def bundled_fuzz_wordlists() -> list[dict[str, Any]]:
    """Return the fixed content-discovery lists staged into each sandbox.

    These assets live inside the package so source installs, wheels, and the
    standalone build all use the same reviewed files. Staging them as extra
    files avoids an agent downloading a mutable generic list at scan time.
    """
    entries: list[dict[str, Any]] = []
    for filename, workspace_path in _WORDLISTS:
        source = get_strix_resource_path("wordlists", filename)
        if not source.is_file():
            raise RuntimeError(f"Bundled fuzz wordlist is missing: {source}")
        entries.append(
            {"workspace_path": workspace_path, "content": source.read_bytes()}
        )
    return entries


__all__ = ["bundled_fuzz_wordlists"]
