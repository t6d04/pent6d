from __future__ import annotations

from typing import TYPE_CHECKING

from strix.tools.mailbox import tools


if TYPE_CHECKING:
    from pathlib import Path

    import pytest


def test_mailbox_config_reads_local_file_without_exposing_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / "mailbox.env"
    env_file.write_text(
        "PENT6D_TEST_MAILBOX_EMAIL=test@gmail.com\n"
        "PENT6D_TEST_MAILBOX_PASSWORD=app-secret\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PENT6D_MAILBOX_ENV_FILE", str(env_file))
    host, port, username, password, folder = tools._connection_config()
    assert (host, port, username, password, folder) == (
        "imap.gmail.com",
        993,
        "test@gmail.com",
        "app-secret",
        "INBOX",
    )


def test_search_returns_headers_only(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeImap:
        def __init__(self, _host: str, _port: int) -> None:
            pass

        def login(self, _username: str, _password: str) -> tuple[str, list[bytes]]:
            return "OK", [b"logged in"]

        def select(self, _folder: str, readonly: bool = True) -> tuple[str, list[bytes]]:
            assert readonly is True
            return "OK", [b"1"]

        def uid(self, action: str, _uid: object, *_args: object) -> tuple[str, list[object]]:
            assert action in {"search", "fetch"}
            if action == "search":
                return "OK", [b"7"]
            return "OK", [
                (
                    b"header",
                    b"From: sender@example.test\r\n"
                    b"To: test@gmail.com\r\n"
                    b"Subject: Verify\r\n"
                    b"Message-ID: <m1>\r\n\r\n",
                )
            ]

        def logout(self) -> tuple[str, list[bytes]]:
            return "OK", [b"logout"]

    monkeypatch.setattr(tools.imaplib, "IMAP4_SSL", FakeImap)
    monkeypatch.setenv("PENT6D_TEST_MAILBOX_EMAIL", "test@gmail.com")
    monkeypatch.setenv("PENT6D_TEST_MAILBOX_PASSWORD", "secret")
    result = tools._search_sync(
        query="verify",
        to_address="test@gmail.com",
        from_address="",
        subject="",
        since="",
        limit=10,
    )
    assert result["count"] == 1
    assert result["messages"][0]["subject"] == "Verify"
    assert "secret" not in str(result)
