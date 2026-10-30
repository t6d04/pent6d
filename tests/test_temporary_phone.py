from __future__ import annotations

from typing import Any

import pytest

from strix.tools.temporary_phone import tools


class _Response:
    ok = True
    status_code = 200

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def json(self) -> dict[str, Any]:
        return self.payload


def test_config_reads_local_file_without_returning_key(tmp_path, monkeypatch) -> None:
    env_file = tmp_path / "hupsms.env"
    env_file.write_text(
        "PENT6D_HUPSMS_API_KEY=local-secret\n"
        "PENT6D_HUPSMS_BASE_URL=https://stub.example/api/v1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("PENT6D_HUPSMS_ENV_FILE", str(env_file))
    assert tools._connection_config() == ("https://stub.example/api/v1", "local-secret")


def test_request_adds_key_and_redacts_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENT6D_HUPSMS_API_KEY", "local-secret")
    captured: dict[str, Any] = {}

    def fake_get(url: str, *, params: dict[str, Any], timeout: object) -> _Response:
        captured.update({"url": url, "params": params, "timeout": timeout})
        return _Response(
            {
                "status": "success",
                "message": "local-secret must not leak",
                "data": {"orderId": "HupSMS1", "phone": "0987654321"},
            }
        )

    monkeypatch.setattr(tools.requests, "get", fake_get)
    result = tools._request("rent", {"serviceId": 1})

    assert captured["url"] == "https://hupsms.com/api/v1/rent"
    assert captured["params"] == {"serviceId": 1, "api_key": "local-secret"}
    assert result["success"] is True
    assert "local-secret" not in str(result)


def test_validation_rejects_unsafe_order_and_phone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PENT6D_HUPSMS_API_KEY", "key")
    with pytest.raises(ValueError, match="unsupported"):
        tools._validate_order_id("bad/id")
    with pytest.raises(ValueError, match="8-15"):
        tools._validate_phone("123")


def test_missing_key_is_reported_without_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("PENT6D_HUPSMS_API_KEY", raising=False)
    monkeypatch.setenv("PENT6D_HUPSMS_ENV_FILE", "Z:\\missing\\hupsms.env")
    with pytest.raises(ValueError, match="PENT6D_HUPSMS_API_KEY"):
        tools._connection_config()
