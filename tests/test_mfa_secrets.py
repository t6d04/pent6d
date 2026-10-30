from __future__ import annotations

from pathlib import Path

import pytest

from strix.tools.mfa_secrets import tools


class _Context:
    def __init__(self, state_dir: Path) -> None:
        self.context = {"state_dir": state_dir}


def test_totp_matches_rfc6238_sha1_vector() -> None:
    secret, metadata = tools._normalize_secret(
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    )
    code, valid_for = tools._totp(secret, metadata, 59)
    assert code == "287082"
    assert valid_for == 1


def test_store_keeps_secret_and_qr_in_run_state(tmp_path: Path) -> None:
    context = _Context(tmp_path)
    image = tmp_path / "enrollment.png"
    image.write_bytes(b"fake-png")
    secret, metadata = tools._normalize_secret("JBSWY3DPEHPK3PXP")
    root, secret_path, metadata_path = tools._paths(context, "login")

    result = tools._store_sync(
        root=root,
        secret_path=secret_path,
        metadata_path=metadata_path,
        secret=secret,
        metadata=metadata,
        qr_image_path=str(image),
    )

    assert result["success"] is True
    assert result["qr_image_saved"] is True
    assert secret_path.read_text(encoding="utf-8").strip() == "JBSWY3DPEHPK3PXP"
    assert Path(str(result["qr_image_path"])).read_bytes() == b"fake-png"
    assert "JBSWY3DPEHPK3PXP" not in metadata_path.read_text(encoding="utf-8")


def test_otpauth_uri_preserves_algorithm_settings() -> None:
    secret, metadata = tools._normalize_secret(
        "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60"
    )
    assert secret == "JBSWY3DPEHPK3PXP"  # noqa: S105
    assert metadata == {"algorithm": "SHA256", "digits": 8, "period": 60}


def test_secret_validation_rejects_non_base32() -> None:
    with pytest.raises(ValueError, match="base32"):
        tools._normalize_secret("not-a-secret!")
