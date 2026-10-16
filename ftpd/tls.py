"""自签 TLS 证书的生成。

FTPS 需要一个证书。这里直接调用系统的 ``openssl`` 命令行生成自签证书，
避免为了一个功能再引入 heavy 的 ``cryptography`` 依赖。
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Union

DEFAULT_DAYS = 3650  # 10 年，自签证书，省得过期


class TLSError(RuntimeError):
    """证书生成失败。"""


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def generate_self_signed_cert(
    certfile: Union[str, Path],
    keyfile: Union[str, Path],
    *,
    common_name: str = "ftpd",
    days: int = DEFAULT_DAYS,
    key_size: int = 2048,
) -> tuple[Path, Path]:
    """生成自签证书与私钥，返回 (certfile, keyfile)。

    重复调用会覆盖已有文件。私钥以 0600 权限写入。
    """
    cert_path = Path(certfile).expanduser()
    key_path = Path(keyfile).expanduser()
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if not openssl_available():
        raise TLSError("系统里找不到 openssl 命令，无法生成自签证书")

    cmd = [
        "openssl", "req", "-x509", "-newkey", f"rsa:{key_size}", "-nodes",
        "-keyout", str(key_path),
        "-out", str(cert_path),
        "-days", str(days),
        "-subj", f"/CN={common_name}",
        "-addext", f"subjectAltName=DNS:{common_name},DNS:localhost,IP:127.0.0.1",
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TLSError(f"调用 openssl 失败：{exc}") from exc

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise TLSError(f"openssl 生成证书失败：{detail}")

    try:
        key_path.chmod(0o600)
    except OSError:
        pass  # 某些文件系统不支持改权限，不致命

    return cert_path, key_path


def cert_exists(certfile: Union[str, Path], keyfile: Union[str, Path]) -> bool:
    return Path(certfile).expanduser().is_file() and Path(keyfile).expanduser().is_file()
