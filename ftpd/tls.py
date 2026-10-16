"""自签 TLS 证书的生成。

FTPS 和 Web 控制台的 HTTPS 用的是同一张证书。这里直接调用系统的
``openssl`` 命令行生成，避免为了一个功能再引入 heavy 的 ``cryptography`` 依赖。

证书的 SAN 里会带上本机的局域网 IP —— 否则用 IP 访问时浏览器会额外报
「名称不匹配」，虽然自签证书本来就要手动信任，但少一个错误少一分困惑。
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import List, Union

from .net import local_ipv4_addresses

DEFAULT_DAYS = 3650  # 10 年，自签证书，省得过期


class TLSError(RuntimeError):
    """证书生成失败。"""


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def _subject_alt_names(common_name: str) -> str:
    entries: List[str] = [
        f"DNS:{common_name}",
        "DNS:localhost",
    ]
    seen = {common_name, "localhost"}
    for ip in ["127.0.0.1", "::1", *local_ipv4_addresses()]:
        if ip in seen:
            continue
        seen.add(ip)
        entries.append(f"IP:{ip}")
    return ",".join(entries)


def generate_self_signed_cert(
    certfile: Union[str, Path],
    keyfile: Union[str, Path],
    *,
    common_name: str = "ftpd",
    days: int = DEFAULT_DAYS,
    key_size: int = 2048,
) -> tuple[Path, Path]:
    """生成自签证书与私钥，返回 (certfile, keyfile)。重复调用会覆盖。"""
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
        "-addext", f"subjectAltName={_subject_alt_names(common_name)}",
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


def ensure_self_signed_cert(
    certfile: Union[str, Path],
    keyfile: Union[str, Path],
    *,
    common_name: str = "ftpd",
) -> tuple[Path, Path]:
    """证书已存在就直接用，不存在才生成。"""
    if cert_exists(certfile, keyfile):
        return Path(certfile).expanduser(), Path(keyfile).expanduser()
    return generate_self_signed_cert(certfile, keyfile, common_name=common_name)
