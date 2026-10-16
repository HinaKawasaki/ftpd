"""路径与默认值。

应用数据（用户数据库、TLS 证书）默认放在 XDG 数据目录下：
    ~/.local/share/ftpd/

可用环境变量覆盖：
    FTPD_HOME   整个数据目录
    FTPD_DB     仅数据库文件
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "ftpd"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 2121

#: 用户不指定时，默认共享整个家目录
def default_share_dir() -> Path:
    return Path.home()


def data_dir() -> Path:
    """应用数据目录，不存在则创建。"""
    override = os.environ.get("FTPD_HOME")
    if override:
        path = Path(override).expanduser()
    else:
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "share"
        path = base / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    """用户数据库文件路径。"""
    override = os.environ.get("FTPD_DB")
    if override:
        path = Path(override).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        return path
    return data_dir() / "users.db"


def tls_dir() -> Path:
    path = data_dir() / "tls"
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_certfile() -> Path:
    return tls_dir() / "cert.pem"


def default_keyfile() -> Path:
    return tls_dir() / "key.pem"
