"""pytest 公共配置与夹具。

放在仓库根目录的 conftest.py 还有一个副作用：pytest 会把本目录
放进 sys.path，这样测试里可以直接 ``import ftpd``。
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture
def free_port() -> int:
    """要一个当前空闲的端口。"""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def db(tmp_path):
    from ftpd.db import UserDB

    database = UserDB(tmp_path / "users.db")
    yield database
    database.close()


@pytest.fixture
def share(tmp_path) -> Path:
    path = tmp_path / "share"
    path.mkdir()
    (path / "hello.txt").write_text("hello from ftpd\n", encoding="utf-8")
    return path
