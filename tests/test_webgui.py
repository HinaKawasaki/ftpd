"""端到端测试：Web 控制台与 FTP 共用同一个端口。

这一组测试走的是**生产代码路径** —— 请求真的打到共享端口上，
由 :class:`ftpd.multiplex.MultiplexedFTPServer` 判定协议后再分流。
"""

from __future__ import annotations

import io
import socket
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

import ftplib
import pytest

from ftpd.db import UserDB
from ftpd.server import FTPService, ServerConfig
from ftpd.webgui import LogBuffer, WebBackend, WebConsole


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for(predicate, timeout=20.0, interval=0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def http_get(port: int, path: str, timeout: float = 15.0):
    url = f"http://127.0.0.1:{port}{path}"
    request = urllib.request.Request(url, headers={"User-Agent": "ftpd-test"})
    return urllib.request.urlopen(request, timeout=timeout)


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    """整套应用起一次：内部 Web 后端 + 共享端口上的协议复用前端。"""
    tmp = tmp_path_factory.mktemp("webgui")
    db = UserDB(tmp / "users.db")
    logs = LogBuffer()
    service = FTPService(db, on_event=logs.append)
    console = WebConsole(db, service, logs)

    backend = WebBackend(console)
    web_port = backend.start()

    if not wait_for(lambda: _backend_ready(web_port), timeout=20):
        backend.stop()
        db.close()
        pytest.fail("内部 Web 后端没有起来")

    port = free_port()
    service.serve(port, http_target=("127.0.0.1", web_port), host="127.0.0.1")

    shared = SimpleNamespace(
        db=db, service=service, backend=backend, logs=logs,
        port=port, web_port=web_port,
    )
    yield shared

    service.shutdown()
    backend.stop()
    db.close()


def _backend_ready(web_port: int) -> bool:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{web_port}/healthz", timeout=2
        ) as response:
            return response.status == 200
    except Exception:
        return False


# --------------------------------------------------------------------------
# HTTP 侧
# --------------------------------------------------------------------------

def test_webgui_is_served_on_the_shared_port(stack):
    with http_get(stack.port, "/webgui") as response:
        body = response.read()
    assert response.status == 200
    assert b"<html" in body.lower()


def test_healthz_through_the_shared_port(stack):
    with http_get(stack.port, "/healthz") as response:
        payload = response.read()
    assert response.status == 200
    assert b'"ok"' in payload


def test_root_redirects_to_webgui(stack):
    opener = urllib.request.build_opener(NoRedirect())
    try:
        opener.open(f"http://127.0.0.1:{stack.port}/", timeout=10)
        status = 200
        location = ""
    except urllib.error.HTTPError as exc:
        status = exc.code
        location = exc.headers.get("Location", "")
    assert status in (301, 302, 303, 307, 308)
    assert location.rstrip("/").endswith("/webgui")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


# --------------------------------------------------------------------------
# FTP 侧：同一个端口
# --------------------------------------------------------------------------

def test_ftp_login_on_the_same_port(stack, tmp_path):
    share = tmp_path / "share"
    share.mkdir()
    (share / "hello.txt").write_text("hello web+ftp\n", encoding="utf-8")

    stack.db.add_user("alice", "secret123")
    stack.service.enable(ServerConfig(directory=share, readonly=True))
    assert wait_for(lambda: stack.service.ftp_enabled), "FTP 应当已启用"

    ftp = ftplib.FTP()
    ftp.connect("127.0.0.1", stack.port, timeout=15)
    try:
        ftp.login("alice", "secret123")
        assert ftp.nlst() == ["hello.txt"]
        buffer = io.BytesIO()
        ftp.retrbinary("RETR hello.txt", buffer.write)
        assert buffer.getvalue() == b"hello web+ftp\n"
    finally:
        ftp.quit()


def test_web_still_works_while_ftp_is_running(stack):
    assert stack.service.ftp_enabled is True
    with http_get(stack.port, "/webgui") as response:
        assert response.status == 200


def test_web_still_works_after_ftp_is_stopped(stack):
    stack.service.disable()
    assert wait_for(lambda: not stack.service.ftp_enabled)
    with http_get(stack.port, "/webgui") as response:
        assert response.status == 200
    assert stack.service.running is True


def test_error_log_is_collected(stack):
    assert any("共享端口" in line or "FTP" in line for line in stack.logs.snapshot())
