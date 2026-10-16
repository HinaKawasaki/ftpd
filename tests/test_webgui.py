"""端到端测试：Web 控制台与 FTP 共用同一个端口。

这一组走的是**生产代码路径** —— 请求真的打到共享端口上，
由 :class:`ftpd.multiplex.MultiplexedFTPServer` 判定协议后再分流。

控制台默认只跑 HTTPS 后端（见 ``WebBackend.start`` 的说明），
所以这里用 HTTPS 访问控制台，另外单独验证明文请求会被 301 跳过去。
"""

from __future__ import annotations

import io
import socket
import ssl
import time
import urllib.error
import urllib.request
from types import SimpleNamespace

import ftplib
import pytest

from ftpd.db import UserDB
from ftpd.server import FTPService, ServerConfig
from ftpd.tls import generate_self_signed_cert
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


def https_get(port: int, path: str, timeout: float = 15.0):
    """通过共享端口用 HTTPS 取页面（自签证书，不校验）。"""
    context = ssl._create_unverified_context()
    request = urllib.request.Request(
        f"https://127.0.0.1:{port}{path}", headers={"User-Agent": "ftpd-test"}
    )
    return urllib.request.urlopen(request, timeout=timeout, context=context)


def http_get(port: int, path: str, timeout: float = 15.0):
    """明文 HTTP（控制台只跑 HTTPS 时应当被 301 跳走）。"""
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", headers={"User-Agent": "ftpd-test"}
    )
    return urllib.request.urlopen(request, timeout=timeout)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _https_ready(port: int) -> bool:
    try:
        with https_get(port, "/healthz", timeout=3) as response:
            return response.status == 200
    except Exception:
        return False


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    """整套应用起一次：HTTPS Web 后端 + 共享端口上的协议复用前端。"""
    tmp = tmp_path_factory.mktemp("webgui")
    db = UserDB(tmp / "users.db")
    logs = LogBuffer()
    service = FTPService(db, on_event=logs.append)
    console = WebConsole(db, service, logs)

    cert, key = generate_self_signed_cert(tmp / "cert.pem", tmp / "key.pem")
    backend = WebBackend(console)
    http_port, https_port = backend.start(certfile=cert, keyfile=key)

    if http_port is not None or not https_port:
        backend.stop()
        db.close()
        pytest.fail(f"期望只起 HTTPS 后端，实际 http={http_port} https={https_port}")

    if not wait_for(lambda: _https_ready(https_port), timeout=20):
        backend.stop()
        db.close()
        pytest.fail("内部 HTTPS 后端没有起来")

    port = free_port()
    service.serve(
        port,
        http_target=None,
        https_target=("127.0.0.1", https_port),
        host="127.0.0.1",
    )

    shared = SimpleNamespace(
        db=db, service=service, backend=backend, logs=logs,
        port=port, http_port=http_port, https_port=https_port,
    )
    yield shared

    service.shutdown()
    backend.stop()
    db.close()


# --------------------------------------------------------------------------
# 同一个端口上的三种流量
# --------------------------------------------------------------------------

def test_console_is_served_over_https_on_the_shared_port(stack):
    with https_get(stack.port, "/webgui") as response:
        body = response.read()
    assert response.status == 200
    assert b"<html" in body.lower()


def test_healthz_over_https(stack):
    with https_get(stack.port, "/healthz") as response:
        payload = response.read()
    assert response.status == 200
    assert payload.strip() == b'{"ok":true}'


def test_plain_http_is_redirected_to_https(stack):
    """只跑 HTTPS 后端时，明文请求应当被 301 跳到 https。"""
    opener = urllib.request.build_opener(NoRedirect())
    try:
        opener.open(f"http://127.0.0.1:{stack.port}/webgui/", timeout=10)
        status, location = 200, ""
    except urllib.error.HTTPError as exc:
        status, location = exc.code, exc.headers.get("Location", "")
    assert status in (301, 302, 307, 308), f"应当是跳转，实际 {status}"
    assert location.startswith("https://")
    assert location.endswith("/webgui/")


def test_root_redirects_to_webgui(stack):
    opener = urllib.request.build_opener(NoRedirect())
    context = ssl._create_unverified_context()
    https = urllib.request.HTTPSHandler(context=context)
    opener = urllib.request.build_opener(NoRedirect, https)
    try:
        opener.open(f"https://127.0.0.1:{stack.port}/", timeout=10)
        status, location = 200, ""
    except urllib.error.HTTPError as exc:
        status, location = exc.code, exc.headers.get("Location", "")
    assert status in (301, 302, 303, 307, 308)
    assert location.rstrip("/").endswith("/webgui")


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


def test_console_still_works_while_ftp_is_running(stack):
    assert stack.service.ftp_enabled is True
    with https_get(stack.port, "/webgui") as response:
        assert response.status == 200


def test_console_still_works_after_ftp_is_stopped(stack):
    stack.service.disable()
    assert wait_for(lambda: not stack.service.ftp_enabled)
    with https_get(stack.port, "/webgui") as response:
        assert response.status == 200
    assert stack.service.running is True


def test_error_log_is_collected(stack):
    assert any("共享端口" in line or "FTP" in line for line in stack.logs.snapshot())


# --------------------------------------------------------------------------
# 控制台登录鉴权
# --------------------------------------------------------------------------

def final_url(port: int, path: str, timeout: float = 15.0) -> str:
    """跟随重定向，返回最终落地的 URL。"""
    with https_get(port, path, timeout=timeout) as response:
        return response.geturl()


def test_console_goes_to_setup_when_no_admin(stack):
    """还没设管理员时，访问控制台会被引导去初始化。"""
    assert stack.db.admin_exists() is False
    assert final_url(stack.port, "/webgui").rstrip("/").endswith("/setup")


def test_console_requires_login_once_admin_exists(stack):
    stack.db.set_admin("admin", "adminpass1")
    assert final_url(stack.port, "/webgui").rstrip("/").endswith("/login")
    with https_get(stack.port, "/webgui/login") as response:
        assert response.status == 200
    # 退出登录后回到登录页
    assert final_url(stack.port, "/webgui/logout").rstrip("/").endswith("/login")
