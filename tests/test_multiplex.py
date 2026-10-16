"""协议嗅探与转发的单元测试。

这台机器的回环 TCP 上有一层转发（客户端本地端口 55794，服务端 accept
到的却是 55802），并且**先开始等待的阻塞读取不会被后来的数据唤醒**。
因此这里刻意不写「客户端先连、稍后再发、服务端阻塞等」这类合成用例 ——
那种前提在本机不成立，会稳定误报。

转发路径的真实覆盖放在 tests/test_server.py 里：
``test_http_is_routed_to_the_web_backend`` 与
``test_ftp_and_http_share_the_same_port`` 走的是生产代码路径。
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from ftpd.multiplex import (
    _inject_forwarded_for,
    _read_http_head,
    classify_head,
    classify_protocol,
    close_quietly,
    proxy_to,
    request_host,
    request_path,
)


def _pair():
    a, b = socket.socketpair()
    return a, b


# --------------------------------------------------------------------------
# 协议嗅探
# --------------------------------------------------------------------------

def test_http_request_is_detected():
    a, b = _pair()
    try:
        b.sendall(b"GET /webgui HTTP/1.1\r\nHost: x\r\n\r\n")
        assert classify_protocol(a, 0.3) == "http"
        # 窥探不能消费数据
        assert a.recv(4) == b"GET "
    finally:
        close_quietly(a)
        close_quietly(b)


@pytest.mark.parametrize(
    "payload",
    [b"POST /x HTTP/1.1\r\n", b"HEAD / HTTP/1.0\r\n", b"PRI * HTTP/2.0\r\n"],
)
def test_various_http_methods(payload):
    a, b = _pair()
    try:
        b.sendall(payload)
        assert classify_protocol(a, 0.3) == "http"
    finally:
        close_quietly(a)
        close_quietly(b)


def test_pipelined_ftp_command_is_detected_as_ftp():
    a, b = _pair()
    try:
        b.sendall(b"USER alice\r\n")
        assert classify_protocol(a, 0.3) == "ftp"
    finally:
        close_quietly(a)
        close_quietly(b)


def test_silent_peer_is_treated_as_ftp():
    """FTP 客户端会等服务器先发问候语，所以沉默就是 FTP。"""
    a, b = _pair()
    try:
        started = time.monotonic()
        assert classify_protocol(a, 0.15) == "ftp"
        assert time.monotonic() - started >= 0.14
    finally:
        close_quietly(a)
        close_quietly(b)


def test_closed_peer_is_reported():
    a, b = _pair()
    b.close()
    try:
        assert classify_protocol(a, 0.3) == "closed"
    finally:
        close_quietly(a)


def test_classify_restores_blocking_mode():
    a, b = _pair()
    try:
        a.setblocking(True)
        classify_protocol(a, 0.05)
        assert a.gettimeout() is None
    finally:
        close_quietly(a)
        close_quietly(b)


# --------------------------------------------------------------------------
# 转发
# --------------------------------------------------------------------------

def _start_echo_backend() -> int:
    """一个收到什么就回什么的 TCP 后端。"""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def run() -> None:
        try:
            conn, _ = server.accept()
            data = conn.recv(64)
            conn.sendall(b"PONG:" + data)
            conn.close()
        finally:
            server.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def _start_front(backend_port: int):
    """一个只接受一条连接、随后交给 proxy_to 的前端。"""
    front = socket.socket()
    front.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    front.bind(("127.0.0.1", 0))
    front.listen(1)
    front_port = front.getsockname()[1]

    def run() -> None:
        try:
            conn, _ = front.accept()
            proxy_to(conn, ("127.0.0.1", backend_port))
        finally:
            front.close()

    threading.Thread(target=run, daemon=True).start()
    return front_port


def test_proxy_to_handles_large_payload():
    """来回各 256 KB，确认分片与背压都正常。"""
    payload = bytes(range(256)) * 1024  # 256 KB

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    backend_port = server.getsockname()[1]

    def backend() -> None:
        try:
            conn, _ = server.accept()
            received = b""
            while len(received) < len(payload):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                received += chunk
            conn.sendall(received)  # 原样送回
            conn.close()
        finally:
            server.close()

    threading.Thread(target=backend, daemon=True).start()
    front_port = _start_front(backend_port)

    client = socket.create_connection(("127.0.0.1", front_port), timeout=20)
    client.settimeout(20)
    try:
        client.sendall(payload)
        echoed = b""
        while len(echoed) < len(payload):
            chunk = client.recv(65536)
            if not chunk:
                break
            echoed += chunk
        assert echoed == payload
    finally:
        close_quietly(client)


def test_proxy_to_reports_unreachable_backend():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    dead_port = probe.getsockname()[1]
    probe.close()

    front = socket.socket()
    front.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    front.bind(("127.0.0.1", 0))
    front.listen(1)
    front_port = front.getsockname()[1]

    def run() -> None:
        try:
            conn, _ = front.accept()
            proxy_to(conn, ("127.0.0.1", dead_port))
        finally:
            front.close()

    threading.Thread(target=run, daemon=True).start()

    client = socket.create_connection(("127.0.0.1", front_port), timeout=8)
    client.settimeout(8)
    try:
        assert b"502" in client.recv(4096)
    finally:
        close_quietly(client)


# --------------------------------------------------------------------------
# X-Forwarded-For 注入（让 Web 后端看到真实客户端 IP）
# --------------------------------------------------------------------------

def test_inject_forwarded_for_adds_header():
    raw = b"GET /webgui HTTP/1.1\r\nHost: x\r\n\r\n"
    out = _inject_forwarded_for(raw, "192.168.1.7")
    assert b"X-Forwarded-For: 192.168.1.7" in out
    assert out.startswith(b"GET /webgui HTTP/1.1\r\n")
    assert out.endswith(b"\r\n\r\n")


def test_inject_forwarded_for_keeps_body():
    raw = b"POST /x HTTP/1.1\r\nHost: x\r\n\r\nBODY"
    out = _inject_forwarded_for(raw, "10.0.0.1")
    assert out.endswith(b"\r\n\r\nBODY")
    assert b"X-Forwarded-For: 10.0.0.1" in out


def test_inject_forwarded_for_is_idempotent():
    raw = b"GET / HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n"
    assert _inject_forwarded_for(raw, "10.0.0.7") == raw


def test_inject_forwarded_for_leaves_partial_head_alone():
    raw = b"GET / HTTP/1.1\r\nHost: x"
    assert _inject_forwarded_for(raw, "10.0.0.7") == raw


def test_read_http_head_reads_up_to_blank_line():
    a, b = _pair()
    try:
        b.sendall(b"GET /win HTTP/1.1\r\nHost: x\r\n\r\nleftover")
        head = _read_http_head(a, timeout=2.0)
        assert head.startswith(b"GET /win")
        assert b"\r\n\r\n" in head
    finally:
        close_quietly(a)
        close_quietly(b)


# --------------------------------------------------------------------------
# TLS 嗅探与请求行解析
# --------------------------------------------------------------------------

def test_classify_head_detects_tls():
    # TLS ClientHello：content-type=22(0x16), version major=3
    assert classify_head(b"\x16\x03\x01\x00\xa5\x01\x00\x00") == "tls"
    assert classify_head(b"GET /web") == "http"
    assert classify_head(b"USER al") == "ftp"


def test_classify_protocol_detects_tls_handshake():
    a, b = _pair()
    try:
        b.sendall(bytes([0x16, 0x03, 0x01, 0x00, 0xA5, 0x01, 0x00, 0x00]))
        assert classify_protocol(a, 0.3) == "tls"
        # 依然不能消费数据：TLS 握手得完整交给后端
        assert a.recv(2) == bytes([0x16, 0x03])
    finally:
        close_quietly(a)
        close_quietly(b)


def test_request_path_and_host_parsing():
    head = b"GET /webgui/ HTTP/1.1\r\nHost: 192.168.1.5:2121\r\n\r\n"
    assert request_path(head) == "/webgui/"
    assert request_host(head) == "192.168.1.5"


def test_request_parsing_is_forgiving():
    assert request_path(b"junk") == "/"
    assert request_host(b"junk") == ""
    assert request_path(b"") == "/"


# --------------------------------------------------------------------------
# 自适应宽限期（默认关闭，见 net.adaptive_classify_grace 的说明）
# --------------------------------------------------------------------------

def test_adaptive_grace_follows_kernel_rtt(monkeypatch):
    from ftpd import net

    monkeypatch.setattr(net, "connection_rtt", lambda sock: 0.001)  # 1ms
    grace = net.adaptive_classify_grace(None, ceiling=0.15)
    assert 0.007 <= grace <= 0.011          # 3ms + 5ms margin


def test_adaptive_grace_falls_back_to_ceiling(monkeypatch):
    from ftpd import net

    monkeypatch.setattr(net, "connection_rtt", lambda sock: None)
    assert net.adaptive_classify_grace(None, ceiling=0.15) == 0.15


def test_adaptive_grace_never_exceeds_ceiling(monkeypatch):
    from ftpd import net

    monkeypatch.setattr(net, "connection_rtt", lambda sock: 1.0)    # 1 秒
    assert net.adaptive_classify_grace(None, ceiling=0.15) == 0.15


def test_connection_rtt_is_none_for_non_tcp():
    a, b = _pair()   # AF_UNIX socketpair：没有 TCP_INFO
    try:
        from ftpd.net import connection_rtt

        assert connection_rtt(a) is None
    finally:
        close_quietly(a)
        close_quietly(b)
