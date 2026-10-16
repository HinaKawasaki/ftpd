"""服务层端到端测试：同端口同时接待 FTP 与 Web。"""

from __future__ import annotations

import ftplib
import io
import socket
import ssl
import threading
import time

import pytest

from ftpd.multiplex import close_quietly
from ftpd.server import FTPService, ServerConfig, ServiceError, local_ipv4_addresses
from ftpd.tls import generate_self_signed_cert


def make_config(share, **overrides) -> ServerConfig:
    params = dict(directory=share)
    params.update(overrides)
    return ServerConfig(**params)


def wait_for(predicate, timeout=6.0, interval=0.02) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def read_banner(port, host="127.0.0.1", timeout=8) -> bytes:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        return sock.recv(256)
    finally:
        sock.close()


def connect_ftp(port, user="alice", password="secret123"):
    ftp = ftplib.FTP()
    ftp.connect("127.0.0.1", port, timeout=10)
    ftp.login(user, password)
    return ftp


@pytest.fixture
def service(db):
    events: list[str] = []
    svc = FTPService(db, on_event=events.append)
    svc.events = events
    yield svc
    svc.shutdown()


def start_http_backend(body: bytes = b"HELLO") -> int:
    """一个只会回一次响应的极简 HTTP 后端。"""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def run() -> None:
        try:
            conn, _ = server.accept()
            conn.recv(8192)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            conn.close()
        finally:
            server.close()

    threading.Thread(target=run, daemon=True).start()
    return port


# --------------------------------------------------------------------------
# 前端（共享端口）
# --------------------------------------------------------------------------

def test_serve_occupies_the_port(service, free_port):
    service.serve(free_port)
    assert service.running is True
    # 端口确实在监听：未启用 FTP 时应收到 421 而不是连不上
    sock = socket.create_connection(("127.0.0.1", free_port), timeout=5)
    try:
        assert sock.recv(256).startswith(b"421")
    finally:
        sock.close()


def test_serve_twice_is_rejected(service, free_port):
    service.serve(free_port)
    with pytest.raises(ServiceError, match="已经在运行"):
        service.serve(free_port)


def test_serve_rejects_bad_port(service):
    with pytest.raises(ServiceError, match="端口号"):
        service.serve(0)


def test_port_conflict_is_reported(db, free_port):
    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("0.0.0.0", free_port))
    blocker.listen(1)
    svc = FTPService(db)
    try:
        with pytest.raises(ServiceError, match="无法监听"):
            svc.serve(free_port)
    finally:
        blocker.close()
        svc.shutdown()


def test_enable_requires_front_door(service, share):
    with pytest.raises(ServiceError, match="前端还没启动"):
        service.enable(make_config(share))


def test_enable_validates_directory(service, free_port, tmp_path):
    service.serve(free_port)
    with pytest.raises(ServiceError, match="共享目录"):
        service.enable(make_config(tmp_path / "nope"))


def test_enable_rejects_negative_auto_stop(service, free_port, share):
    service.serve(free_port)
    with pytest.raises(ServiceError, match="自动停止"):
        service.enable(make_config(share, auto_stop_minutes=-1))


def test_tls_enable_requires_certificate(service, free_port, share, tmp_path):
    service.serve(free_port)
    with pytest.raises(ServiceError):
        service.enable(
            make_config(
                share, use_tls=True,
                certfile=tmp_path / "c.pem", keyfile=tmp_path / "k.pem",
            )
        )


# --------------------------------------------------------------------------
# FTP 功能
# --------------------------------------------------------------------------

def test_ftp_disabled_then_enabled(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    assert service.ftp_enabled is False

    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled), "FTP 应当被启用"

    ftp = connect_ftp(free_port)
    try:
        assert ftp.nlst() == ["hello.txt"]
        buf = io.BytesIO()
        ftp.retrbinary("RETR hello.txt", buf.write)
        assert buf.getvalue() == b"hello from ftpd\n"
    finally:
        ftp.quit()


def test_ftp_stays_disabled_when_not_enabled(service, free_port):
    service.serve(free_port)
    assert read_banner(free_port).startswith(b"421")


def test_readonly_blocks_upload(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share, readonly=True))
    assert wait_for(lambda: service.ftp_enabled)

    ftp = connect_ftp(free_port)
    try:
        with pytest.raises(ftplib.error_perm):
            ftp.storbinary("STOR up.txt", io.BytesIO(b"nope"))
    finally:
        ftp.quit()
    assert not (share / "up.txt").exists()


def test_write_mode_allows_upload(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share, readonly=False))
    assert wait_for(lambda: service.ftp_enabled)

    ftp = connect_ftp(free_port)
    try:
        ftp.storbinary("STOR up.txt", io.BytesIO(b"uploaded"))
    finally:
        ftp.quit()
    assert (share / "up.txt").read_bytes() == b"uploaded"


def test_wrong_password_rejected(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    ftp = ftplib.FTP()
    ftp.connect("127.0.0.1", free_port, timeout=10)
    with pytest.raises(ftplib.error_perm):
        ftp.login("alice", "wrong")
    ftp.close()


def test_disable_closes_existing_sessions(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    ftp = connect_ftp(free_port)
    try:
        service.disable()
        assert wait_for(lambda: not service.ftp_enabled)
        # 现有会话应当被踢掉：下一次命令会失败
        assert wait_for(lambda: _session_is_dead(ftp), timeout=5)
    finally:
        ftp.close()


def _session_is_dead(ftp: ftplib.FTP) -> bool:
    try:
        ftp.voidcmd("NOOP")
        return False
    except Exception:
        return True


def test_disable_keeps_front_door_alive(service, db, share, free_port):
    """停用 FTP 不能把 Web 控制台也一起关掉。"""
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    service.disable()
    assert wait_for(lambda: not service.ftp_enabled)
    assert service.running is True
    assert read_banner(free_port).startswith(b"421")


def test_auto_stop_disables_ftp_but_keeps_front_door(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share, auto_stop_minutes=0.05))  # 3 秒
    assert wait_for(lambda: service.ftp_enabled)
    assert service.countdown_remaining() is not None

    assert wait_for(lambda: not service.ftp_enabled, timeout=15)
    assert service.running is True, "前端必须继续为 Web 控制台服务"
    assert service.countdown_remaining() is None
    assert any("自动停用" in e for e in service.events)


def test_manual_disable_cancels_auto_stop(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share, auto_stop_minutes=5))
    assert wait_for(lambda: service.ftp_enabled)
    service.disable()
    assert service.countdown_remaining() is None


# --------------------------------------------------------------------------
# 关闭：原版 bug 的回归测试
# --------------------------------------------------------------------------

def test_shutdown_joins_the_loop_thread(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    thread = service._thread
    started = time.monotonic()
    service.shutdown()
    elapsed = time.monotonic() - started

    assert thread is not None
    assert thread.is_alive() is False, "事件循环线程必须真正结束，而不是挂住"
    assert elapsed < 6.0
    assert service.running is False


def test_shutdown_releases_the_port(service, free_port):
    service.serve(free_port)
    service.shutdown()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", free_port), timeout=1)


def test_shutdown_is_idempotent(service, free_port):
    service.serve(free_port)
    service.shutdown()
    service.shutdown()
    assert service.running is False


def test_rebind_moves_to_a_new_port(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        new_port = probe.getsockname()[1]

    service.rebind(new_port)
    assert service.port == new_port
    assert service.running is True
    # 旧端口已释放
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", free_port), timeout=1)


# --------------------------------------------------------------------------
# 同端口的协议复用
# --------------------------------------------------------------------------

def test_http_is_routed_to_the_web_backend(service, free_port):
    backend_port = start_http_backend(b"WEB_OK")
    service.serve(free_port, http_target=("127.0.0.1", backend_port))

    sock = socket.create_connection(("127.0.0.1", free_port), timeout=8)
    try:
        sock.sendall(b"GET /webgui HTTP/1.1\r\nHost: localhost\r\n\r\n")
        chunks = b""
        while b"WEB_OK" not in chunks:
            data = sock.recv(4096)
            if not data:
                break
            chunks += data
        assert b"200 OK" in chunks
        assert b"WEB_OK" in chunks
    finally:
        sock.close()


def test_ftp_and_http_share_the_same_port(service, db, share, free_port):
    """同一个端口，HTTP 走 Web 后端，FTP 走 pyftpdlib。"""
    db.add_user("alice", "secret123")
    backend_port = start_http_backend(b"WEB_OK")
    service.serve(free_port, http_target=("127.0.0.1", backend_port))
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    # HTTP
    sock = socket.create_connection(("127.0.0.1", free_port), timeout=8)
    try:
        sock.sendall(b"GET /webgui HTTP/1.1\r\nHost: localhost\r\n\r\n")
        assert b"WEB_OK" in sock.recv(4096)
    finally:
        sock.close()

    # FTP —— 同一个端口
    ftp = connect_ftp(free_port)
    try:
        assert ftp.nlst() == ["hello.txt"]
    finally:
        ftp.quit()


def test_ftp_client_ip_is_preserved(service, db, share, free_port):
    """核心回归：FTP 连接不做字节代理，日志里必须是真实客户端地址。

    走代理的实现在这里会显示成 127.0.0.1。
    """
    candidates = [ip for ip in local_ipv4_addresses()]
    if not candidates:
        pytest.skip("这台机器没有非回环 IPv4 地址")
    lan_ip = candidates[0]

    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(10)
    try:
        client.bind((lan_ip, 0))
        client.connect((lan_ip, free_port))
        assert client.recv(256).startswith(b"220")
    finally:
        client.close()

    assert wait_for(
        lambda: any("FTP session opened" in e for e in service.events), timeout=6
    ), f"没有看到会话日志：{service.events[-5:]}"

    opened = [e for e in service.events if "FTP session opened" in e]
    assert any(lan_ip in line for line in opened), (
        f"日志里应当出现真实客户端地址 {lan_ip}，实际是：{opened}"
    )


# --------------------------------------------------------------------------
# TLS
# --------------------------------------------------------------------------

def test_tls_login_and_download(service, db, share, free_port, tmp_path):
    cert, key = generate_self_signed_cert(tmp_path / "cert.pem", tmp_path / "key.pem")
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share, use_tls=True, certfile=cert, keyfile=key))
    assert wait_for(lambda: service.ftp_enabled)

    context = ssl._create_unverified_context()
    ftps = ftplib.FTP_TLS(context=context)
    ftps.connect("127.0.0.1", free_port, timeout=10)
    ftps.auth()
    ftps.login("alice", "secret123")
    ftps.prot_p()
    try:
        assert ftps.nlst() == ["hello.txt"]
        buf = io.BytesIO()
        ftps.retrbinary("RETR hello.txt", buf.write)
        assert buf.getvalue() == b"hello from ftpd\n"
    finally:
        ftps.quit()


def test_ftp_access_urls(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    urls = service.access_urls()
    assert urls and all(u.startswith("ftp://") for u in urls)


# --------------------------------------------------------------------------
# 打磨：真实客户端 IP 与可配置的判定宽限期
# --------------------------------------------------------------------------

def start_capturing_http_backend(captured: dict) -> int:
    """把收到的请求头记下来的极简后端。"""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def run() -> None:
        try:
            conn, _ = server.accept()
            captured["head"] = conn.recv(16384)
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                b"Connection: close\r\n\r\nOK"
            )
            conn.close()
        finally:
            server.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def test_http_proxy_injects_x_forwarded_for(service, free_port):
    captured: dict = {}
    backend_port = start_capturing_http_backend(captured)
    service.serve(free_port, http_target=("127.0.0.1", backend_port))

    sock = socket.create_connection(("127.0.0.1", free_port), timeout=8)
    try:
        sock.sendall(b"GET /webgui HTTP/1.1\r\nHost: localhost\r\n\r\n")
        sock.recv(4096)
    finally:
        sock.close()

    assert wait_for(lambda: "head" in captured, timeout=5), "后端没有收到请求"
    assert b"X-Forwarded-For: 127.0.0.1" in captured["head"]


def test_serve_rejects_negative_classify_grace(service, free_port):
    with pytest.raises(ServiceError, match="宽限期"):
        service.serve(free_port, classify_grace=-1)


def test_classify_grace_is_honoured(service, free_port):
    """沉默的连接要等满宽限期才被当成 FTP。"""
    service.serve(free_port, classify_grace=0.05)
    started = time.monotonic()
    banner = read_banner(free_port)
    elapsed = time.monotonic() - started
    assert banner.startswith(b"421")
    assert elapsed >= 0.04


def test_rebind_keeps_classify_grace(service, db, share, free_port):
    db.add_user("alice", "secret123")
    service.serve(free_port, classify_grace=0.06)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        new_port = probe.getsockname()[1]
    service.rebind(new_port)
    assert service._classify_grace == 0.06


def test_ftp_login_is_throttled(service, db, share, free_port):
    """FTP 登录连续失败后要被临时锁住（防暴力破解）。"""
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    for _ in range(5):  # 默认阈值就是 5 次
        ftp = ftplib.FTP()
        ftp.connect("127.0.0.1", free_port, timeout=10)
        try:
            with pytest.raises(ftplib.error_perm):
                ftp.login("alice", "wrong")
        finally:
            ftp.close()

    ftp = ftplib.FTP()
    ftp.connect("127.0.0.1", free_port, timeout=10)
    try:
        with pytest.raises(ftplib.error_perm) as excinfo:
            ftp.login("alice", "secret123")
        assert "Too many failed attempts" in str(excinfo.value)
    finally:
        ftp.close()

    assert service.throttle.locked_accounts(), "应该有被锁定的 key"


# --------------------------------------------------------------------------
# 回归：慢的 Web 连接不能把 FTP 饿死
# --------------------------------------------------------------------------

def start_hanging_backend():
    """一个只接受连接、永不响应的后端：HTTP 连接会一直挂着。"""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(16)
    held = []

    def run() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            held.append(conn)  # 收下就不管

    threading.Thread(target=run, daemon=True).start()
    return server, server.getsockname()[1], held


def test_slow_web_connections_do_not_starve_ftp(service, db, share, free_port):
    """分类线程池只该做「判定」这一小步。

    如果转发也跑在池里，几条长期挂着的 Web 连接就会占满 worker，
    后面的 FTP 连接连问候语都拿不到。
    """
    backend, hang_port, held = start_hanging_backend()
    try:
        service.serve(
            free_port,
            http_target=("127.0.0.1", hang_port),
            classify_grace=0.02,
            max_classifiers=2,      # 故意开得很小
        )
        db.add_user("alice", "secret123")
        service.enable(make_config(share))
        assert wait_for(lambda: service.ftp_enabled)

        clients = []
        try:
            for _ in range(3):      # 超过 worker 数量
                sock = socket.create_connection(("127.0.0.1", free_port), timeout=5)
                sock.sendall(b"GET /hang HTTP/1.1\r\nHost: x\r\n\r\n")
                clients.append(sock)

            # 必须确认这些 Web 连接真的占到了 worker，否则测试会空转通过
            assert wait_for(lambda: len(held) >= 2, timeout=8), (
                f"挂起后端只收到 {len(held)} 条连接，测试前提不成立"
            )

            # FTP 仍然必须能连上并登录
            ftp = ftplib.FTP()
            ftp.connect("127.0.0.1", free_port, timeout=8)
            try:
                ftp.login("alice", "secret123")
                assert ftp.nlst() == ["hello.txt"]
            finally:
                ftp.quit()
        finally:
            for sock in clients:
                close_quietly(sock)
    finally:
        for conn in held:
            close_quietly(conn)
        backend.close()


def test_rebind_refuses_unavailable_port(service, db, share, free_port):
    """新端口不可用时要原地失败，不能把现有服务关掉。"""
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    taken = blocker.getsockname()[1]
    try:
        with pytest.raises(ServiceError, match="不可用"):
            service.rebind(taken)
    finally:
        blocker.close()

    # 原服务必须完好无损
    assert service.running is True
    assert service.port == free_port
    ftp = connect_ftp(free_port)
    try:
        assert ftp.nlst() == ["hello.txt"]
    finally:
        ftp.quit()


def test_rebind_keeps_ftp_running(service, db, share, free_port):
    """换端口不该把 FTP 顺手停掉。"""
    db.add_user("alice", "secret123")
    service.serve(free_port)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        new_port = probe.getsockname()[1]

    service.rebind(new_port)
    assert service.port == new_port
    assert wait_for(lambda: service.ftp_enabled), "换端口后 FTP 应当仍在运行"

    ftp = connect_ftp(new_port)
    try:
        assert ftp.nlst() == ["hello.txt"]
    finally:
        ftp.quit()


def test_shutdown_closes_proxied_connections(service, free_port):
    """转发中的 Web 连接不在 ioloop 里，关服务时必须一起收掉。"""
    backend, hang_port, held = start_hanging_backend()
    client = None
    try:
        service.serve(free_port, http_target=("127.0.0.1", hang_port))
        client = socket.create_connection(("127.0.0.1", free_port), timeout=5)
        client.sendall(b"GET /hang HTTP/1.1\r\nHost: x\r\n\r\n")
        assert wait_for(lambda: len(held) >= 1, timeout=8), "连接没被转发过去"

        service.shutdown()
        client.settimeout(5)
        closed = False
        try:
            closed = client.recv(4096) == b""
        except OSError:
            closed = True
        assert closed, "关闭服务后，被转发的连接也应当被关闭"
    finally:
        if client is not None:
            close_quietly(client)
        for conn in held:
            close_quietly(conn)
        backend.close()


# --------------------------------------------------------------------------
# 协议判定的宽限期：边界行为
# --------------------------------------------------------------------------

def test_adaptive_grace_is_off_by_default(service, free_port):
    """RTT 自适应默认关闭——中间有代理时它会读错那一跳。"""
    service.serve(free_port)
    assert service._server.adaptive_grace is False


def test_late_but_within_grace_http_is_classified_as_http(service, free_port):
    """只要在宽限期内把请求发出来，就应当被正确识别成 HTTP。"""
    captured: dict = {}
    backend_port = start_capturing_http_backend(captured)
    service.serve(
        free_port, http_target=("127.0.0.1", backend_port), classify_grace=0.4
    )

    client = socket.create_connection(("127.0.0.1", free_port), timeout=8)
    try:
        time.sleep(0.1)      # 故意晚一点发，但仍远小于宽限期
        client.sendall(b"GET /webgui HTTP/1.1\r\nHost: localhost\r\n\r\n")
        client.settimeout(6)
        assert client.recv(64).startswith(b"HTTP/1.1 200")
    finally:
        close_quietly(client)
    assert captured.get("head", b"").startswith(b"GET /webgui")


def test_silent_connection_is_classified_as_ftp_within_grace(service, free_port):
    """共用端口模式（有 Web 后端）下，沉默的连接在宽限期后被当成 FTP。"""
    backend_port = start_http_backend()
    service.serve(
        free_port, http_target=("127.0.0.1", backend_port), classify_grace=0.2
    )
    started = time.monotonic()
    banner = read_banner(free_port)
    elapsed = time.monotonic() - started

    assert banner.startswith(b"421")
    assert 0.19 <= elapsed <= 0.35, f"等待时间异常：{elapsed:.3f}s"


# --------------------------------------------------------------------------
# FTP 专用端口：不做协议判定
# --------------------------------------------------------------------------

def test_ftp_only_port_skips_classification(service, free_port):
    """没有 Web 后端时不该判定协议：宽限期设得再大也立刻应答。

    这正是「FTP 与 Web 分成两个端口」的核心收益。
    """
    service.serve(free_port, classify_grace=5.0)   # 故意设得很大
    started = time.monotonic()
    banner = read_banner(free_port)
    elapsed = time.monotonic() - started

    assert banner.startswith(b"421")
    assert elapsed < 0.5, f"应当零等待，实际 {elapsed:.3f}s"


def test_ftp_only_port_serves_ftp_without_delay(service, db, share, free_port):
    """真的登录一次，确认没有判定环节也能正常工作。"""
    db.add_user("alice", "secret123")
    service.serve(free_port, classify_grace=5.0)
    service.enable(make_config(share))
    assert wait_for(lambda: service.ftp_enabled)

    ftp = connect_ftp(free_port)
    try:
        assert ftp.nlst() == ["hello.txt"]
    finally:
        ftp.quit()
