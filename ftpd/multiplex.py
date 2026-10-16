"""单端口协议复用。

**为什么需要这个模块**

FTP 和 HTTP 是两种不同的应用层协议，一个 TCP 端口上并不存在
「按 URL 路径路由」这回事——`ftp://host:2121/webgui` 只会被当成 FTP 命令。
要在**同一个端口**上既提供 FTP 又提供 Web 控制台，只能看连接的首包来判定协议。

**怎么判定**

* HTTP 客户端一建立连接就立刻发请求（``GET /webgui HTTP/1.1``）；
* FTP 客户端相反，它**等服务器先发 220 问候语**，在此之前一个字节都不发。

所以：连上来后窥探（``MSG_PEEK``，不消费数据）一小段时间，
拿到像 HTTP 请求的字节就走 HTTP，超时没动静就当 FTP。
代价是每个 FTP 连接会多等 ``classify_grace``（默认 150ms）。

**怎么交接**

判定为 FTP 后**不做字节代理**，而是把已接受的 socket 原样交给
``FTPServer.handle_accepted()``。这样 pyftpdlib 看到的客户端地址就是真实地址，
日志里不会全变成 127.0.0.1；被动模式的监听地址也会正确地取真实网卡地址。

注意 ``handle_accepted`` 必须在 pyftpdlib 的事件循环线程里调用，
所以判定在 worker 线程里做，结果丢进队列，由 ``ioloop.call_every``
的回调在循环线程里取出并交接。
"""

from __future__ import annotations

import errno
import queue
import select
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional, Tuple

from pyftpdlib.servers import FTPServer

EventCallback = Callable[[str], None]
Target = Tuple[str, int]

#: TLS 握手记录的前两个字节（ClientHello, content-type=22, major=3）
TLS_HANDSHAKE_PREFIX = b"\x16\x03"

#: HTTP 请求行可能的前缀（含 HTTP/2 的 PRI 前导）
HTTP_PREFIXES = (
    b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE",
    b"PATC", b"CONN", b"TRAC", b"PRI ",
)

#: 判定协议时最多窥探多久（秒）
DEFAULT_GRACE = 0.15
#: 注入队列的轮询间隔（秒）
PUMP_INTERVAL = 0.03
#: 同时进行协议判定的连接数上限
DEFAULT_MAX_CLASSIFIERS = 32
#: 同时转发的 Web 连接数上限
DEFAULT_MAX_PROXIES = 256


def close_quietly(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


def classify_head(head: bytes) -> str:
    """根据首包字节判断协议。"""
    if head[:2] == TLS_HANDSHAKE_PREFIX:
        return "tls"
    if head.startswith(HTTP_PREFIXES):
        return "http"
    return "ftp"


def classify_protocol(sock: socket.socket, grace: float = DEFAULT_GRACE) -> str:
    """窥探首包判断这是什么协议的连接。

    返回 ``"tls"`` / ``"http"`` / ``"ftp"`` / ``"closed"``。
    数据只用 ``MSG_PEEK`` 看，不消费。

    ``tls`` / ``http`` 的客户端都会立刻发数据，一读就知道；
    FTP 客户端会等服务器先发问候语，所以要等到超时才能判定。
    等待用 ``select`` 而不是轮询 sleep：既能立刻被数据唤醒，也不空转 CPU。
    """
    previous_timeout = sock.gettimeout()
    sock.setblocking(False)
    deadline = time.monotonic() + grace
    try:
        while True:
            try:
                head = sock.recv(8, socket.MSG_PEEK)
            except (BlockingIOError, InterruptedError):
                head = None          # 暂时没有数据
            except OSError:
                return "closed"      # 连接已废
            if head is not None:
                if head == b"":
                    return "closed"  # 对端关闭，EOF
                return classify_head(head)

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return "ftp"         # 一声不吭 —— 典型的 FTP 客户端
            try:
                readable, _, _ = select.select([sock], [], [], remaining)
            except (OSError, ValueError):
                return "closed"
            if not readable:
                return "ftp"
    finally:
        try:
            sock.settimeout(previous_timeout)
        except OSError:
            pass


def request_path(head: bytes) -> str:
    """从请求头里取出路径，取不到就返回 "/"。"""
    try:
        first_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = first_line.split()
        if len(parts) >= 2 and parts[1].startswith("/"):
            return parts[1]
    except Exception:
        pass
    return "/"


def request_host(head: bytes) -> str:
    """从请求头里取出 Host（不含端口），取不到返回空串。"""
    try:
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"host":
                return value.strip().decode("latin-1").split(":")[0]
    except Exception:
        pass
    return ""


def _read_http_head(sock: socket.socket, *, limit: int = 65536,
                    timeout: float = 5.0) -> bytes:
    """把客户端请求头读到 ``\r\n\r\n`` 为止（可能多读，多出的部分一并返回）。"""
    previous = sock.gettimeout()
    sock.settimeout(timeout)
    buffer = b""
    try:
        while b"\r\n\r\n" not in buffer and len(buffer) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
    except OSError:
        pass
    finally:
        try:
            sock.settimeout(previous)
        except OSError:
            pass
    return buffer


def _inject_forwarded_for(raw: bytes, client_ip: str) -> bytes:
    """在请求头里插入 X-Forwarded-For；已经有就不重复插。"""
    marker = raw.find(b"\r\n\r\n")
    if marker < 0:
        return raw
    head, rest = raw[:marker], raw[marker:]
    if b"x-forwarded-for" in head.lower():
        return raw
    return head + b"\r\nX-Forwarded-For: " + client_ip.encode("ascii", "replace") + rest


def proxy_to(
    client: socket.socket,
    target: Target,
    *,
    connect_timeout: float = 5.0,
    idle_timeout: float = 120.0,
    on_event: Optional[EventCallback] = None,
    client_ip: Optional[str] = None,
) -> None:
    """把一条已接受的连接原样转发给内部后端（用于 HTTP / WebSocket）。

    用**单线程 select 泵**同时照看两个方向，而不是每个方向开一个线程、
    各自阻塞在 ``recv`` 上。这样：

    * 支持半关闭 —— 一端关闭写方向时，另一端的写方向也干净地关掉；
    * 不依赖「阻塞中的 recv 会被新数据唤醒」这种行为（某些环境并不可靠）；
    * 线程数可控，一条连接只占一个线程。

    空闲超过 ``idle_timeout`` 秒就收工，避免死连接长期占着线程。
    """
    try:
        upstream = socket.create_connection(target, timeout=connect_timeout)
    except OSError as exc:
        if on_event:
            on_event(f"无法连接 Web 后端 {target[0]}:{target[1]} —— {exc}")
        body = b"Web backend is not reachable.\n"
        try:
            client.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
        except OSError:
            pass
        close_quietly(client)
        return

    if client_ip:
        # Web 后端看到的会是回环地址，所以把真实来源写进 X-Forwarded-For。
        # 只处理每条连接的第一个请求（keep-alive 的后续请求拿不到，属已知限制）。
        head = _read_http_head(client)
        if head:
            try:
                upstream.sendall(_inject_forwarded_for(head, client_ip))
            except OSError:
                close_quietly(client)
                close_quietly(upstream)
                return

    for sock in (client, upstream):
        try:
            sock.setblocking(False)
        except OSError:
            close_quietly(client)
            close_quietly(upstream)
            return

    # pending[s] 是「准备写给 s」的字节；reading 是还在读的方向。
    # 半关闭必须等缓冲排空后再做，否则会把还没交给内核的尾部数据丢掉。
    pending: dict = {client: bytearray(), upstream: bytearray()}
    reading = {client, upstream}
    pending_shutdown = set()

    try:
        while reading or any(pending.values()):
            readable = list(reading)
            writable = [sock for sock, buf in pending.items() if buf]
            if not readable and not writable:
                break
            try:
                ready_r, ready_w, _ = select.select(
                    readable, writable, [], idle_timeout
                )
            except (OSError, ValueError):
                break
            if not ready_r and not ready_w:
                break  # 长时间空闲

            for sock in ready_r:
                if sock not in reading:
                    continue
                try:
                    chunk = sock.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    chunk = b""
                peer = upstream if sock is client else client
                if not chunk:
                    # 这一端不再有数据了：等对它的待发数据排空后关掉写方向
                    reading.discard(sock)
                    pending_shutdown.add(peer)
                    continue
                pending[peer] += chunk

            for sock in ready_w:
                buffer = pending.get(sock)
                if not buffer:
                    continue
                try:
                    sent = sock.send(buffer)
                except (BlockingIOError, InterruptedError):
                    continue
                except OSError:
                    reading.discard(sock)
                    pending_shutdown.discard(sock)
                    pending.pop(sock, None)
                    continue
                del buffer[:sent]

            for sock in list(pending_shutdown):
                if not pending.get(sock):
                    try:
                        sock.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    pending_shutdown.discard(sock)
    finally:
        close_quietly(client)
        close_quietly(upstream)


class MultiplexedFTPServer(FTPServer):
    """监听一个端口，同时接待 FTP 与 Web GUI。

    * HTTP 连接 → 转发给 ``http_target``（内部 uvicorn）；
    * FTP 连接  → 原地交给 pyftpdlib（``ftp_enabled`` 为假时礼貌拒绝）。
    """

    def __init__(
        self,
        address,
        handler,
        *,
        http_target: Optional[Target] = None,
        https_target: Optional[Target] = None,
        on_event: Optional[EventCallback] = None,
        classify_grace: float = DEFAULT_GRACE,
        max_classifiers: int = DEFAULT_MAX_CLASSIFIERS,
        max_proxies: int = DEFAULT_MAX_PROXIES,
    ) -> None:
        super().__init__(address, handler)
        self.http_target = http_target
        self.https_target = https_target
        self.on_event = on_event
        self.classify_grace = classify_grace
        self.ftp_enabled = True

        self._inject: "queue.Queue[Tuple[socket.socket, tuple]]" = queue.Queue()
        self._pool = ThreadPoolExecutor(
            max_workers=max_classifiers, thread_name_prefix="ftpd-classify"
        )
        # 转发是「一条连接一个线程、活到连接结束」，不能放进分类线程池，
        # 否则几条挂着不动的 Web 连接就能占满 worker、把 FTP 饿死。
        self._proxy_slots = threading.BoundedSemaphore(max(1, int(max_proxies)))
        # 转发中的连接不在 ioloop 的 socket_map 里，关闭时要自己收
        self._proxy_socks: set = set()
        self._proxy_lock = threading.Lock()
        self._closed = threading.Event()
        # 在事件循环线程里定期排空注入队列
        self._pump_task = self.ioloop.call_every(PUMP_INTERVAL, self._pump)

    # -- 事件 -------------------------------------------------------------

    def _emit(self, message: str) -> None:
        if self.on_event:
            try:
                self.on_event(message)
            except Exception:
                pass

    # -- 接收：只做分派，判定交给线程池 -----------------------------------

    def handle_accepted(self, sock, addr):  # noqa: D102 - 覆盖 pyftpdlib 钩子
        try:
            self._pool.submit(self._classify_and_route, sock, addr)
        except RuntimeError:  # 线程池已关闭
            close_quietly(sock)

    def _classify_and_route(self, sock: socket.socket, addr) -> None:
        try:
            kind = classify_protocol(sock, self.classify_grace)
        except Exception as exc:  # pragma: no cover - 兜底
            self._emit(f"协议判定失败：{exc!r}")
            close_quietly(sock)
            return

        if kind == "closed":
            close_quietly(sock)
            return

        if kind == "tls":
            if self.https_target:
                self._start_proxy(sock, addr, self.https_target)
            else:
                self._emit("收到 TLS 连接，但没有启动 HTTPS 后端")
                close_quietly(sock)
            return

        if kind == "http":
            if self.http_target:
                # 不逐条记录 Web 访问，否则浏览器一开就把日志刷爆了
                self._start_proxy(sock, addr, self.http_target)
            elif self.https_target:
                # 只跑了 HTTPS 后端，明文请求就 301 跳过去
                self._redirect_to_https(sock, addr)
            else:
                self._emit("收到 HTTP 连接，但没有启动 Web 后端")
                self._reject(sock, "Web 控制台未启动")
            return

        # FTP
        if not self.ftp_enabled:
            self._emit(f"FTP 连接来自 {addr[0]}，但服务未启用，已拒绝")
            self._reject(
                sock,
                "421 FTP service is currently disabled. "
                "Open the web console at /webgui to enable it.",
            )
            return
        self._inject.put((sock, addr))

    def _start_proxy(self, sock: socket.socket, addr, target: Target) -> None:
        """把 Web 连接的转发交给独立线程，立刻还回分类线程池的 worker。

        ``proxy_to`` 会一直跑到连接结束（WebSocket 可能是几十分钟），
        所以绝不能占用分类线程池。
        """
        if not self._proxy_slots.acquire(blocking=False):
            self._emit("并发 Web 连接过多，已拒绝一条新连接")
            self._reject(sock, "503 Service Unavailable")
            return

        client_ip = addr[0] if addr else None

        def run() -> None:
            try:
                proxy_to(sock, target, on_event=self._emit, client_ip=client_ip)
            finally:
                with self._proxy_lock:
                    self._proxy_socks.discard(sock)
                self._proxy_slots.release()

        with self._proxy_lock:
            self._proxy_socks.add(sock)

        threading.Thread(target=run, name="ftpd-proxy", daemon=True).start()

    def _redirect_to_https(self, sock: socket.socket, addr=None) -> None:
        """强制 HTTPS 时，把明文请求 301 到同端口的 https。"""
        head = _read_http_head(sock, timeout=3.0)
        path = request_path(head)
        host = request_host(head) or (addr[0] if addr else "localhost")
        try:
            port = self.socket.getsockname()[1]
        except OSError:
            port = 443
        location = f"https://{host}:{port}{path}"
        body = f"Redirecting to {location}\n".encode("utf-8")
        response = (
            b"HTTP/1.1 301 Moved Permanently\r\n"
            b"Location: " + location.encode("latin-1", "replace") + b"\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        try:
            sock.sendall(response)
        except OSError:
            pass
        close_quietly(sock)

    def _reject(self, sock: socket.socket, message: str) -> None:
        if not message.endswith("\r\n"):
            message = message + "\r\n"
        try:
            sock.sendall(message.encode("utf-8", "replace"))
        except OSError:
            pass
        close_quietly(sock)

    # -- 注入：在事件循环线程里交接给 pyftpdlib ---------------------------

    def _pump(self) -> None:
        while True:
            try:
                sock, addr = self._inject.get_nowait()
            except queue.Empty:
                return
            if not self.ftp_enabled:
                # 判定期间服务可能被停用，这里再确认一次
                self._reject(
                    sock,
                    "421 FTP service is currently disabled. "
                    "Open the web console at /webgui to enable it.",
                )
                continue
            try:
                FTPServer.handle_accepted(self, sock, addr)
            except Exception as exc:  # pragma: no cover - 兜底
                self._emit(f"接管 FTP 连接失败：{exc!r}")
                close_quietly(sock)

    # -- 关闭 -------------------------------------------------------------

    def shutdown_extra(self) -> None:
        """释放线程池与定时任务（在 ioloop 关闭之后调用）。"""
        self._closed.set()
        # 转发中的连接不归 ioloop 管，必须在这里关掉
        with self._proxy_lock:
            pending = list(self._proxy_socks)
            self._proxy_socks.clear()
        for sock in pending:
            close_quietly(sock)
        try:
            if self._pump_task is not None:
                self._pump_task.cancel()
        except Exception:
            pass
        self._pool.shutdown(wait=False, cancel_futures=True)
