"""FTP 服务生命周期管理。

**架构**

Web 控制台和 FTP 共用同一个 TCP 端口，所以这个端口由
``MultiplexedFTPServer``（见 :mod:`ftpd.multiplex`）常驻占用：
HTTP 连接转发给内部的 NiceGUI/uvicorn，FTP 连接原地交给 pyftpdlib。

由此带来两点语义变化：

* 「启动前端」是应用启动时就完成的事，端口一开，Web 控制台就一直可用；
* GUI 上的「启动 / 停止服务」只切换 **FTP 是否接待连接**，
  端口本身不会关闭（否则 Web 控制台自己也断了）。

**线程模型**

* ioloop 跑在后台线程里（``ftpd-ioloop``）；
* 所有对 ioloop 内部状态的改动（换 handler、关会话）都不直接从 GUI 线程做，
  而是置一个标志位，由 ioloop 线程里的定期任务 ``_maintenance`` 执行。

**原版 bug 的修复**

原脚本用 ``Timer`` 调 ``server.close_all()`` 后，主线程仍卡在
``ioloop.loop()`` 的 ``poll(None)`` 里，端口虽释放、进程却不退出。
这里给 ``serve_forever(timeout=...)`` 一个超时，事件循环会定期回头
检查 ``socket_map`` 是否已清空，从而正常返回、线程正常结束。
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from pyftpdlib.handlers import FTPHandler
from pyftpdlib.log import logger as pyftpdlib_logger

from .auth import DBFTPAuthorizer
from .db import UserDB
from .multiplex import DEFAULT_GRACE, MultiplexedFTPServer
from .security import LoginThrottle
from .tls import cert_exists

EventCallback = Callable[[str], None]

POLL_INTERVAL = 0.5
JOIN_TIMEOUT = 5.0
MAINTENANCE_INTERVAL = 0.1


class ServiceError(RuntimeError):
    """配置不合法，或当前状态下不允许该操作。"""


@dataclass
class ServerConfig:
    """FTP 侧的可调项；监听端口由前端统一持有，不在这里。"""

    directory: Path
    readonly: bool = True
    use_tls: bool = False
    certfile: Optional[Path] = None
    keyfile: Optional[Path] = None
    #: 多少分钟后自动停止 FTP；0 表示不自动停止
    auto_stop_minutes: float = 0.0


class _CallbackLogHandler(logging.Handler):
    """把 pyftpdlib 的日志转发给界面。"""

    def __init__(self, callback: EventCallback) -> None:
        super().__init__()
        self.callback = callback
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.callback(self.format(record))
        except Exception:
            pass


def local_ipv4_addresses() -> List[str]:
    """尽力列出本机的局域网 IPv4 地址。"""
    addrs: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            addrs.add(sock.getsockname()[0])
    except OSError:
        pass
    return sorted(a for a in addrs if not a.startswith("127."))


class FTPService:
    """常驻前端 + 可开关的 FTP 服务。"""

    def __init__(
        self,
        db: UserDB,
        on_event: Optional[EventCallback] = None,
        throttle: Optional[LoginThrottle] = None,
    ) -> None:
        self.db = db
        self.on_event = on_event
        #: FTP 登录失败计数；用户名与来源 IP 都会被记
        self.throttle = throttle or LoginThrottle()
        self.config: Optional[ServerConfig] = None

        self._server: Optional[MultiplexedFTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._maintenance_task = None
        self._log_handler: Optional[_CallbackLogHandler] = None
        self._lock = threading.RLock()

        self._pending_handler = None
        self._want_disable = False
        self._want_close_sessions = False

        self._port: Optional[int] = None
        self._http_target: Optional[Tuple[str, int]] = None
        self._classify_grace = DEFAULT_GRACE
        self._ftp_enabled = False

        self._timer: Optional[threading.Timer] = None
        self._deadline: Optional[float] = None

    # ------------------------------------------------------------------
    # 状态
    # ------------------------------------------------------------------

    @property
    def running(self) -> bool:
        """前端（也就是共享端口）是否在运行。"""
        thread = self._thread
        return bool(thread and thread.is_alive())

    @property
    def ftp_enabled(self) -> bool:
        """FTP 当前是否接待连接。"""
        return self._ftp_enabled

    @property
    def port(self) -> Optional[int]:
        return self._port

    def countdown_remaining(self) -> Optional[float]:
        if self._deadline is None:
            return None
        return max(0.0, self._deadline - time.monotonic())

    def _scheme(self) -> str:
        return "ftps" if (self.config and self.config.use_tls) else "ftp"

    def access_urls(self) -> List[str]:
        """给用户看的访问地址。"""
        if not self._port:
            return []
        hosts = local_ipv4_addresses() or ["<本机IP>"]
        return [f"{self._scheme()}://{h}:{self._port}" for h in hosts]

    def web_urls(self) -> List[str]:
        """Web 控制台地址。"""
        if not self._port:
            return []
        hosts = local_ipv4_addresses() or ["<本机IP>"]
        return [f"http://{h}:{self._port}/webgui" for h in hosts]

    # ------------------------------------------------------------------
    # 事件
    # ------------------------------------------------------------------

    def _emit(self, message: str) -> None:
        if not self.on_event:
            return
        stamp = time.strftime("%H:%M:%S")
        try:
            self.on_event(f"[{stamp}] {message}")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 前端（共享端口）
    # ------------------------------------------------------------------

    def _placeholder_handler(self):
        class _Placeholder(FTPHandler):
            pass

        _Placeholder.authorizer = DBFTPAuthorizer(
            self.db, Path.home(), readonly=True, throttle=self.throttle
        )
        return _Placeholder

    def serve(
        self,
        port: int,
        *,
        http_target: Optional[Tuple[str, int]] = None,
        host: str = "0.0.0.0",
        classify_grace: float = DEFAULT_GRACE,
    ) -> None:
        """占用共享端口，开始同时接待 FTP 与 Web 控制台。

        ``classify_grace`` 是判定协议时最多等首包多久：越小 FTP 连接越快，
        但太小时慢一点的 HTTP 客户端可能被误判成 FTP。
        """
        with self._lock:
            if self._server is not None:
                raise ServiceError("前端已经在运行了")
            if not (1 <= int(port) <= 65535):
                raise ServiceError(f"端口号必须在 1-65535 之间：{port}")
            if classify_grace < 0:
                raise ServiceError("首包判定宽限期不能为负数")

            try:
                server = MultiplexedFTPServer(
                    (host, int(port)),
                    self._placeholder_handler(),
                    http_target=http_target,
                    on_event=self._emit,
                    classify_grace=classify_grace,
                )
            except OSError as exc:
                raise ServiceError(f"无法监听 {host}:{port} —— {exc}") from exc

            server.ftp_enabled = False

            self._log_handler = _CallbackLogHandler(self._emit)
            pyftpdlib_logger.setLevel(logging.INFO)
            pyftpdlib_logger.addHandler(self._log_handler)

            self._server = server
            self._port = int(port)
            self._http_target = http_target
            self._classify_grace = classify_grace
            self._maintenance_task = server.ioloop.call_every(
                MAINTENANCE_INTERVAL, self._maintenance
            )
            self._thread = threading.Thread(
                target=self._serve_loop, name="ftpd-ioloop", daemon=True
            )
            self._thread.start()

        self._emit(f"共享端口已就绪：{host}:{port}")
        if http_target:
            self._emit(f"Web 控制台：http://<本机IP>:{port}/webgui")

    def _serve_loop(self) -> None:
        server = self._server
        if server is None:
            return
        try:
            # 关键：给事件循环一个超时，close_all() 之后才能正常返回
            server.serve_forever(
                timeout=POLL_INTERVAL, blocking=True, handle_exit=False
            )
        except Exception as exc:  # pragma: no cover - 兜底
            self._emit(f"事件循环异常退出：{exc!r}")
        finally:
            self._emit("事件循环已退出")

    def rebind(self, port: int) -> None:
        """换一个共享端口（Web 控制台地址会随之改变）。"""
        http_target = self._http_target
        classify_grace = self._classify_grace
        self.shutdown()
        self.serve(port, http_target=http_target, classify_grace=classify_grace)

    # ------------------------------------------------------------------
    # 维护任务（在 ioloop 线程里执行）
    # ------------------------------------------------------------------

    def _maintenance(self) -> None:
        server = self._server
        if server is None:
            return

        handler, self._pending_handler = self._pending_handler, None
        if handler is not None:
            server.handler = handler
            server.ftp_enabled = True
            self._ftp_enabled = True
            cfg = self.config
            if cfg is not None:
                mode = "只读" if cfg.readonly else "读写"
                tls = "FTPS" if cfg.use_tls else "FTP"
                self._emit(
                    f"{tls} 服务已启用（{mode}），共享目录 {cfg.directory}"
                )

        if self._want_disable:
            self._want_disable = False
            server.ftp_enabled = False
            self._ftp_enabled = False
            self._close_sessions()
            self._emit("FTP 服务已停用（Web 控制台仍在运行）")

        if self._want_close_sessions:
            self._want_close_sessions = False
            self._close_sessions()

    def _close_sessions(self) -> None:
        ioloop = self._server.ioloop if self._server else None
        if ioloop is None:
            return
        for obj in list(ioloop.socket_map.values()):
            if isinstance(obj, FTPHandler):
                try:
                    obj.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------
    # 配置校验与 handler 构造
    # ------------------------------------------------------------------

    def _validate(self, cfg: ServerConfig) -> Path:
        directory = Path(cfg.directory).expanduser()
        if not directory.is_dir():
            raise ServiceError(f"共享目录不存在或不是目录：{directory}")
        if cfg.auto_stop_minutes < 0:
            raise ServiceError("自动停止时间不能为负数")
        if cfg.use_tls:
            if not cfg.certfile or not cfg.keyfile:
                raise ServiceError("启用 TLS 需要指定证书和私钥文件")
            if not cert_exists(cfg.certfile, cfg.keyfile):
                raise ServiceError(
                    f"证书或私钥不存在：{cfg.certfile} / {cfg.keyfile}"
                )
        return directory.resolve()

    def _build_handler(self, cfg: ServerConfig):
        service = self

        if cfg.use_tls:
            from pyftpdlib.handlers import TLS_FTPHandler as BaseHandler
        else:
            BaseHandler = FTPHandler  # type: ignore[assignment]

        authorizer = DBFTPAuthorizer(
            self.db, cfg.directory, readonly=cfg.readonly, throttle=self.throttle
        )

        class Handler(BaseHandler):  # type: ignore[misc, valid-type]
            def on_login(self, username: str) -> None:
                super().on_login(username)
                service._emit(
                    f"用户 {username} 登录成功"
                    f"（{'只读' if cfg.readonly else '读写'}）"
                )

            def on_logout(self, username: str) -> None:
                super().on_logout(username)
                service._emit(f"用户 {username} 断开连接")

            def on_file_sent(self, file: str) -> None:
                super().on_file_sent(file)
                service._emit(f"下载完成：{Path(file).name}")

            def on_file_received(self, file: str) -> None:
                super().on_file_received(file)
                service._emit(f"上传完成：{Path(file).name}")

            def on_incomplete_file_sent(self, file: str) -> None:
                super().on_incomplete_file_sent(file)
                service._emit(f"下载中断：{Path(file).name}")

            def on_incomplete_file_received(self, file: str) -> None:
                super().on_incomplete_file_received(file)
                service._emit(f"上传中断：{Path(file).name}")

        Handler.authorizer = authorizer

        if cfg.use_tls:
            Handler.certfile = str(cfg.certfile)      # type: ignore[attr-defined]
            Handler.keyfile = str(cfg.keyfile)        # type: ignore[attr-defined]
            Handler.tls_control_required = True       # type: ignore[attr-defined]
            Handler.tls_data_required = True          # type: ignore[attr-defined]

        return Handler

    # ------------------------------------------------------------------
    # 启停 FTP
    # ------------------------------------------------------------------

    def enable(self, cfg: ServerConfig) -> None:
        """启用 FTP 接待（不影响 Web 控制台）。"""
        with self._lock:
            if self._server is None:
                raise ServiceError("前端还没启动，无法启用 FTP")
            cfg.directory = self._validate(cfg)
            handler = self._build_handler(cfg)
            self.config = cfg
            self._pending_handler = handler

            timer, self._timer = self._timer, None
            if timer is not None:
                timer.cancel()
            self._deadline = None
            if cfg.auto_stop_minutes > 0:
                seconds = float(cfg.auto_stop_minutes) * 60
                self._deadline = time.monotonic() + seconds
                self._timer = threading.Timer(seconds, self._auto_stop)
                self._timer.daemon = True
                self._timer.start()

        if cfg.auto_stop_minutes > 0:
            self._emit(f"将在 {cfg.auto_stop_minutes:g} 分钟后自动停用 FTP")

    def disable(self) -> None:
        """停用 FTP（关闭现有会话），端口继续为 Web 控制台服务。"""
        with self._lock:
            timer, self._timer = self._timer, None
            if timer is not None:
                timer.cancel()
            self._deadline = None
            self._want_disable = True

    def _auto_stop(self) -> None:
        self._emit("到达预设时间，自动停用 FTP")
        self.disable()

    # ------------------------------------------------------------------
    # 关闭
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        with self._lock:
            timer, self._timer = self._timer, None
            if timer is not None:
                timer.cancel()
            self._deadline = None

            server, self._server = self._server, None
            thread, self._thread = self._thread, None
            handler, self._log_handler = self._log_handler, None
            task, self._maintenance_task = self._maintenance_task, None
            self._ftp_enabled = False
            self._pending_handler = None
            self._want_disable = False
            self._port = None

        if handler is not None:
            pyftpdlib_logger.removeHandler(handler)
        if server is None:
            return

        try:
            if task is not None:
                task.cancel()
        except Exception:
            pass

        server.close_all()
        if thread is not None and thread.is_alive():
            thread.join(timeout=JOIN_TIMEOUT)

        server.shutdown_extra()
        self._emit("共享端口已释放")
