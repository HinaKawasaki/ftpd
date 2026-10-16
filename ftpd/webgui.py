"""NiceGUI Web 控制台。

界面挂在 ``/webgui`` 下，和 FTP 服务**共用同一个 TCP 端口** ——
端口上的协议复用见 :mod:`ftpd.multiplex`。

四个功能区：
  * 用户：增删、重置密码、启用/禁用（数据在 SQLite 里，密码 PBKDF2 加盐哈希）
  * 服务：共享目录、共享端口、只读/读写、FTPS 开关、启动/停止
  * 日志：实时滚动显示连接与传输事件
  * 倒计时：自动停止的剩余时间

NiceGUI 的页面是「每个浏览器标签页一个实例」，而 FTP 服务运行在别的线程里，
所以日志通过 :class:`LogBuffer`（线程安全的环形缓冲）传递，
页面用 ``ui.timer`` 定期取增量，不跨线程碰界面对象。
"""

from __future__ import annotations

import socket
import threading
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from nicegui import ui

from . import config as config_mod
from .db import UserDB, ValidationError
from .server import FTPService, ServerConfig, ServiceError
from .tls import TLSError, cert_exists, generate_self_signed_cert

MOUNT_PATH = "/webgui"
MAX_LOG_LINES = 400


# --------------------------------------------------------------------------
# 日志缓冲
# --------------------------------------------------------------------------

class LogBuffer:
    """线程安全的日志环形缓冲，支持按序号取增量。"""

    def __init__(self, maxlen: int = MAX_LOG_LINES) -> None:
        self._lines: deque = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._seq = 0

    @property
    def seq(self) -> int:
        with self._lock:
            return self._seq

    def append(self, line: str) -> None:
        with self._lock:
            self._lines.append(str(line))
            self._seq += 1

    def tail(self, after_seq: int) -> Tuple[List[str], int]:
        """返回序号大于 ``after_seq`` 的行，以及当前序号。"""
        with self._lock:
            lines = list(self._lines)
            seq = self._seq
            first_seq = seq - len(lines) + 1
        new = [line for i, line in enumerate(lines, start=first_seq) if i > after_seq]
        return new, seq

    def snapshot(self) -> List[str]:
        with self._lock:
            return list(self._lines)


# --------------------------------------------------------------------------
# 控制台状态
# --------------------------------------------------------------------------

class WebConsole:
    """Web 界面与后端服务共享的状态。"""

    def __init__(self, db: UserDB, service: FTPService, logs: LogBuffer) -> None:
        self.db = db
        self.service = service
        self.logs = logs


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    if minutes >= 60:
        hours, minutes = divmod(minutes, 60)
        return f"{hours} 小时 {minutes} 分 {secs} 秒"
    return f"{minutes:02d}:{secs:02d}"


# --------------------------------------------------------------------------
# 页面
# --------------------------------------------------------------------------

def build_page(console: WebConsole) -> None:
    db = console.db
    service = console.service
    logs = console.logs

    state: Dict[str, Optional[str]] = {"selected": None}

    ui.page_title("ftpd 控制台")
    ui.colors(primary="#1565c0")

    with ui.header().classes("items-center justify-between px-4 py-2"):
        with ui.row().classes("items-center gap-2"):
            ui.icon("dns").classes("text-2xl")
            ui.label("ftpd 控制台").classes("text-lg font-semibold")
        header_status = ui.label("").classes("text-sm opacity-90")

    # ---------------- 用户管理 ----------------
    @ui.refreshable
    def users_table() -> None:
        rows = [
            {
                "username": user.username,
                "status": user.status_text,
                "last_login": user.last_login_text,
            }
            for user in db.list_users()
        ]
        if not rows:
            ui.label("还没有任何用户，请先在上面添加一个。").classes("text-sm opacity-70")
            return
        table = ui.table(
            columns=[
                {"name": "username", "label": "用户名", "field": "username", "align": "left"},
                {"name": "status", "label": "状态", "field": "status", "align": "left"},
                {"name": "last_login", "label": "最后登录", "field": "last_login", "align": "left"},
            ],
            rows=rows,
            row_key="username",
            selection="single",
        ).classes("w-full")

        table.on(
            "selection",
            lambda event: _remember_selection(event.args),
        )
        if state["selected"]:
            table.selected = [r for r in rows if r["username"] == state["selected"]]

    def _remember_selection(args) -> None:
        rows = args if isinstance(args, list) else ([] if not args else [args])
        picked = [r for r in rows if isinstance(r, dict) and "username" in r]
        state["selected"] = picked[0]["username"] if picked else None

    def _selected() -> Optional[str]:
        return state["selected"]

    def user_count_label() -> str:
        users = db.list_users()
        enabled = sum(1 for u in users if u.enabled)
        return f"共 {len(users)} 个用户，其中 {enabled} 个启用"

    # ---------------- 服务配置 ----------------
    def current_port() -> int:
        return int(db.get_setting("port", str(config_mod.DEFAULT_PORT)))

    def set_port(value: int) -> None:
        db.set_setting("port", str(int(value)))

    # ---------------- 日志 ----------------
    def build_logs_panel() -> None:
        log_view = ui.log(max_lines=MAX_LOG_LINES).classes("w-full h-80 font-mono text-xs")
        for line in logs.snapshot():
            log_view.push(line)

        cursor = {"seq": logs.seq}

        def pump() -> None:
            new_lines, seq = logs.tail(cursor["seq"])
            for line in new_lines:
                log_view.push(line)
            cursor["seq"] = seq

        ui.timer(0.4, pump)

        def clear_logs() -> None:
            log_view.clear()
            cursor["seq"] = logs.seq
            ui.notify("日志视图已清空（后端缓冲仍保留）", type="info")

        ui.button("清空视图", icon="cleaning_services", on_click=clear_logs)

    with ui.tabs().classes("w-full") as tabs:
        tab_users = ui.tab("users", label="用户", icon="people")
        tab_service = ui.tab("service", label="服务", icon="settings")
        tab_logs = ui.tab("logs", label="日志", icon="receipt_long")

    with ui.tab_panels(tabs, value=tab_users).classes("w-full"):
        # ==================== 用户 ====================
        with ui.tab_panel(tab_users):
            with ui.card().classes("w-full"):
                ui.label("添加用户").classes("text-base font-semibold")
                username_input = ui.input(
                    "用户名", placeholder="字母/数字/点/下划线/连字符"
                ).classes("w-72")
                password_input = ui.input(
                    "密码", password=True, password_toggle_button=True,
                    placeholder="至少 6 位",
                ).classes("w-72")

                def add_user() -> None:
                    try:
                        user = db.add_user(username_input.value, password_input.value)
                    except ValidationError as exc:
                        ui.notify(f"添加失败：{exc}", type="negative")
                        return
                    username_input.value = ""
                    password_input.value = ""
                    state["selected"] = user.username
                    users_table.refresh()
                    count_label.set_text(user_count_label())
                    ui.notify(f"已添加用户 {user.username}", type="positive")

                def reset_password() -> None:
                    name = _selected()
                    if not name:
                        ui.notify("请先在下方表格里选中一个用户", type="warning")
                        return
                    try:
                        db.set_password(name, password_input.value)
                    except ValidationError as exc:
                        ui.notify(f"重置失败：{exc}", type="negative")
                        return
                    password_input.value = ""
                    ui.notify(f"已重置 {name} 的密码", type="positive")

                def toggle_enabled() -> None:
                    name = _selected()
                    if not name:
                        ui.notify("请先选中一个用户", type="warning")
                        return
                    user = db.get_user(name)
                    if user is None:
                        ui.notify("该用户已不存在", type="warning")
                        users_table.refresh()
                        return
                    db.set_enabled(name, not user.enabled)
                    users_table.refresh()
                    count_label.set_text(user_count_label())
                    ui.notify(
                        f"{name} 现在是{'禁用' if user.enabled else '启用'}状态",
                        type="positive",
                    )

                def delete_user() -> None:
                    name = _selected()
                    if not name:
                        ui.notify("请先选中一个用户", type="warning")
                        return
                    with ui.dialog() as dialog, ui.card():
                        ui.label(f"确定要删除用户 {name} 吗？此操作不可撤销。")
                        with ui.row():
                            ui.button("取消", on_click=dialog.close)

                            def confirm() -> None:
                                dialog.close()
                                try:
                                    db.delete_user(name)
                                except ValidationError as exc:
                                    ui.notify(f"删除失败：{exc}", type="negative")
                                    return
                                state["selected"] = None
                                users_table.refresh()
                                count_label.set_text(user_count_label())
                                ui.notify(f"已删除用户 {name}", type="positive")

                            ui.button("删除", color="negative", on_click=confirm)
                    dialog.open()

                with ui.row():
                    ui.button("添加用户", icon="person_add", on_click=add_user)
                    ui.button("重置密码", icon="key", on_click=reset_password)
                    ui.button("启用 / 禁用", icon="toggle_on", on_click=toggle_enabled)
                    ui.button("删除用户", icon="delete", color="negative",
                              on_click=delete_user)

            with ui.card().classes("w-full"):
                count_label = ui.label(user_count_label()).classes("text-sm")
                users_table()

        # ==================== 服务 ====================
        with ui.tab_panel(tab_service):
            with ui.card().classes("w-full"):
                ui.label("服务设置").classes("text-base font-semibold")
                ui.label(
                    "FTP 与 Web 控制台共用同一个端口：浏览器用 http、"
                    "FTP 客户端用 ftp，端口上的协议由首包自动区分。"
                ).classes("text-xs opacity-70")

                directory_input = ui.input(
                    "共享目录（FTP 用户看到的根目录）",
                    value=db.get_setting("share_dir", str(config_mod.default_share_dir())),
                ).classes("w-full")
                with ui.row().classes("items-end"):
                    port_input = ui.number(
                        "共享端口", value=current_port(), min=1, max=65535,
                        precision=0, format="%d",
                    ).classes("w-40")
                    autostop_input = ui.number(
                        "自动停止 FTP（分钟，0=不自动停）",
                        value=float(db.get_setting("auto_stop_minutes", "0")),
                        min=0, precision=1,
                    ).classes("w-64")

                readonly_switch = ui.switch(
                    "只读模式（FTP 用户只能下载）",
                    value=db.get_setting("readonly", "1") == "1",
                )
                with ui.row().classes("items-center gap-4"):
                    tls_switch = ui.switch(
                        "启用 FTPS 加密",
                        value=db.get_setting("use_tls", "0") == "1",
                    )
                    ui.button(
                        "生成自签证书", icon="verified_user",
                        on_click=lambda: generate_cert(),
                    )
                tls_status_label = ui.label("").classes("text-xs")

                def collect_config() -> ServerConfig:
                    directory_text = (directory_input.value or "").strip()
                    directory = (
                        Path(directory_text).expanduser()
                        if directory_text
                        else config_mod.default_share_dir()
                    )
                    try:
                        port = int(port_input.value or config_mod.DEFAULT_PORT)
                    except (TypeError, ValueError) as exc:
                        raise ServiceError(f"端口号必须是整数：{port_input.value!r}") from exc
                    if not (1 <= port <= 65535):
                        raise ServiceError(f"端口号必须在 1-65535 之间：{port}")
                    auto_stop = float(autostop_input.value or 0)
                    use_tls = bool(tls_switch.value)
                    return ServerConfig(
                        directory=directory,
                        readonly=bool(readonly_switch.value),
                        use_tls=use_tls,
                        certfile=config_mod.default_certfile() if use_tls else None,
                        keyfile=config_mod.default_keyfile() if use_tls else None,
                        auto_stop_minutes=auto_stop,
                    ), port

                def start_ftp() -> None:
                    try:
                        cfg, port = collect_config()
                    except (ServiceError, ValueError) as exc:
                        ui.notify(f"配置有误：{exc}", type="negative")
                        return
                    if port != service.port:
                        ui.notify(
                            f"共享端口是 {service.port}，改端口请用「应用端口」按钮",
                            type="warning",
                        )
                        return
                    db.set_setting("share_dir", str(cfg.directory))
                    db.set_setting("readonly", "1" if cfg.readonly else "0")
                    db.set_setting("use_tls", "1" if cfg.use_tls else "0")
                    db.set_setting("auto_stop_minutes", f"{cfg.auto_stop_minutes:g}")
                    try:
                        service.enable(cfg)
                    except ServiceError as exc:
                        ui.notify(f"启动失败：{exc}", type="negative")
                        return
                    ui.notify("FTP 服务正在启动", type="positive")

                def stop_ftp() -> None:
                    service.disable()
                    ui.notify("已请求停止 FTP 服务", type="info")

                def apply_port() -> None:
                    try:
                        new_port = int(port_input.value or 0)
                    except (TypeError, ValueError):
                        ui.notify("端口号必须是整数", type="negative")
                        return
                    old_port = service.port
                    if new_port == old_port:
                        ui.notify("端口没有变化", type="info")
                        return
                    set_port(new_port)
                    with ui.dialog() as dialog, ui.card():
                        ui.label(
                            f"将把共享端口从 {old_port} 切到 {new_port}。"
                            "当前页面会立刻断开。"
                        )
                        ui.label(
                            f"请改用 http://<本机IP>:{new_port}{MOUNT_PATH} 重新打开控制台。"
                        ).classes("text-sm")

                        def confirm() -> None:
                            dialog.close()
                            try:
                                service.rebind(new_port)
                            except ServiceError as exc:
                                ui.notify(f"切换失败：{exc}", type="negative")
                                return
                            ui.notify(f"已切换到端口 {new_port}", type="positive")

                        with ui.row():
                            ui.button("取消", on_click=dialog.close)
                            ui.button("切换", color="warning", on_click=confirm)
                    dialog.open()

                def generate_cert() -> None:
                    cert = config_mod.default_certfile()
                    key = config_mod.default_keyfile()
                    try:
                        generate_self_signed_cert(cert, key)
                    except TLSError as exc:
                        ui.notify(f"生成失败：{exc}", type="negative")
                        return
                    refresh_tls_status()
                    ui.notify(f"自签证书已生成：{cert}", type="positive")

                def refresh_tls_status() -> None:
                    cert = config_mod.default_certfile()
                    key = config_mod.default_keyfile()
                    if cert_exists(cert, key):
                        tls_status_label.set_text(f"证书已就绪：{cert}")
                    else:
                        tls_status_label.set_text(
                            "尚无证书 —— 启用 FTPS 之前请先点「生成自签证书」"
                        )

                with ui.row():
                    ui.button("启动 FTP", icon="play_arrow", on_click=start_ftp)
                    ui.button("停止 FTP", icon="stop", color="grey", on_click=stop_ftp)
                    ui.button("应用端口", icon="swap_horiz", color="warning",
                              on_click=apply_port)

            with ui.card().classes("w-full"):
                ui.label("运行状态").classes("text-base font-semibold")
                state_label = ui.label("")
                urls_label = ui.label("").classes("text-sm font-mono")
                countdown_label = ui.label("").classes("text-sm")

            refresh_tls_status()

        # ==================== 日志 ====================
        with ui.tab_panel(tab_logs):
            build_logs_panel()

    with ui.footer().classes("items-center px-4"):
        footer_label = ui.label("").classes("text-xs")

    # ---------------- 周期刷新 ----------------
    def refresh() -> None:
        running = service.running
        ftp_on = service.ftp_enabled
        port = service.port

        if not running:
            header_status.set_text("共享端口未运行")
        elif ftp_on:
            header_status.set_text(f"FTP 运行中 · 端口 {port}")
        else:
            header_status.set_text(f"FTP 已停止 · 端口 {port}（Web 控制台可用）")

        if ftp_on:
            state_label.set_text("FTP 服务：运行中")
        else:
            state_label.set_text("FTP 服务：已停止（可在上方启动）")

        urls = service.access_urls() if ftp_on else []
        web = service.web_urls()
        lines = []
        if urls:
            lines.append("FTP 地址：" + "    ".join(urls))
        if web:
            lines.append("控制台地址：" + "    ".join(web))
        urls_label.set_text("\n".join(lines) if lines else "（未就绪）")

        remaining = service.countdown_remaining()
        countdown_label.set_text(
            f"自动停止倒计时：{_format_duration(remaining)}"
            if remaining is not None
            else ""
        )

        footer_label.set_text(
            f"用户 {db.count_users()} 个 · 共享目录 "
            f"{db.get_setting('share_dir', str(config_mod.default_share_dir()))}"
        )

    ui.timer(0.5, refresh)
    users_table.refresh()
    refresh()


# --------------------------------------------------------------------------
# Web 后端（内部 uvicorn）
# --------------------------------------------------------------------------

class WebBackend:
    """在回环地址上跑 NiceGUI，供端口复用器转发。

    对外只暴露一个回环端口，真正的共享端口由
    :class:`ftpd.multiplex.MultiplexedFTPServer` 持有。
    """

    def __init__(self, console: WebConsole) -> None:
        self.console = console
        self.app: FastAPI = self._build_app()
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None

    def _build_app(self) -> FastAPI:
        console = self.console
        api = FastAPI(title="ftpd 控制台", docs_url=None, redoc_url=None)

        @api.get("/")
        async def _root() -> RedirectResponse:
            return RedirectResponse(MOUNT_PATH)

        @api.get("/healthz")
        async def _health() -> dict:
            return {"ok": True, "ftp": console.service.ftp_enabled}

        @ui.page("/")
        def _index() -> None:
            build_page(console)

        ui.run_with(
            api,
            mount_path=MOUNT_PATH,
            title="ftpd 控制台",
            favicon="🔐",
            show_welcome_message=False,
        )
        return api

    def start(self, host: str = "127.0.0.1") -> int:
        """启动内部 Web 服务，返回它监听的端口。"""
        if self._thread is not None:
            raise RuntimeError("Web 后端已经启动了")

        with socket.socket() as probe:
            probe.bind((host, 0))
            port = int(probe.getsockname()[1])

        config = uvicorn.Config(
            self.app, host=host, port=port, log_level="warning", ws="auto",
            access_log=False,
        )
        self._server = uvicorn.Server(config)
        self.port = port
        self._thread = threading.Thread(
            target=self._server.run, name="ftpd-web", daemon=True
        )
        self._thread.start()

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if getattr(self._server, "started", False):
                break
            time.sleep(0.05)
        return port

    def stop(self) -> None:
        server, self._server = self._server, None
        thread, self._thread = self._thread, None
        if server is not None:
            server.should_exit = True
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)
