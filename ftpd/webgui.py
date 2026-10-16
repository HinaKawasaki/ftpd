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

import hmac
import socket
import threading
import time
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import uvicorn
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from nicegui import app, ui

from . import config as config_mod
from .db import UserDB, ValidationError
from .net import local_ipv4_addresses
from .security import LoginThrottle, attempt_keys
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
        #: Web 控制台的登录限流（与 FTP 的分开统计）
        self.admin_throttle = LoginThrottle()
        #: 首次初始化的口令；只在还没设置管理员时存在
        self.setup_token: Optional[str] = None
        #: 由 app 层回填，便于在界面上重启 HTTPS 后端
        self.backend: Optional["WebBackend"] = None
        #: 控制台对外的端口与协议（由 app 层按运行模式回填）
        self.web_port: Optional[int] = None
        self.web_https: bool = False
        #: 是否共用一个端口（由 app 层按启动参数回填）
        self.shared_port: bool = False


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


def client_ip() -> Optional[str]:
    """当前浏览器连接的来源地址（拿不到就返回 None）。"""
    try:
        return getattr(ui.context.client, "ip", None)
    except Exception:
        return None


def attempt_admin_login(
    console: "WebConsole", username: str, password: str, ip: Optional[str] = None
) -> Tuple[bool, str]:
    """校验管理员登录，返回 (是否成功, 提示语)。

    抽成纯函数是为了能脱离浏览器直接测试。
    """
    keys = attempt_keys(username or "", ip)
    remaining = console.admin_throttle.lock_remaining(keys)
    if remaining > 0:
        return False, f"失败次数过多，请 {int(remaining) + 1} 秒后再试"

    if not console.db.verify_admin(username or "", password or ""):
        console.admin_throttle.record_failure(keys)
        return False, "用户名或密码错误"

    console.admin_throttle.record_success(keys)
    return True, "登录成功"


def console_urls(console: "WebConsole") -> List[str]:
    """控制台的对外地址。端口与协议由 app 层回填。"""
    if not console.web_port:
        return []
    hosts = local_ipv4_addresses() or ["<本机IP>"]
    scheme = "https" if console.web_https else "http"
    return [f"{scheme}://{host}:{console.web_port}{MOUNT_PATH}" for host in hosts]


def is_loopback(ip: Optional[str]) -> bool:
    """是否是本机来源。"""
    if not ip:
        return False
    return ip.startswith("127.") or ip in ("::1", "localhost")


def create_admin(
    console: "WebConsole",
    username: str,
    password: str,
    confirm: str,
    *,
    token: str = "",
    client_ip: Optional[str] = None,
) -> Tuple[bool, str]:
    """首次运行时创建管理员，返回 (是否成功, 提示语)。

    还没设管理员时，任何人都能打开初始化页 —— 所以启动时会生成一个一次性口令。
    本机（回环）访问不需要口令：能操作本机的人本来就有 shell 权限；
    其它来源必须提供口令，否则「谁先打开谁当管理员」的窗口就堵不住。
    """
    if console.setup_token and not is_loopback(client_ip):
        if not hmac.compare_digest((token or "").strip(), console.setup_token):
            return False, "初始化口令不正确（见启动时终端打印的口令）"

    if (password or "") != (confirm or ""):
        return False, "两次输入的密码不一致"
    try:
        console.db.set_admin(username or "admin", password or "")
    except ValidationError as exc:
        return False, f"设置失败：{exc}"
    return True, "管理员已创建"


def login_redirect(console: "WebConsole") -> Optional[RedirectResponse]:
    """页面守卫。

    注意：**页面函数里不能靠 ``ui.navigate.to`` 跳转**（那时浏览器还没连上，
    JS 发不出去），必须返回一个 ``RedirectResponse``；NiceGUI 见到页面函数
    返回 Response 就不再渲染页面。事件处理器里则相反，用 ``ui.navigate.to``。
    """
    if not console.db.admin_exists():
        return RedirectResponse(f"{MOUNT_PATH}/setup")
    if not app.storage.user.get("admin"):
        return RedirectResponse(f"{MOUNT_PATH}/login")
    return None


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
        with ui.row().classes("items-center gap-3"):
            header_status = ui.label("").classes("text-sm opacity-90")
            ui.label(f"管理员：{db.admin_username()}").classes("text-xs opacity-90")
            ui.button(
                "退出", icon="logout",
                on_click=lambda: ui.navigate.to("/logout"),
            ).props("flat dense color=white")

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

    def current_web_port() -> int:
        return int(db.get_setting("web_port", str(config_mod.DEFAULT_WEB_PORT)))

    def set_web_port(value: int) -> None:
        db.set_setting("web_port", str(int(value)))

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

            with ui.card().classes("w-full"):
                ui.label("管理员密码").classes("text-base font-semibold")
                ui.label(
                    f"当前管理员：{db.admin_username()}"
                    "（只用于登录这个控制台，与 FTP 用户无关）"
                ).classes("text-xs opacity-70")
                current_admin_pw = ui.input(
                    "当前密码", password=True, password_toggle_button=True
                ).classes("w-72")
                new_admin_pw = ui.input(
                    "新密码", password=True, password_toggle_button=True
                ).classes("w-72")

                def change_admin_password() -> None:
                    if not db.verify_admin(
                        db.admin_username(), current_admin_pw.value or ""
                    ):
                        ui.notify("当前密码不正确", type="negative")
                        return
                    try:
                        db.set_admin(db.admin_username(), new_admin_pw.value or "")
                    except ValidationError as exc:
                        ui.notify(f"修改失败：{exc}", type="negative")
                        return
                    current_admin_pw.value = ""
                    new_admin_pw.value = ""
                    ui.notify("管理员密码已更新", type="positive")

                ui.button("修改密码", icon="password", on_click=change_admin_password)

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
                        "FTP 端口", value=current_port(), min=1, max=65535,
                        precision=0, format="%d",
                    ).classes("w-40")
                    web_port_input = ui.number(
                        "Web 控制台端口（改后需重启）",
                        value=current_web_port(), min=1, max=65535,
                        precision=0, format="%d",
                    ).classes("w-56")
                    autostop_input = ui.number(
                        "自动停止 FTP（分钟，0=不自动停）",
                        value=float(db.get_setting("auto_stop_minutes", "0")),
                        min=0, precision=1,
                    ).classes("w-64")

                if console.shared_port:
                    ui.label(
                        "当前是「共用端口」模式：FTP 与控制台在同一个端口上，"
                        "Web 控制台端口这一项不生效。"
                    ).classes("text-xs opacity-70")

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

                console_scheme_label = ui.label("").classes("text-xs")

                def collect_config() -> Tuple[ServerConfig, int]:
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
                            f"当前 FTP 端口是 {service.port}，要换请用「应用 FTP 端口」",
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

                def save_web_port() -> None:
                    try:
                        value = int(web_port_input.value or 0)
                    except (TypeError, ValueError):
                        ui.notify("端口号必须是整数", type="negative")
                        return
                    if not (1 <= value <= 65535):
                        ui.notify("端口号必须在 1-65535 之间", type="negative")
                        return
                    set_web_port(value)
                    ui.notify(
                        f"Web 控制台端口已保存为 {value}，重启后生效", type="positive"
                    )

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
                    if not console.shared_port:
                        # 端口分开：换 FTP 端口不影响控制台，直接切就行
                        try:
                            service.rebind(new_port)
                        except ServiceError as exc:
                            ui.notify(f"切换失败：{exc}", type="negative")
                            return
                        ui.notify(f"FTP 端口已切到 {new_port}", type="positive")
                        return
                    with ui.dialog() as dialog, ui.card():
                        ui.label(
                            f"将把共享端口从 {old_port} 切到 {new_port}。"
                            "当前页面会立刻断开。"
                        )
                        ui.label(
                            f"请改用 http://<本机IP>:{new_port}{MOUNT_PATH} 重新打开控制台。"
                        ).classes("text-sm")

                        def do_rebind(port_number: int) -> None:
                            try:
                                service.rebind(port_number)
                            except ServiceError as exc:
                                logs.append(f"[错误] 切换端口失败：{exc}")

                        def confirm() -> None:
                            dialog.close()
                            # 先把跳转脚本交给浏览器，再执行会断开连接的切换
                            try:
                                ui.run_javascript(_redirect_js(new_port))
                            except Exception:
                                pass
                            ui.notify(
                                f"正在切换到端口 {new_port}，页面会自动跳转",
                                type="info",
                            )
                            ui.timer(1.5, lambda: do_rebind(new_port), once=True)

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

                    # 证书换新后，把用到它的两处立刻切过去
                    backend = console.backend
                    if backend is not None:
                        https_port = backend.restart_https(cert, key)
                        if https_port:
                            service.set_web_targets(None, ("127.0.0.1", https_port))
                            logs.append("[证书] HTTPS 后端已用新证书重启")
                        elif backend.http_port:
                            logs.append(
                                "[证书] 控制台当前是明文模式；重启后即可用 HTTPS 访问"
                            )
                        else:
                            logs.append("[证书] HTTPS 后端启动失败")
                    if service.ftp_enabled and service.config and service.config.use_tls:
                        service.enable(service.config)
                        logs.append("[证书] FTPS 已用新证书重启")

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
                    ui.button("应用 FTP 端口", icon="swap_horiz", color="warning",
                              on_click=apply_port)
                    ui.button("保存 Web 端口", icon="save", color="grey",
                              on_click=save_web_port)

            with ui.card().classes("w-full"):
                ui.label("运行状态").classes("text-base font-semibold")
                state_label = ui.label("")
                urls_label = ui.label("").classes("text-sm font-mono")
                countdown_label = ui.label("").classes("text-sm")
                locked_label = ui.label("").classes("text-sm text-negative")

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
            header_status.set_text("端口未运行")
        elif ftp_on:
            header_status.set_text(f"FTP 运行中 · 端口 {port}")
        else:
            header_status.set_text(f"FTP 已停止 · 端口 {port}（Web 控制台可用）")

        if ftp_on:
            state_label.set_text("FTP 服务：运行中")
        else:
            state_label.set_text("FTP 服务：已停止（可在上方启动）")

        urls = service.access_urls() if ftp_on else []
        web = console_urls(console)
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

        if console.web_https:
            detail = (
                "明文请求会 301 跳转"
                if console.shared_port
                else "控制台端口只接受 https://"
            )
            console_scheme_label.set_text(f"控制台协议：HTTPS（{detail}）")
        else:
            console_scheme_label.set_text(
                "控制台协议：HTTP（未启用 HTTPS，启动时不加 --no-console-tls 即可开启）"
            )

        locked = service.throttle.locked_accounts()
        if locked:
            items = "，".join(f"{k}（{int(v)}s）" for k, v in locked.items())
            locked_label.set_text(f"登录已锁定：{items}")
        else:
            locked_label.set_text("")

        footer_label.set_text(
            f"用户 {db.count_users()} 个 · 共享目录 "
            f"{db.get_setting('share_dir', str(config_mod.default_share_dir()))}"
        )

    ui.timer(0.5, refresh)
    users_table.refresh()
    refresh()


# --------------------------------------------------------------------------
# 换端口后的浏览器跳转
# --------------------------------------------------------------------------


def _redirect_js(new_port: int) -> str:
    """换端口后让浏览器自己跟过去的脚本。

    切换端口会立刻断开当前页面，所以先把脚本发下去，再执行切换。
    脚本只探测**新端口**：握手成功才跳转，否则一直重试，
    避免跳过去撞上「连接被拒绝」。
    """
    return f"""
    (function () {{
      const base = location.protocol + "//" + location.hostname + ":{new_port}";
      const target = base + "{MOUNT_PATH}/";
      let tries = 0;
      function attempt() {{
        tries += 1;
        fetch(base + "/healthz", {{cache: "no-store", mode: "no-cors"}})
          .then(function () {{ window.location.href = target; }})
          .catch(function () {{
            // 自签证书会让 fetch 因证书校验失败而永远探测不通，
            // 所以试够次数就直接跳，总比停在已经断掉的旧页面上强。
            if (tries < 20) setTimeout(attempt, 500);
            else window.location.href = target;
          }});
      }}
      setTimeout(attempt, 1500);
    }})();
    """


def build_login_page(console: WebConsole) -> None:
    db = console.db
    ui.page_title("登录 · ftpd 控制台")
    ui.colors(primary="#1565c0")

    with ui.column().classes("absolute-center items-center"):
        with ui.card().classes("w-96"):
            with ui.row().classes("items-center gap-2"):
                ui.icon("lock").classes("text-2xl")
                ui.label("ftpd 控制台").classes("text-lg font-semibold")
            username = ui.input("用户名", value=db.admin_username()).classes("w-full")
            password = ui.input(
                "密码", password=True, password_toggle_button=True
            ).classes("w-full")

            def do_login() -> None:
                ok, message = attempt_admin_login(
                    console, username.value or "", password.value or "", client_ip()
                )
                if not ok:
                    ui.notify(message, type="negative")
                    return
                app.storage.user["admin"] = db.admin_username()
                ui.navigate.to("/")

            password.on("keydown.enter", lambda _event: do_login())
            ui.button("登录", icon="login", on_click=do_login).classes("w-full")


def build_setup_page(console: WebConsole) -> None:
    db = console.db
    ui.page_title("初始化 · ftpd 控制台")
    ui.colors(primary="#1565c0")

    with ui.column().classes("absolute-center items-center"):
        with ui.card().classes("w-[30rem]"):
            ui.label("第一次使用，先设置管理员账号").classes("text-lg font-semibold")
            ui.label(
                "这个账号只用来登录 Web 控制台；FTP 用户是另一回事，"
                "登录进来后在「用户」页添加。"
            ).classes("text-xs opacity-70")
            username = ui.input("管理员用户名", value="admin").classes("w-full")
            password = ui.input(
                "密码", password=True, password_toggle_button=True,
                placeholder="至少 6 位",
            ).classes("w-full")
            confirm = ui.input("再输一次", password=True).classes("w-full")
            token_input = ui.input(
                "初始化口令",
                placeholder="本机访问可留空；其它机器请填终端里打印的口令",
            ).classes("w-full")

            def do_setup() -> None:
                ok, message = create_admin(
                    console, username.value or "", password.value or "",
                    confirm.value or "",
                    token=token_input.value or "", client_ip=client_ip(),
                )
                if not ok:
                    ui.notify(message, type="negative")
                    return
                app.storage.user["admin"] = db.admin_username()
                ui.notify(message, type="positive")
                ui.navigate.to("/")

            ui.button("创建并进入", icon="check", on_click=do_setup).classes("w-full")



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
        self.host = "127.0.0.1"
        self.app: FastAPI = self._build_app()
        self.http_port: Optional[int] = None
        self.https_port: Optional[int] = None
        self.certfile: Optional[Path] = None
        self.keyfile: Optional[Path] = None
        self._http: Optional[Tuple[uvicorn.Server, threading.Thread]] = None
        self._https: Optional[Tuple[uvicorn.Server, threading.Thread]] = None

    def _build_app(self) -> FastAPI:
        console = self.console
        # NiceGUI 默认把会话存储写在 ./.nicegui，会污染仓库；挪到数据目录
        storage_root = config_mod.data_dir() / "webgui"
        storage_root.mkdir(parents=True, exist_ok=True)
        app.storage.path = storage_root

        api = FastAPI(title="ftpd 控制台", docs_url=None, redoc_url=None)

        @api.get("/")
        async def _root() -> RedirectResponse:
            return RedirectResponse(MOUNT_PATH)

        @api.get("/healthz")
        async def _health() -> dict:
            # 探针接口保持公开，但不泄露 FTP 运行状态
            return {"ok": True}

        @ui.page("/")
        def _index():
            redirect = login_redirect(console)
            if redirect is not None:
                return redirect
            build_page(console)
            return None

        @ui.page("/login")
        def _login():
            if not console.db.admin_exists():
                return RedirectResponse(f"{MOUNT_PATH}/setup")
            if app.storage.user.get("admin"):
                return RedirectResponse(f"{MOUNT_PATH}/")
            build_login_page(console)
            return None

        @ui.page("/setup")
        def _setup():
            if console.db.admin_exists():
                return RedirectResponse(f"{MOUNT_PATH}/login")
            build_setup_page(console)
            return None

        @ui.page("/logout")
        def _logout():
            app.storage.user.clear()
            return RedirectResponse(f"{MOUNT_PATH}/login")

        ui.run_with(
            api,
            mount_path=MOUNT_PATH,
            title="ftpd 控制台",
            favicon="🔐",
            storage_secret=console.db.session_secret(),
            show_welcome_message=False,
        )
        return api

    def _serve_one(self, *, certfile=None, keyfile=None, port=None, host=None):
        """起一个 uvicorn，返回 (server, thread, port)。

        ``port`` 为 None 时在回环上挑一个空闲端口（共用端口模式，
        由协议复用器转过来）；给了端口就直接绑上去（端口分开模式）。
        """
        host = host or self.host
        if port is None:
            with socket.socket() as probe:
                probe.bind((host, 0))
                port = int(probe.getsockname()[1])

        config = uvicorn.Config(
            self.app, host=host, port=port, log_level="warning", ws="auto",
            access_log=False,
            # 前置的端口复用器会给每条连接注入 X-Forwarded-For，
            # 它来自回环地址，所以只信任回环
            proxy_headers=True,
            forwarded_allow_ips="127.0.0.1",
            ssl_certfile=str(certfile) if certfile else None,
            ssl_keyfile=str(keyfile) if keyfile else None,
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, name="ftpd-web", daemon=True)
        thread.start()

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if getattr(server, "started", False):
                break
            if not thread.is_alive():
                raise RuntimeError("Web 后端线程提前退出")
            time.sleep(0.05)
        return server, thread, port

    @staticmethod
    def _shutdown(pair) -> None:
        if pair is None:
            return
        server, thread = pair
        server.should_exit = True
        if thread.is_alive():
            thread.join(timeout=5)

    def start(
        self,
        host: str = "127.0.0.1",
        *,
        port: Optional[int] = None,
        certfile=None,
        keyfile=None,
    ):
        """启动 Web 服务，返回 (明文端口或 None, HTTPS 端口或 None)。

        * ``port=None``：绑回环上的空闲端口，供协议复用器转发（共用一个端口）；
        * ``port=2122``：直接绑到该端口对外服务（FTP 与 Web 分开）。

        **只会起一个后端**：有证书就走 HTTPS，没有就走明文。

        为什么不 HTTP 和 HTTPS 各起一个：NiceGUI 的 ``Slot.stacks`` 是模块级全局字典、
        按 asyncio 任务 id 索引（``nicegui/slot.py``）；两个事件循环同时用它会出现
        id 复用，导致 ``IndexError: pop from empty list`` 之类的内部崩溃——实测复现过。
        """
        if self._http is not None or self._https is not None:
            raise RuntimeError("Web 后端已经启动了")
        self.host = host

        if certfile and keyfile:
            https_port = self.start_https(certfile, keyfile, port=port)
            if https_port is not None:
                return None, https_port
            self.console.logs.append("[警告] HTTPS 后端起不来，退回明文 HTTP")

        server, thread, self.http_port = self._serve_one(port=port)
        self._http = (server, thread)
        return self.http_port, None

    def start_https(self, certfile, keyfile, *, port=None) -> Optional[int]:
        """启动 HTTPS 后端；失败只记日志。

        如果明文后端已经在跑，这里直接拒绝——一个 NiceGUI 应用不能同时挂两个事件循环。
        """
        if self._http is not None:
            self.console.logs.append(
                "[警告] 明文控制台后端已在运行，无法同时启用 HTTPS（需重启进程）"
            )
            return None
        self._shutdown(self._https)
        self._https = None
        self.https_port = None
        try:
            server, thread, bound = self._serve_one(
                certfile=certfile, keyfile=keyfile, port=port
            )
        except Exception as exc:  # pragma: no cover - 证书坏了之类
            self.console.logs.append(f"[警告] HTTPS 后端启动失败：{exc}")
            return None
        self._https = (server, thread)
        self.https_port = bound
        self.certfile, self.keyfile = Path(certfile), Path(keyfile)
        return bound

    def restart_https(self, certfile, keyfile) -> Optional[int]:
        """换证书后重启 HTTPS 后端；本来没跑 HTTPS 就什么都不做。"""
        if self._https is None:
            return None
        return self.start_https(certfile, keyfile)

    def stop(self) -> None:
        self._shutdown(self._https)
        self._shutdown(self._http)
        self._https = None
        self._http = None
        self.https_port = None
