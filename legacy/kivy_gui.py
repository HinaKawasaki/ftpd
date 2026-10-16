"""Kivy 图形界面。

线程模型（重要）：

* Kivy 的事件循环必须待在主线程，所以 FTP 服务在后台 daemon 线程里跑；
* 服务线程产生的日志不直接碰界面，而是丢进 ``queue.Queue``，
  主线程用 ``Clock.schedule_interval`` 定期排空，再刷新控件。
  这是 Kivy 里跨线程更新 UI 的稳妥做法；
* 启停服务这种可能阻塞的操作也放进临时线程，避免界面卡住。
"""

from __future__ import annotations

import argparse
import queue
import threading
from pathlib import Path
from typing import Callable, List, Optional

from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup

from ftpd import config as config_mod
from ftpd.db import UserDB, ValidationError
from .server import FTPService, ServerConfig, ServiceError
from .kivy_fonts import register_cjk_font
from ftpd.tls import TLSError, cert_exists, generate_self_signed_cert

KV_PATH = Path(__file__).with_name("kivy_gui.kv")
Builder.load_file(str(KV_PATH))

# Kivy 默认字体不含 CJK 字形，中文会变方块，这里换成系统中文字体
register_cjk_font()

MAX_LOG_LINES = 500


class RootWidget(BoxLayout):
    """KV 里定义的根布局。"""


def _format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    if minutes >= 60:
        hours, minutes = divmod(minutes, 60)
        return f"{hours} 小时 {minutes} 分"
    return f"{minutes:02d}:{secs:02d}"


class FTPDApp(App):
    title = "ftpd —— 带用户管理的 FTP 服务器"

    #: 当前在用户列表里选中的用户名
    selected_username = StringProperty("")

    def __init__(self, db: UserDB, **kwargs) -> None:
        super().__init__(**kwargs)
        self.db = db
        self.service = FTPService(db, on_event=self.log)
        self._log_queue: "queue.Queue[str]" = queue.Queue()
        self._log_lines: List[str] = []
        self._booted = False

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def build(self):
        root = RootWidget()
        Clock.schedule_interval(self._drain_logs, 0.2)
        Clock.schedule_interval(self._tick, 0.5)
        Clock.schedule_once(lambda _dt: self._post_build(), 0.05)
        return root

    def _post_build(self) -> None:
        self._booted = True
        self._load_settings()
        self.refresh_users()
        self._refresh_tls_status()
        self.log("就绪。先在「用户」页添加账号，再到「服务」页启动。")

    def on_stop(self) -> None:
        if self.service.running:
            self.service.stop()

    # ------------------------------------------------------------------
    # 日志（可被任意线程调用）
    # ------------------------------------------------------------------

    def log(self, message: str) -> None:
        """线程安全：服务线程和 GUI 线程都可以调用。"""
        self._log_queue.put(str(message))

    def _drain_logs(self, _dt) -> None:
        if not self._booted:
            return
        drained = []
        while True:
            try:
                drained.append(self._log_queue.get_nowait())
            except queue.Empty:
                break
        if not drained:
            return
        self._log_lines.extend(drained)
        if len(self._log_lines) > MAX_LOG_LINES:
            del self._log_lines[:-MAX_LOG_LINES]
        self.root.ids.log_label.text = "\n".join(self._log_lines)
        Clock.schedule_once(self._scroll_logs_to_bottom, 0.05)

    def _scroll_logs_to_bottom(self, _dt) -> None:
        self.root.ids.log_scroll.scroll_y = 0

    def action_clear_log(self) -> None:
        self._log_lines.clear()
        self.root.ids.log_label.text = "（暂无日志）"
        self._flash("日志已清空")

    def action_copy_log(self) -> None:
        try:
            Clipboard.copy("\n".join(self._log_lines))
        except Exception as exc:
            self._flash(f"复制失败（系统缺少剪贴板工具 xsel/xclip）：{exc}")
            return
        self._flash("日志已复制到剪贴板")

    # ------------------------------------------------------------------
    # 周期刷新：状态、地址、倒计时
    # ------------------------------------------------------------------

    def _tick(self, _dt) -> None:
        if not self._booted:
            return
        ids = self.root.ids
        running = self.service.running

        ids.start_button.disabled = running
        ids.stop_button.disabled = not running

        parts = ["● 服务运行中" if running else "○ 服务已停止"]
        if running:
            urls = self.service.access_urls()
            if urls:
                parts.append("   ".join(urls))
            remaining = self.service.countdown_remaining()
            if remaining is not None:
                parts.append(f"自动停止倒计时 {_format_duration(remaining)}")
        ids.status_bar.text = "    ".join(parts)

    # ------------------------------------------------------------------
    # 小工具
    # ------------------------------------------------------------------

    def _flash(self, message: str) -> None:
        """给一句即时的用户反馈：写进状态栏也记进日志。"""
        try:
            self.root.ids.status_bar.text = message
        except Exception:
            pass
        self.log(message)

    def _async(self, work: Callable[[], None], label: str) -> None:
        """把可能阻塞的动作放到临时线程里执行。"""

        def runner() -> None:
            try:
                work()
            except (ServiceError, TLSError, ValidationError, OSError) as exc:
                self.log(f"{label}失败：{exc}")
            except Exception as exc:  # pragma: no cover - 兜底
                self.log(f"{label}出现意外错误：{exc!r}")

        threading.Thread(target=runner, name="ftpd-gui-task", daemon=True).start()

    def _refresh_tls_status(self) -> None:
        cert = config_mod.default_certfile()
        key = config_mod.default_keyfile()
        if cert_exists(cert, key):
            self.root.ids.tls_status_label.text = f"证书已就绪：{cert}"
        else:
            self.root.ids.tls_status_label.text = (
                "尚无证书 —— 打开 FTPS 之前请先点「生成自签证书」"
            )

    # ------------------------------------------------------------------
    # 配置读写
    # ------------------------------------------------------------------

    def _load_settings(self) -> None:
        ids = self.root.ids
        ids.dir_input.text = self.db.get_setting(
            "share_dir", str(config_mod.default_share_dir())
        )
        ids.port_input.text = self.db.get_setting("port", str(config_mod.DEFAULT_PORT))
        ids.readonly_switch.active = self.db.get_setting("readonly", "1") == "1"
        ids.tls_switch.active = self.db.get_setting("use_tls", "0") == "1"
        ids.autostop_input.text = self.db.get_setting("auto_stop_minutes", "0")

    def _save_settings(self, cfg: ServerConfig) -> None:
        self.db.set_setting("share_dir", str(cfg.directory))
        self.db.set_setting("port", str(cfg.port))
        self.db.set_setting("readonly", "1" if cfg.readonly else "0")
        self.db.set_setting("use_tls", "1" if cfg.use_tls else "0")
        self.db.set_setting("auto_stop_minutes", f"{cfg.auto_stop_minutes:g}")

    def _collect_config(self) -> ServerConfig:
        ids = self.root.ids

        directory_text = ids.dir_input.text.strip()
        directory = Path(directory_text).expanduser() if directory_text else config_mod.default_share_dir()
        if not directory.is_dir():
            raise ServiceError(f"共享目录不存在或不是目录：{directory}")

        port_text = ids.port_input.text.strip() or str(config_mod.DEFAULT_PORT)
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ServiceError(f"端口号必须是整数，当前是 {port_text!r}") from exc

        auto_text = ids.autostop_input.text.strip() or "0"
        try:
            auto_stop = float(auto_text)
        except ValueError as exc:
            raise ServiceError(f"自动停止时间必须是数字，当前是 {auto_text!r}") from exc
        if auto_stop < 0:
            raise ServiceError("自动停止时间不能为负数")

        use_tls = bool(ids.tls_switch.active)
        cfg = ServerConfig(
            directory=directory,
            readonly=bool(ids.readonly_switch.active),
            use_tls=use_tls,
            certfile=config_mod.default_certfile() if use_tls else None,
            keyfile=config_mod.default_keyfile() if use_tls else None,
            auto_stop_minutes=auto_stop,
        )
        return cfg

    # ------------------------------------------------------------------
    # 用户管理
    # ------------------------------------------------------------------

    def select_user(self, username: str) -> None:
        self.selected_username = username
        self.refresh_users()
        self._flash(f"已选中 {username}")

    def refresh_users(self) -> None:
        if not self._booted:
            return
        grid = self.root.ids.user_grid
        grid.clear_widgets()
        users = self.db.list_users()

        if not users:
            grid.add_widget(
                Label(
                    text="还没有任何用户，请在上方填写后点「添加用户」",
                    size_hint_y=None,
                    height=dp(40),
                    halign="left",
                    valign="middle",
                    text_size=(grid.width or dp(400), None),
                )
            )
            self.root.ids.users_hint.text = "共 0 个用户"
            return

        for user in users:
            selected = user.username == self.selected_username
            mark = "▶" if selected else "  "
            text = (
                f"{mark} {user.username}    [{user.status_text}]"
                f"    最后登录：{user.last_login_text}"
            )
            button = Button(
                text=text,
                size_hint_y=None,
                height=dp(38),
                halign="left",
                valign="middle",
            )
            button.text_size = (button.width - dp(24), None)
            button.bind(
                width=lambda inst, width: setattr(inst, "text_size", (width - dp(24), None))
            )
            if selected:
                button.background_color = (0.20, 0.55, 0.86, 1)
            button.bind(
                on_release=lambda _inst, name=user.username: self.select_user(name)
            )
            grid.add_widget(button)

        enabled = sum(1 for u in users if u.enabled)
        self.root.ids.users_hint.text = (
            f"共 {len(users)} 个用户，其中 {enabled} 个启用"
        )

    def action_add_user(self) -> None:
        ids = self.root.ids
        try:
            user = self.db.add_user(ids.username_input.text, ids.password_input.text)
        except ValidationError as exc:
            self._flash(f"添加失败：{exc}")
            return
        ids.username_input.text = ""
        ids.password_input.text = ""
        self.selected_username = user.username
        self.refresh_users()
        self._flash(f"已添加用户 {user.username}")

    def action_reset_password(self) -> None:
        if not self.selected_username:
            self._flash("请先选中一个用户，再重置密码")
            return
        password = self.root.ids.password_input.text
        try:
            self.db.set_password(self.selected_username, password)
        except ValidationError as exc:
            self._flash(f"重置密码失败：{exc}")
            return
        self.root.ids.password_input.text = ""
        self._flash(f"已重置 {self.selected_username} 的密码")

    def action_toggle_enabled(self) -> None:
        if not self.selected_username:
            self._flash("请先选中一个用户")
            return
        user = self.db.get_user(self.selected_username)
        if user is None:
            self._flash("该用户已经不存在了")
            self.selected_username = ""
            self.refresh_users()
            return
        self.db.set_enabled(user.username, not user.enabled)
        self.refresh_users()
        self._flash(
            f"{user.username} 现在是{'禁用' if user.enabled else '启用'}状态"
        )

    def action_delete_user(self) -> None:
        if not self.selected_username:
            self._flash("请先选中一个用户，再删除")
            return

        username = self.selected_username
        content = BoxLayout(orientation="vertical", spacing=dp(10), padding=dp(10))
        content.add_widget(Label(text=f"确定要删除用户 {username} 吗？此操作不可撤销。"))
        buttons = BoxLayout(
            orientation="horizontal", spacing=dp(10), size_hint_y=None, height=dp(46)
        )
        popup = Popup(
            title="确认删除", content=content, size_hint=(0.62, 0.34),
            auto_dismiss=False,
        )

        def do_delete(*_args) -> None:
            popup.dismiss()
            try:
                self.db.delete_user(username)
            except ValidationError as exc:
                self._flash(f"删除失败：{exc}")
                return
            if self.selected_username == username:
                self.selected_username = ""
            self.refresh_users()
            self._flash(f"已删除用户 {username}")

        cancel = Button(text="取消")
        cancel.bind(on_release=lambda *_: popup.dismiss())
        confirm = Button(text="删除")
        confirm.bind(on_release=do_delete)
        buttons.add_widget(cancel)
        buttons.add_widget(confirm)
        content.add_widget(buttons)
        popup.open()

    # ------------------------------------------------------------------
    # 服务控制
    # ------------------------------------------------------------------

    def action_generate_cert(self) -> None:
        cert = config_mod.default_certfile()
        key = config_mod.default_keyfile()

        def work() -> None:
            generate_self_signed_cert(cert, key)
            self.log(f"自签证书已生成：{cert}")
            Clock.schedule_once(lambda _dt: self._refresh_tls_status(), 0)

        self._async(work, "生成证书")

    def action_start_service(self) -> None:
        try:
            cfg = self._collect_config()
        except ServiceError as exc:
            self._flash(f"启动失败：{exc}")
            return
        self._save_settings(cfg)
        self._async(lambda: self.service.start(cfg), "启动服务")

    def action_stop_service(self) -> None:
        self._async(self.service.stop, "停止服务")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ftpd", description="带用户管理与图形界面的 FTP 服务器"
    )
    parser.add_argument(
        "--db", default=None, help="用户数据库文件路径（默认在 ~/.local/share/ftpd/）"
    )
    args = parser.parse_args(argv)

    db_file = Path(args.db).expanduser() if args.db else config_mod.db_path()
    db_file.parent.mkdir(parents=True, exist_ok=True)

    Window.size = (1000, 720)
    app = FTPDApp(UserDB(db_file))
    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
