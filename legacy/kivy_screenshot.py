"""在虚拟显示（Xvfb）上给 GUI 截图，用于开发期验证。

用法：
    DISPLAY=:99 SDL_VIDEODRIVER=x11 python tools/screenshot.py [输出目录]

它会造一个带演示用户的临时数据库、真的把 FTP 服务跑起来，
然后依次给三个标签页截图，最后干净退出。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kivy.clock import Clock  # noqa: E402
from kivy.core.window import Window  # noqa: E402

from ftpd.db import UserDB  # noqa: E402
from ftpd.gui import FTPDApp  # noqa: E402
from ftpd.server import ServerConfig  # noqa: E402


def build_demo_db(path: Path) -> UserDB:
    if path.exists():
        path.unlink()
    db = UserDB(path)
    for name, password in [
        ("alice", "secret123"),
        ("bob", "hunter22"),
        ("carol", "pa55word"),
    ]:
        db.add_user(name, password)
    db.set_enabled("carol", False)
    db.touch_login("alice")
    return db


def select_tab(app: FTPDApp, text: str) -> None:
    tabs = app.root.ids.tabs
    for tab in tabs.tab_list:
        if tab.text == text:
            tabs.switch_to(tab)
            return


def main() -> int:
    outdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/ftpd-shots")
    outdir.mkdir(parents=True, exist_ok=True)

    share = Path.home() / "shared"
    share.mkdir(exist_ok=True)
    (share / "readme.txt").write_text("demo file\n", encoding="utf-8")

    db = build_demo_db(outdir / "demo-users.db")
    db.set_setting("share_dir", str(share))
    db.set_setting("port", "21210")
    db.set_setting("readonly", "1")
    db.set_setting("auto_stop_minutes", "10")

    app = FTPDApp(db)

    def shot(name: str) -> None:
        target = outdir / name
        Window.screenshot(name=str(target))
        print(f"截图 -> {target}", flush=True)

    def boot(_dt) -> None:
        app.service.start(
            ServerConfig(
                directory=share,
                port=21210,
                host="127.0.0.1",
                readonly=True,
                auto_stop_minutes=10,
            )
        )
        app.refresh_users()

    def step(tab: str, filename: str):
        def action(_dt) -> None:
            select_tab(app, tab)
            Clock.schedule_once(lambda _dt2: shot(filename), 0.35)

        return action

    def finish(_dt) -> None:
        app.service.stop()
        app.stop()

    Clock.schedule_once(boot, 0.8)
    Clock.schedule_once(step("用户", "1-users.png"), 1.6)
    Clock.schedule_once(step("服务", "2-service.png"), 2.6)
    Clock.schedule_once(step("日志", "3-logs.png"), 3.6)
    Clock.schedule_once(finish, 4.8)

    app.run()
    db.close()
    print("完成", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
