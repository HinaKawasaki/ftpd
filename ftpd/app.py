"""应用装配与命令行入口。

启动顺序：

1. 先把 NiceGUI/uvicorn 起在**回环地址**的一个内部端口上；
2. 再用 :class:`ftpd.server.FTPService` 占用**共享端口**，
   并把内部 Web 端口告诉它 —— 端口上的协议复用由它负责；
3. 主线程只负责等待 Ctrl+C。

这样打开 ``http://<本机IP>:<共享端口>/webgui`` 就能看到控制台，
而 ``ftp://<本机IP>:<共享端口>`` 是 FTP，两者同一个端口。
"""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path
from typing import List, Optional

from . import config as config_mod
from .db import UserDB
from .multiplex import DEFAULT_GRACE
from .server import FTPService, ServiceError
from .webgui import LogBuffer, WebBackend, WebConsole


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ftpd",
        description="FTP 服务器 + Web 控制台，两者共用一个端口",
    )
    parser.add_argument(
        "--db", default=None,
        help="用户数据库文件路径（默认 ~/.local/share/ftpd/users.db）",
    )
    parser.add_argument(
        "--port", type=int, default=None,
        help=f"共享端口（默认取上次保存的设置，初始 {config_mod.DEFAULT_PORT}）",
    )
    parser.add_argument(
        "--host", default=config_mod.DEFAULT_HOST,
        help=f"监听地址（默认 {config_mod.DEFAULT_HOST}）",
    )
    parser.add_argument(
        "--classify-grace", type=float, default=DEFAULT_GRACE,
        help=(
            "共用端口上判定协议时最多等首包多久（秒）。"
            f"默认 {DEFAULT_GRACE:g}；调小可让 FTP 连接更快，"
            "但太小时较慢的 HTTP 客户端可能被误判成 FTP"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    db_file = Path(args.db).expanduser() if args.db else config_mod.db_path()
    db_file.parent.mkdir(parents=True, exist_ok=True)

    db = UserDB(db_file)
    logs = LogBuffer()
    service = FTPService(db, on_event=logs.append)
    console = WebConsole(db, service, logs)
    backend = WebBackend(console)

    # 1) 内部 Web 后端
    web_port = backend.start()
    logs.append(f"[启动] Web 后端已在 127.0.0.1:{web_port} 就绪")

    # 2) 共享端口
    port = int(args.port or db.get_setting("port", str(config_mod.DEFAULT_PORT)))
    try:
        service.serve(
            port,
            http_target=("127.0.0.1", web_port),
            host=args.host,
            classify_grace=args.classify_grace,
        )
    except ServiceError as exc:
        print(f"启动失败：{exc}", file=sys.stderr)
        backend.stop()
        db.close()
        return 1

    db.set_setting("port", str(port))
    logs.append("[启动] 共享端口就绪，FTP 默认处于停止状态")

    if not db.admin_exists():
        print("！还没有设置管理员密码：第一个打开控制台的人就能设置它。")
        if args.host not in ("127.0.0.1", "localhost"):
            print(f"！当前监听在 {args.host}，请尽快打开控制台完成初始化。")
        print()

    print("ftpd 已启动。", flush=True)
    print(f"  Web 控制台：http://<本机IP>:{port}{config_mod.__dict__.get('MOUNT_HINT', '/webgui')}")
    print(f"  FTP 登录  ：ftp://<本机IP>:{port}   （先到控制台添加用户并启动 FTP）")
    print(f"  数据库    ：{db_file}")
    print("按 Ctrl+C 退出。")

    stop = threading.Event()

    def _on_signal(signum, _frame) -> None:  # pragma: no cover - 交互路径
        print(f"\n收到信号 {signum}，正在退出……")
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _on_signal)
        except (ValueError, OSError):  # 非主线程等情况下跳过
            pass

    try:
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:  # pragma: no cover
        print("\n正在退出……")
    finally:
        service.shutdown()
        backend.stop()
        db.close()
    print("已退出。")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
