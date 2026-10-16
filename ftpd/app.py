"""应用装配与命令行入口。

启动顺序：

1. 需要的话先生成一张自签证书（FTPS 与控制台 HTTPS 共用）；
2. 把 NiceGUI/uvicorn 起在**回环地址**上 —— 明文一个、HTTPS 一个，
   两者共用一个 FastAPI 应用对象；
3. 再用 :class:`ftpd.server.FTPService` 占用**共享端口**，
   并把两个内部端口告诉它：端口上的协议复用由它负责
   （TLS 连接走 HTTPS 后端，明文 HTTP 走另一个）；
4. 主线程只负责等待 Ctrl+C。

这样 ``https://<本机IP>:<端口>/webgui`` 是控制台、
``ftp://<本机IP>:<端口>`` 是 FTP，同一个端口。
"""

from __future__ import annotations

import argparse
import secrets
import signal
import sys
import threading
from pathlib import Path
from typing import List, Optional, Tuple

from . import config as config_mod
from .db import UserDB
from .multiplex import DEFAULT_GRACE
from .server import FTPService, ServiceError
from .tls import TLSError, cert_exists, generate_self_signed_cert
from .webgui import LogBuffer, WebBackend, WebConsole, console_urls


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
        help=f"FTP 端口（默认取上次保存的设置，初始 {config_mod.DEFAULT_PORT}）",
    )
    parser.add_argument(
        "--web-port", type=int, default=None,
        help=(
            "Web 控制台端口（默认取上次保存的设置，初始 "
            f"{config_mod.DEFAULT_WEB_PORT}）"
        ),
    )
    parser.add_argument(
        "--shared-port", action="store_true",
        help=(
            "把 FTP 和 Web 控制台放回同一个端口（靠首包嗅探分流）。"
            "默认是两个端口；共用时 FTP 连接要多等一小会儿用于判定协议"
        ),
    )
    parser.add_argument(
        "--host", default=config_mod.DEFAULT_HOST,
        help=f"监听地址（默认 {config_mod.DEFAULT_HOST}）",
    )
    parser.add_argument(
        "--classify-grace", type=float, default=DEFAULT_GRACE,
        help=(
            "共用端口上判定协议时最多等首包多久（秒），自适应模式下的上限。"
            f"默认 {DEFAULT_GRACE:g}；太小时较慢的 HTTP 客户端可能被误判成 FTP"
        ),
    )
    parser.add_argument(
        "--adaptive-grace", action="store_true",
        help=(
            "按连接 RTT 自适应缩短判定等待（默认关闭）。"
            "能让直连场景下的 FTP 连接快很多，但**中间有代理/转发层时会误判**——"
            "那里读到的 RTT 只是到代理的那一跳"
        ),
    )
    parser.add_argument(
        "--no-console-tls", action="store_true",
        help="不给 Web 控制台启用 HTTPS（默认会生成自签证书并用 HTTPS）",
    )
    return parser.parse_args(argv)


def _prepare_certificate(logs: LogBuffer) -> Tuple[Optional[Path], Optional[Path]]:
    """有就用，没有就生成；生成不了就退回明文并记一条日志。"""
    certfile = config_mod.default_certfile()
    keyfile = config_mod.default_keyfile()
    if cert_exists(certfile, keyfile):
        return certfile, keyfile
    try:
        generate_self_signed_cert(certfile, keyfile)
    except TLSError as exc:
        logs.append(f"[启动] 没能生成自签证书（{exc}），控制台与 FTPS 只能走明文")
        return None, None
    logs.append(f"[启动] 已生成自签证书：{certfile}")
    return certfile, keyfile


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    db_file = Path(args.db).expanduser() if args.db else config_mod.db_path()
    db_file.parent.mkdir(parents=True, exist_ok=True)

    db = UserDB(db_file)
    logs = LogBuffer()
    service = FTPService(db, on_event=logs.append)
    console = WebConsole(db, service, logs)

    certfile, keyfile = (None, None)
    if not args.no_console_tls:
        certfile, keyfile = _prepare_certificate(logs)

    port = int(args.port or db.get_setting("port", str(config_mod.DEFAULT_PORT)))
    web_port = int(
        args.web_port or db.get_setting("web_port", str(config_mod.DEFAULT_WEB_PORT))
    )

    backend = WebBackend(console)
    console.backend = backend
    if args.shared_port:
        http_port, https_port = backend.start(
            host="127.0.0.1", certfile=certfile, keyfile=keyfile
        )
    else:
        http_port, https_port = backend.start(
            host=args.host, port=web_port, certfile=certfile, keyfile=keyfile
        )
    logs.append(
        "[启动] Web 后端就绪："
        + (f"HTTPS {https_port}" if https_port else f"明文 HTTP {http_port}")
    )

    try:
        if args.shared_port:
            # 共用一个端口：Web 后端留在回环上，由协议复用器转发
            http_target = ("127.0.0.1", http_port) if http_port else None
            https_target = ("127.0.0.1", https_port) if https_port else None
            console.web_port = port
        else:
            # 端口分开：FTP 端口只做 FTP，完全不需要判定协议
            http_target = https_target = None
            console.web_port = web_port
        console.web_https = bool(https_port)
        console.shared_port = bool(args.shared_port)
        service.serve(
            port,
            http_target=http_target,
            https_target=https_target,
            host=args.host,
            classify_grace=args.classify_grace,
            adaptive_grace=args.adaptive_grace,
        )
    except ServiceError as exc:
        print(f"启动失败：{exc}", file=sys.stderr)
        backend.stop()
        db.close()
        return 1

    db.set_setting("port", str(port))
    db.set_setting("web_port", str(web_port))
    logs.append("[启动] 端口就绪，FTP 默认处于停止状态")

    print("ftpd 已启动。", flush=True)
    for url in console_urls(console):
        suffix = "（自签证书，浏览器会提示不受信任）" if url.startswith("https") else ""
        print(f"  Web 控制台：{url}{suffix}")
    for url in service.access_urls():
        print(f"  FTP 登录  ：{url}   （先到控制台添加用户并启动 FTP）")
    print(f"  数据库    ：{db_file}")
    if not https_port:
        console_policy = "HTTP（未启用 HTTPS）"
    elif args.shared_port:
        console_policy = "HTTPS（共用端口，明文请求会 301 跳转）"
    else:
        console_policy = "HTTPS（控制台端口只接受 https://）"
    print(f"  控制台策略：{console_policy}")
    print()

    if not db.admin_exists():
        console.setup_token = secrets.token_urlsafe(9)
        print("！还没有设置管理员：第一个打开控制台的人可以设置它。")
        print(f"  初始化口令：{console.setup_token}")
        print("  （从本机访问不需要口令；其它机器必须把这个口令填进初始化页）")
        if args.host not in ("127.0.0.1", "localhost"):
            print(f"！当前监听在 {args.host}，请尽快完成初始化。")
        print()

    print("按 Ctrl+C 退出。", flush=True)

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
