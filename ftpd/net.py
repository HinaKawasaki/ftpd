"""网络小工具。

``local_ipv4_addresses`` 被三处用到：给用户拼访问地址、生成证书的 SAN、
以及日志里展示本机 IP，所以单独放一个模块，避免循环导入。
"""

from __future__ import annotations

import socket
from typing import List


def local_ipv4_addresses() -> List[str]:
    """尽力列出本机的局域网 IPv4 地址（不含回环）。"""
    addrs: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    # 补一个「出站路由」地址，通常就是真实网卡地址
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            addrs.add(sock.getsockname()[0])
    except OSError:
        pass
    return sorted(a for a in addrs if not a.startswith("127."))
