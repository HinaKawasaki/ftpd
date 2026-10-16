"""网络小工具。

``local_ipv4_addresses`` 被三处用到：给用户拼访问地址、生成证书的 SAN、
以及日志里展示本机 IP，所以单独放一个模块，避免循环导入。

另外这里放了一个「读内核 RTT 估计」的函数，用来给协议判定定一个自适应的等待上限。
"""

from __future__ import annotations

import socket
import struct
from typing import List, Optional

#: Linux 的 TCP_INFO；socket.TCP_INFO 不一定存在，兜底用字面量
TCP_INFO = getattr(socket, "TCP_INFO", 11)

#: struct tcp_info 里 tcpi_rtt 的字节偏移（头部 8 字节 + 15 个 u32）
#:   0  state, 1 ca_state, 2 retransmits, 3 probes, 4 backoff, 5 options,
#:   6  snd_wscale/rcv_wscale, 7 delivery_rate_app_limited,
#:   8 rto, 12 ato, 16 snd_mss, 20 rcv_mss, 24 unacked, 28 sacked, 32 lost,
#:   36 retrans, 40 fackets, 44 last_data_sent, 48 last_ack_sent,
#:   52 last_data_recv, 56 last_ack_recv, 60 pmtu, 64 rcv_ssthresh, 68 rtt
_TCP_INFO_RTT_OFFSET = 68
_TCP_INFO_MIN_SIZE = _TCP_INFO_RTT_OFFSET + 4


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


def connection_rtt(sock: socket.socket) -> Optional[float]:
    """读内核给这条连接估的 RTT（秒）。读不到返回 None。

    这个值在手握完（``accept()`` 返回）时就有了，正好用来决定
    「等多长时间才把沉默的连接当成 FTP」。
    """
    try:
        raw = sock.getsockopt(socket.IPPROTO_TCP, TCP_INFO, 128)
    except (OSError, AttributeError, ValueError):
        return None
    if len(raw) < _TCP_INFO_MIN_SIZE:
        return None
    microseconds = struct.unpack_from("<I", raw, _TCP_INFO_RTT_OFFSET)[0]
    if microseconds <= 0:
        return None
    return microseconds / 1_000_000.0


def adaptive_classify_grace(
    sock: socket.socket,
    *,
    ceiling: float,
    factor: float = 3.0,
    margin: float = 0.005,
    floor: float = 0.008,
) -> float:
    """按连接的实际 RTT 算一个等待上限。

    为什么要自适应：需要等的只是「HTTP 客户端把请求发出来」这件事，
    而它本质上是一个网络往返 —— 局域网零点几毫秒，公网可能上百毫秒。
    写死一个大值等于拿公网的最坏情况惩罚所有人。

    HTTP 请求通常在 ``accept()`` 返回前后就到了（约 1 个 RTT 内），
    所以取 ``factor × RTT + margin`` 已经足够，再用 floor / ceiling 兜住两端。
    读不到 RTT 时退回 ``ceiling``。
    """
    rtt = connection_rtt(sock)
    if rtt is None:
        return ceiling
    return max(floor, min(ceiling, factor * rtt + margin))
