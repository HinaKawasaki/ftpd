"""登录限流，用来抵挡暴力破解。

FTP 和 Web 控制台都用它。设计上有两点：

* **用户名和来源 IP 都记**。只记用户名的话，攻击者换账号名就绕过了；
  只记 IP 的话，分布式尝试又能绕过。两个都记，任一条触发就锁定。
* **锁定是临时的**，到点自动解除，无需人工干预。
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, Iterable, List, Tuple

#: 窗口内允许的失败次数
DEFAULT_MAX_ATTEMPTS = 5
#: 失败计数的统计窗口（秒）
DEFAULT_WINDOW = 300.0
#: 触发后的锁定时长（秒）
DEFAULT_LOCKOUT = 900.0
#: 每累计这么多次失败就全表清扫一次，避免大量无效 key 长期占内存
SWEEP_EVERY = 256
#: 最多同时跟踪多少个 key，防止被「换用户名刷」撑爆内存
DEFAULT_MAX_TRACKED = 10_000


def attempt_keys(username: str, ip: str | None) -> Tuple[str, ...]:
    """把一次登录尝试映射成要计数的 key。"""
    keys: List[str] = []
    if username:
        keys.append(f"user:{username.strip().lower()}")
    if ip:
        keys.append(f"ip:{ip}")
    if not keys:
        keys.append("unknown")
    return tuple(keys)


class LoginThrottle:
    """按 key 统计失败次数，窗口内超阈值就临时锁定。"""

    def __init__(
        self,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        window: float = DEFAULT_WINDOW,
        lockout: float = DEFAULT_LOCKOUT,
        max_tracked: int = DEFAULT_MAX_TRACKED,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_attempts = max(1, int(max_attempts))
        self.window = float(window)
        self.lockout = float(lockout)
        self.max_tracked = max(16, int(max_tracked))
        self._clock = clock
        self._failures: Dict[str, Deque[float]] = defaultdict(deque)
        self._locked_until: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._since_sweep = 0

    # -- 内部 -------------------------------------------------------------

    def _purge(self, key: str, now: float) -> None:
        queue = self._failures.get(key)
        if not queue:
            return
        while queue and now - queue[0] > self.window:
            queue.popleft()
        if not queue:
            self._failures.pop(key, None)

    # -- 对外 -------------------------------------------------------------

    def lock_remaining(self, keys: Iterable[str]) -> float:
        """返回最长的剩余锁定秒数；没被锁返回 0.0。"""
        now = self._clock()
        remaining = 0.0
        with self._lock:
            for key in keys:
                until = self._locked_until.get(key)
                if until is None:
                    continue
                if until <= now:
                    # 锁已到期，顺手清干净
                    self._locked_until.pop(key, None)
                    self._failures.pop(key, None)
                    continue
                remaining = max(remaining, until - now)
        return remaining

    def record_failure(self, keys: Iterable[str]) -> None:
        now = self._clock()
        with self._lock:
            for key in keys:
                self._purge(key, now)
                queue = self._failures[key]
                queue.append(now)
                if len(queue) >= self.max_attempts:
                    self._locked_until[key] = now + self.lockout
                    queue.clear()
            # 攻击者换着用户名试时会留下大量空 key，定期清一清
            self._since_sweep += 1
            if self._since_sweep >= SWEEP_EVERY:
                self._since_sweep = 0
                self._sweep(now)
            # 真的被刷爆时，先按窗口清理，仍然超限就丢掉最旧的记录
            if len(self._failures) > self.max_tracked:
                self._sweep(now)
            if len(self._failures) > self.max_tracked:
                self._evict_oldest(len(self._failures) - self.max_tracked)

    def _sweep(self, now: float) -> None:
        for key in list(self._failures):
            self._purge(key, now)
            if not self._failures.get(key):
                self._failures.pop(key, None)

    def _evict_oldest(self, count: int) -> None:
        """丢掉最旧的失败记录；已被锁定的 key 不动（那是正在生效的防护）。"""
        candidates = [
            (key, queue[-1] if queue else 0.0)
            for key, queue in self._failures.items()
            if key not in self._locked_until
        ]
        candidates.sort(key=lambda item: item[1])
        for key, _ in candidates[:max(0, count)]:
            self._failures.pop(key, None)

    def record_success(self, keys: Iterable[str]) -> None:
        with self._lock:
            for key in keys:
                self._failures.pop(key, None)
                self._locked_until.pop(key, None)

    def locked_accounts(self) -> Dict[str, float]:
        """当前处于锁定状态的 key 及剩余秒数，供界面展示。"""
        now = self._clock()
        with self._lock:
            expired = [k for k, until in self._locked_until.items() if until <= now]
            for key in expired:
                self._locked_until.pop(key, None)
            return {
                key: round(until - now, 1)
                for key, until in self._locked_until.items()
            }

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()
