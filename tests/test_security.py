"""登录限流的测试。"""

from __future__ import annotations

import pytest

from ftpd.security import LoginThrottle, attempt_keys


class FakeClock:
    """可手动推进的时钟，避免测试里真的 sleep。"""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def make_throttle(**kwargs):
    clock = FakeClock()
    params = dict(max_attempts=3, window=60.0, lockout=120.0, clock=clock)
    params.update(kwargs)
    return LoginThrottle(**params), clock


# --------------------------------------------------------------------------
# key 构造
# --------------------------------------------------------------------------

def test_attempt_keys_includes_user_and_ip():
    assert attempt_keys("Alice", "10.0.0.1") == ("user:alice", "ip:10.0.0.1")


def test_attempt_keys_is_case_insensitive_for_user():
    assert attempt_keys("ALICE", None) == ("user:alice",)


def test_attempt_keys_without_anything():
    assert attempt_keys("", None) == ("unknown",)


# --------------------------------------------------------------------------
# 基本行为
# --------------------------------------------------------------------------

def test_not_locked_initially():
    throttle, _ = make_throttle()
    assert throttle.lock_remaining(("user:alice",)) == 0.0


def test_locks_after_max_attempts():
    throttle, _ = make_throttle()
    keys = ("user:alice",)
    for _ in range(2):
        throttle.record_failure(keys)
        assert throttle.lock_remaining(keys) == 0.0
    throttle.record_failure(keys)  # 第 3 次触发
    assert throttle.lock_remaining(keys) == pytest.approx(120.0)


def test_lock_expires_automatically():
    throttle, clock = make_throttle()
    keys = ("user:alice",)
    for _ in range(3):
        throttle.record_failure(keys)
    assert throttle.lock_remaining(keys) > 0

    clock.advance(121)
    assert throttle.lock_remaining(keys) == 0.0


def test_success_clears_failures():
    throttle, _ = make_throttle()
    keys = ("user:alice",)
    throttle.record_failure(keys)
    throttle.record_failure(keys)
    throttle.record_success(keys)
    throttle.record_failure(keys)
    assert throttle.lock_remaining(keys) == 0.0  # 计数已归零


def test_old_failures_fall_out_of_the_window():
    throttle, clock = make_throttle(window=60.0)
    keys = ("user:alice",)
    throttle.record_failure(keys)
    throttle.record_failure(keys)
    clock.advance(61)          # 前两次滑出窗口
    throttle.record_failure(keys)
    assert throttle.lock_remaining(keys) == 0.0


def test_ip_key_catches_username_rotation():
    """换着用户名从同一台机器猛试，也要被挡住。"""
    throttle, _ = make_throttle()
    shared_ip = "ip:10.0.0.9"
    for name in ("a", "b", "c"):
        throttle.record_failure((f"user:{name}", shared_ip))
    assert throttle.lock_remaining((shared_ip,)) > 0
    # 那条 IP 上的新用户名同样被挡（因为 key 里有 ip）
    assert throttle.lock_remaining(attempt_keys("brand-new", "10.0.0.9")) > 0


def test_locked_accounts_snapshot():
    throttle, clock = make_throttle()
    for _ in range(3):
        throttle.record_failure(("user:alice",))
    snapshot = throttle.locked_accounts()
    assert "user:alice" in snapshot
    assert snapshot["user:alice"] == pytest.approx(120.0)

    clock.advance(200)
    assert throttle.locked_accounts() == {}


def test_reset_clears_everything():
    throttle, _ = make_throttle()
    for _ in range(3):
        throttle.record_failure(("user:alice",))
    throttle.reset()
    assert throttle.lock_remaining(("user:alice",)) == 0.0
    assert throttle.locked_accounts() == {}


def test_thread_safety_smoke():
    """多线程并发记账不应丢计数。"""
    import threading

    throttle = LoginThrottle(max_attempts=1000, window=60, lockout=60)
    keys = ("user:spam",)

    def worker():
        for _ in range(50):
            throttle.record_failure(keys)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert throttle.lock_remaining(keys) == 0.0  # 还没到 1000 次
