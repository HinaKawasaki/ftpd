"""Web 控制台登录相关的纯逻辑测试。

这里不需要浏览器：登录/初始化都被抽成了普通函数，
页面只负责把结果画出来。
"""

from __future__ import annotations

import pytest

from ftpd.db import UserDB
from ftpd.security import LoginThrottle
from ftpd.webgui import (
    LogBuffer,
    WebConsole,
    attempt_admin_login,
    create_admin,
    is_loopback,
)


@pytest.fixture
def console(tmp_path):
    db = UserDB(tmp_path / "users.db")
    # 这几个函数用不到 service，传 None 即可
    console = WebConsole(db, service=None, logs=LogBuffer())
    console.admin_throttle = LoginThrottle(max_attempts=3, window=60, lockout=120)
    yield console
    db.close()


# --------------------------------------------------------------------------
# 初始化管理员
# --------------------------------------------------------------------------

def test_create_admin_success(console):
    ok, message = create_admin(console, "root", "adminpass1", "adminpass1")
    assert ok is True
    assert console.db.admin_exists() is True
    assert console.db.admin_username() == "root"
    assert console.db.verify_admin("root", "adminpass1") is True


def test_create_admin_password_mismatch(console):
    ok, message = create_admin(console, "root", "adminpass1", "adminpass2")
    assert ok is False
    assert "不一致" in message
    assert console.db.admin_exists() is False


def test_create_admin_rejects_weak_password(console):
    ok, message = create_admin(console, "root", "short", "short")
    assert ok is False
    assert console.db.admin_exists() is False


def test_create_admin_rejects_bad_username(console):
    ok, message = create_admin(console, "bad name", "adminpass1", "adminpass1")
    assert ok is False
    assert console.db.admin_exists() is False


def test_create_admin_defaults_to_admin(console):
    ok, _ = create_admin(console, "", "adminpass1", "adminpass1")
    assert ok is True
    assert console.db.admin_username() == "admin"


# --------------------------------------------------------------------------
# 登录
# --------------------------------------------------------------------------

def test_login_success(console):
    console.db.set_admin("root", "adminpass1")
    ok, message = attempt_admin_login(console, "root", "adminpass1", "10.0.0.1")
    assert ok is True


def test_login_wrong_password(console):
    console.db.set_admin("root", "adminpass1")
    ok, message = attempt_admin_login(console, "root", "nope", "10.0.0.1")
    assert ok is False
    assert "错误" in message


def test_login_wrong_username(console):
    console.db.set_admin("root", "adminpass1")
    ok, _ = attempt_admin_login(console, "someone", "adminpass1", "10.0.0.1")
    assert ok is False


def test_login_before_setup_always_fails(console):
    ok, _ = attempt_admin_login(console, "admin", "whatever", "10.0.0.1")
    assert ok is False


def test_login_locks_after_repeated_failures(console):
    console.db.set_admin("root", "adminpass1")
    ip = "10.0.0.9"
    for _ in range(3):
        ok, _ = attempt_admin_login(console, "root", "wrong", ip)
        assert ok is False

    # 锁上之后正确密码也进不来
    ok, message = attempt_admin_login(console, "root", "adminpass1", ip)
    assert ok is False
    assert "失败次数过多" in message


def test_login_success_resets_failure_counter(console):
    console.db.set_admin("root", "adminpass1")
    ip = "10.0.0.9"
    for _ in range(2):
        attempt_admin_login(console, "root", "wrong", ip)
    ok, _ = attempt_admin_login(console, "root", "adminpass1", ip)
    assert ok is True

    for _ in range(2):
        attempt_admin_login(console, "root", "wrong", ip)
    assert console.admin_throttle.lock_remaining((f"ip:{ip}",)) == 0.0


def test_lock_covers_both_username_and_ip(console):
    console.db.set_admin("root", "adminpass1")
    for _ in range(3):
        attempt_admin_login(console, "root", "wrong", "10.0.0.9")

    # 用户名和来源 IP 两条 key 都被记上了
    locked = console.admin_throttle.locked_accounts()
    assert "user:root" in locked
    assert "ip:10.0.0.9" in locked
    # 没参与攻击的 IP 不受影响
    assert console.admin_throttle.lock_remaining(("ip:10.0.0.10",)) == 0.0
    # 但同一个用户名换台机器也进不来（这正是按用户名计数的目的）
    ok, message = attempt_admin_login(console, "root", "adminpass1", "10.0.0.10")
    assert ok is False
    assert "失败次数过多" in message


# --------------------------------------------------------------------------
# 首次初始化的口令
# --------------------------------------------------------------------------

def test_create_admin_needs_token_from_remote(console):
    console.setup_token = "s3cret-token"
    ok, message = create_admin(
        console, "root", "adminpass1", "adminpass1",
        token="wrong", client_ip="192.168.1.9",
    )
    assert ok is False
    assert "口令" in message
    assert console.db.admin_exists() is False

    ok, _ = create_admin(
        console, "root", "adminpass1", "adminpass1",
        token="s3cret-token", client_ip="192.168.1.9",
    )
    assert ok is True


def test_create_admin_no_token_needed_from_loopback(console):
    """能在本机操作的人本来就有 shell 权限，不必再输口令。"""
    console.setup_token = "s3cret-token"
    ok, _ = create_admin(
        console, "root", "adminpass1", "adminpass1",
        token="", client_ip="127.0.0.1",
    )
    assert ok is True


def test_create_admin_without_token_configured(console):
    console.setup_token = None
    ok, _ = create_admin(
        console, "root", "adminpass1", "adminpass1", client_ip="10.0.0.7"
    )
    assert ok is True


def test_is_loopback():
    assert is_loopback("127.0.0.1") is True
    assert is_loopback("127.0.0.53") is True
    assert is_loopback("::1") is True
    assert is_loopback("192.168.1.5") is False
    assert is_loopback(None) is False
