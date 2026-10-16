"""认证器测试：确认 pyftpdlib 的认证确实走 SQLite。"""

from __future__ import annotations

import pytest
from pyftpdlib.exceptions import AuthenticationFailed

from ftpd.auth import READ_PERMS, WRITE_PERMS, DBFTPAuthorizer


def make_authorizer(db, share, *, readonly=True):
    return DBFTPAuthorizer(db, share, readonly=readonly)


def test_has_user(db, share):
    auth = make_authorizer(db, share)
    assert auth.has_user("alice") is False
    db.add_user("alice", "secret123")
    assert auth.has_user("alice") is True
    assert auth.has_user("ALICE") is True  # 大小写不敏感


def test_validate_authentication_success(db, share):
    db.add_user("alice", "secret123")
    auth = make_authorizer(db, share)
    auth.validate_authentication("alice", "secret123", handler=None)  # 不抛异常即通过


def test_validate_authentication_wrong_password(db, share):
    db.add_user("alice", "secret123")
    auth = make_authorizer(db, share)
    with pytest.raises(AuthenticationFailed):
        auth.validate_authentication("alice", "wrong", handler=None)


def test_validate_authentication_unknown_user(db, share):
    auth = make_authorizer(db, share)
    with pytest.raises(AuthenticationFailed):
        auth.validate_authentication("ghost", "whatever", handler=None)


def test_validate_authentication_disabled_user(db, share):
    db.add_user("alice", "secret123")
    db.set_enabled("alice", False)
    auth = make_authorizer(db, share)
    with pytest.raises(AuthenticationFailed):
        auth.validate_authentication("alice", "secret123", handler=None)


def test_error_message_does_not_leak_which_part_failed(db, share):
    db.add_user("alice", "secret123")
    auth = make_authorizer(db, share)

    with pytest.raises(AuthenticationFailed) as wrong_pw:
        auth.validate_authentication("alice", "wrong", handler=None)
    with pytest.raises(AuthenticationFailed) as no_user:
        auth.validate_authentication("ghost", "wrong", handler=None)

    assert str(wrong_pw.value) == str(no_user.value)


def test_successful_login_records_last_login(db, share):
    db.add_user("alice", "secret123")
    assert db.get_user("alice").last_login is None
    make_authorizer(db, share).validate_authentication("alice", "secret123", handler=None)
    assert db.get_user("alice").last_login is not None


def test_home_dir_is_the_shared_dir(db, share):
    db.add_user("alice", "secret123")
    auth = make_authorizer(db, share)
    assert auth.get_home_dir("alice") == str(share.resolve())


def test_readonly_permissions(db, share):
    auth = make_authorizer(db, share, readonly=True)
    assert auth.get_perms("alice") == READ_PERMS
    for perm in READ_PERMS:
        assert auth.has_perm("alice", perm) is True
    for perm in "adfmw":
        assert auth.has_perm("alice", perm) is False


def test_write_permissions(db, share):
    auth = make_authorizer(db, share, readonly=False)
    assert auth.get_perms("alice") == WRITE_PERMS
    for perm in "elradfmw":
        assert auth.has_perm("alice", perm) is True


def test_passwords_are_not_kept_in_the_authorizer(db, share):
    """核心诉求：认证器内存里不存在明文密码表。"""
    db.add_user("alice", "secret123")
    auth = make_authorizer(db, share)
    assert auth.user_table == {}
    assert not any("secret123" in str(v) for v in auth.user_table.values())
