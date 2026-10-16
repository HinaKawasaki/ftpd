"""用户库与密码哈希的测试。"""

from __future__ import annotations

import pytest

from ftpd.db import (
    ALGORITHM,
    DEFAULT_ITERATIONS,
    DuplicateUser,
    UserNotFound,
    ValidationError,
    UserDB,
    hash_password,
    needs_rehash,
    validate_password,
    validate_username,
    verify_password,
)


# --------------------------------------------------------------------------
# 密码哈希
# --------------------------------------------------------------------------

def test_hash_is_salted_and_not_plaintext():
    stored = hash_password("hunter2")
    assert "hunter2" not in stored
    assert stored.startswith(f"{ALGORITHM}${DEFAULT_ITERATIONS}$")
    assert stored.count("$") == 3


def test_same_password_gets_different_hash():
    assert hash_password("hunter2") != hash_password("hunter2")


def test_verify_roundtrip():
    stored = hash_password("hunter2")
    assert verify_password(stored, "hunter2") is True
    assert verify_password(stored, "hunter3") is False


def test_verify_rejects_garbage():
    for bad in ["", "not-a-hash", "pbkdf2_sha256$abc$x$y", "md5$1$a$b", None]:
        assert verify_password(bad, "hunter2") is False


def test_verify_survives_short_salt():
    # 手工构造一个合法但很短的哈希，确认不会抛异常
    stored = hash_password("pw123456", salt=b"0123456789abcdef")
    assert verify_password(stored, "pw123456") is True


def test_needs_rehash_detects_weak_iterations():
    weak = hash_password("pw123456", iterations=1000)
    assert needs_rehash(weak) is True
    strong = hash_password("pw123456")
    assert needs_rehash(strong) is False
    assert needs_rehash("garbage") is True


# --------------------------------------------------------------------------
# 输入校验
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["alice", "Bob_2", "a.b-c", "A1"])
def test_validate_username_ok(name):
    assert validate_username(name) == name


@pytest.mark.parametrize(
    "name", ["", "-bad", ".bad", "has space", "中文", "a" * 33, "b@d"]
)
def test_validate_username_rejects(name):
    with pytest.raises(ValidationError):
        validate_username(name)


def test_validate_username_strips():
    assert validate_username("  alice  ") == "alice"


@pytest.mark.parametrize("password", ["", "12345"])
def test_validate_password_rejects(password):
    with pytest.raises(ValidationError):
        validate_password(password)


def test_validate_password_ok():
    assert validate_password("123456") == "123456"


# --------------------------------------------------------------------------
# 用户增删改查
# --------------------------------------------------------------------------

def test_add_and_get_user(db: UserDB):
    user = db.add_user("alice", "secret123")
    assert user.username == "alice"
    assert user.enabled is True
    assert user.last_login is None
    assert user.status_text == "启用"
    assert user.last_login_text == "从未登录"

    fetched = db.get_user("alice")
    assert fetched is not None and fetched.id == user.id


def test_usernames_are_case_insensitive(db: UserDB):
    db.add_user("alice", "secret123")
    with pytest.raises(DuplicateUser):
        db.add_user("ALICE", "secret456")
    assert db.get_user("Alice") is not None


def test_add_rejects_bad_input(db: UserDB):
    with pytest.raises(ValidationError):
        db.add_user("bad name", "secret123")
    with pytest.raises(ValidationError):
        db.add_user("bob", "short")
    assert db.count_users() == 0


def test_delete_user(db: UserDB):
    db.add_user("alice", "secret123")
    db.delete_user("alice")
    assert db.get_user("alice") is None
    with pytest.raises(UserNotFound):
        db.delete_user("alice")


def test_set_password(db: UserDB):
    db.add_user("alice", "secret123")
    db.set_password("alice", "newsecret")
    assert db.verify("alice", "newsecret") is True
    assert db.verify("alice", "secret123") is False
    with pytest.raises(UserNotFound):
        db.set_password("nobody", "secret123")


def test_set_enabled_blocks_login(db: UserDB):
    db.add_user("alice", "secret123")
    db.set_enabled("alice", False)
    assert db.verify("alice", "secret123") is False
    assert db.get_user("alice").enabled is False
    db.set_enabled("alice", True)
    assert db.verify("alice", "secret123") is True
    with pytest.raises(UserNotFound):
        db.set_enabled("nobody", False)


def test_verify_unknown_user(db: UserDB):
    assert db.verify("ghost", "whatever") is False


def test_verify_is_not_plaintext_comparison(db: UserDB):
    db.add_user("alice", "secret123")
    # 库里的东西不可能是明文
    row = db._conn.execute("SELECT password_hash FROM users").fetchone()
    assert "secret123" not in row["password_hash"]


def test_touch_login(db: UserDB):
    db.add_user("alice", "secret123")
    assert db.get_user("alice").last_login is None
    db.touch_login("alice")
    assert db.get_user("alice").last_login is not None


def test_list_users_sorted(db: UserDB):
    for name in ["carol", "alice", "bob"]:
        db.add_user(name, "secret123")
    assert [u.username for u in db.list_users()] == ["alice", "bob", "carol"]
    assert db.count_users() == 3


# --------------------------------------------------------------------------
# 设置
# --------------------------------------------------------------------------

def test_settings_roundtrip(db: UserDB):
    assert db.get_setting("port") is None
    assert db.get_setting("port", "2121") == "2121"
    db.set_setting("port", "2121")
    assert db.get_setting("port") == "2121"
    db.set_setting("port", "2122")  # 幂等覆盖
    assert db.get_setting("port") == "2122"
    assert db.all_settings() == {"port": "2122"}


def test_database_persists_across_reopen(tmp_path):
    path = tmp_path / "users.db"
    with UserDB(path) as first:
        first.add_user("alice", "secret123")
    with UserDB(path) as second:
        assert second.verify("alice", "secret123") is True
