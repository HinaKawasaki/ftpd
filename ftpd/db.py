"""SQLite 用户库与密码哈希。

密码一律以 PBKDF2-HMAC-SHA256 加盐哈希保存，绝不落明文。
存储格式：

    pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>

这个格式自带算法与迭代次数，日后升级迭代次数或换算法时，
老密码仍然可以校验，并可在用户下次登录时顺手重新哈希。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union

ALGORITHM = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 200_000
SALT_BYTES = 16
MIN_PASSWORD_LENGTH = 6

USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")


class ValidationError(ValueError):
    """用户名或密码不满足规则。"""


class DuplicateUser(ValidationError):
    """用户名已存在。"""


class UserNotFound(ValidationError):
    """用户名不存在。"""


# --------------------------------------------------------------------------
# 密码哈希
# --------------------------------------------------------------------------

def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def hash_password(
    password: str,
    *,
    iterations: int = DEFAULT_ITERATIONS,
    salt: Optional[bytes] = None,
) -> str:
    """把明文密码转成可入库的哈希字符串。"""
    if not isinstance(password, str) or not password:
        raise ValidationError("密码不能为空")
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}${iterations}${_b64e(salt)}${_b64e(digest)}"


def verify_password(stored: str, password: str) -> bool:
    """常量时间比对的密码校验；格式不合法一律返回 False。"""
    if not stored or not password:
        return False
    try:
        algo, iterations_s, salt_s, hash_s = stored.split("$")
        iterations = int(iterations_s)
        salt = _b64d(salt_s)
        expected = _b64d(hash_s)
    except (ValueError, TypeError, base64.binascii.Error):
        return False
    if algo != ALGORITHM or iterations <= 0:
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(digest, expected)


def needs_rehash(stored: str, *, iterations: int = DEFAULT_ITERATIONS) -> bool:
    """判断已有哈希是否该按当前参数重算。"""
    try:
        algo, iterations_s, _, _ = stored.split("$")
    except (ValueError, AttributeError):
        return True
    return algo != ALGORITHM or int(iterations_s) < iterations


# --------------------------------------------------------------------------
# 输入校验
# --------------------------------------------------------------------------

def validate_username(username: str) -> str:
    if not isinstance(username, str):
        raise ValidationError("用户名必须是字符串")
    username = username.strip()
    if not USERNAME_RE.match(username):
        raise ValidationError(
            "用户名只能包含字母、数字、点、下划线和连字符，"
            "长度 1-32，且必须以字母或数字开头"
        )
    return username


def validate_password(password: str) -> str:
    if not isinstance(password, str):
        raise ValidationError("密码必须是字符串")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"密码至少需要 {MIN_PASSWORD_LENGTH} 个字符")
    return password


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# 数据模型
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class User:
    id: int
    username: str
    enabled: bool
    created_at: str
    updated_at: str
    last_login: Optional[str]

    @property
    def status_text(self) -> str:
        return "启用" if self.enabled else "禁用"

    @property
    def last_login_text(self) -> str:
        return self.last_login or "从未登录"


# --------------------------------------------------------------------------
# 用户库
# --------------------------------------------------------------------------

class UserDB:
    """线程安全的 SQLite 用户库。

    GUI 主线程和 FTP 服务线程会并发访问，所以：
      * 连接以 ``check_same_thread=False`` 打开；
      * 所有读写都用同一把可重入锁串行化。
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    # -- 基础设施 ---------------------------------------------------------

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            with self._conn:
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        id            INTEGER PRIMARY KEY AUTOINCREMENT,
                        username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
                        password_hash TEXT NOT NULL,
                        enabled       INTEGER NOT NULL DEFAULT 1,
                        created_at    TEXT NOT NULL,
                        updated_at    TEXT NOT NULL,
                        last_login    TEXT
                    )
                    """
                )
                self._conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settings (
                        key   TEXT PRIMARY KEY,
                        value TEXT
                    )
                    """
                )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "UserDB":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> User:
        return User(
            id=row["id"],
            username=row["username"],
            enabled=bool(row["enabled"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            last_login=row["last_login"],
        )

    # -- 用户增删改查 -----------------------------------------------------

    def add_user(self, username: str, password: str, *, enabled: bool = True) -> User:
        username = validate_username(username)
        validate_password(password)
        now = _now()
        stored = hash_password(password)
        with self._lock:
            try:
                with self._conn:
                    cur = self._conn.execute(
                        "INSERT INTO users (username, password_hash, enabled,"
                        " created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (username, stored, int(enabled), now, now),
                    )
            except sqlite3.IntegrityError as exc:
                raise DuplicateUser(f"用户 {username!r} 已存在") from exc
            row = self._conn.execute(
                "SELECT * FROM users WHERE id = ?", (cur.lastrowid,)
            ).fetchone()
        return self._row_to_user(row)

    def delete_user(self, username: str) -> None:
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "DELETE FROM users WHERE username = ? COLLATE NOCASE", (username,)
                )
            if cur.rowcount == 0:
                raise UserNotFound(f"用户 {username!r} 不存在")

    def set_password(self, username: str, password: str) -> None:
        validate_password(password)
        stored = hash_password(password)
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "UPDATE users SET password_hash = ?, updated_at = ?"
                    " WHERE username = ? COLLATE NOCASE",
                    (stored, _now(), username),
                )
            if cur.rowcount == 0:
                raise UserNotFound(f"用户 {username!r} 不存在")

    def set_enabled(self, username: str, enabled: bool) -> None:
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "UPDATE users SET enabled = ?, updated_at = ?"
                    " WHERE username = ? COLLATE NOCASE",
                    (int(enabled), _now(), username),
                )
            if cur.rowcount == 0:
                raise UserNotFound(f"用户 {username!r} 不存在")

    def get_user(self, username: str) -> Optional[User]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def list_users(self) -> List[User]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users ORDER BY username COLLATE NOCASE"
            ).fetchall()
        return [self._row_to_user(r) for r in rows]

    def count_users(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    # -- 认证 -------------------------------------------------------------

    def verify(self, username: str, password: str) -> bool:
        """校验用户名密码。用户不存在、被禁用或密码错误一律 False。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT password_hash, enabled FROM users"
                " WHERE username = ? COLLATE NOCASE",
                (username,),
            ).fetchone()
        if row is None or not row["enabled"]:
            return False
        return verify_password(row["password_hash"], password)

    def touch_login(self, username: str) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "UPDATE users SET last_login = ? WHERE username = ? COLLATE NOCASE",
                    (_now(), username),
                )

    # -- 设置 -------------------------------------------------------------

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self._lock:
            with self._conn:
                self._conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)"
                    " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, str(value)),
                )

    def all_settings(self) -> dict:
        with self._lock:
            rows = self._conn.execute("SELECT key, value FROM settings").fetchall()
        return {r["key"]: r["value"] for r in rows}
