"""数据库驱动的 pyftpdlib 认证器。

``DummyAuthorizer`` 本身就是设计来被继承的，其中
``validate_authentication`` 是自定义密码校验的钩子——我们在这里
把校验转交给 SQLite，而不是让 pyftpdlib 在内存里存明文密码。

权限模型（按需求）：只做登录，所有账号共享同一个目录、同一套权限。

另外接入 :class:`ftpd.security.LoginThrottle`：同一用户名或同一来源 IP
在窗口内失败次数过多时，临时拒绝登录。
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.exceptions import AuthenticationFailed

from .db import UserDB
from .security import LoginThrottle, attempt_keys

#: 只读：进目录(e) / 列目录(l) / 下载(r)
READ_PERMS = "elr"
#: 读写：再加上传(a) / 删除(d) / 改名(f) / 建目录(m) / 写(w) / 改时间(T) / 移动(M)
WRITE_PERMS = "elradfmwMT"


class DBFTPAuthorizer(DummyAuthorizer):
    """以 SQLite 用户表为唯一凭据来源的认证器。"""

    def __init__(
        self,
        db: UserDB,
        shared_dir: Union[str, Path],
        *,
        readonly: bool = True,
        throttle: Optional[LoginThrottle] = None,
    ) -> None:
        super().__init__()
        self.db = db
        self.shared_dir = str(Path(shared_dir).expanduser().resolve())
        self.readonly = readonly
        self.throttle = throttle

    # -- 权限 -------------------------------------------------------------

    @property
    def perms(self) -> str:
        return READ_PERMS if self.readonly else WRITE_PERMS

    def get_perms(self, username: str) -> str:
        return self.perms

    def has_perm(self, username: str, perm: str, path: Optional[str] = None) -> bool:
        # 所有用户权限一致，且共享目录是唯一的根，无需按路径细分
        return perm in self.perms

    # -- 身份 -------------------------------------------------------------

    def has_user(self, username: str) -> bool:
        return self.db.get_user(username) is not None

    def validate_authentication(self, username: str, password: str, handler) -> None:
        client_ip = getattr(handler, "remote_ip", None) if handler is not None else None
        keys = attempt_keys(username, client_ip)

        if self.throttle is not None:
            remaining = self.throttle.lock_remaining(keys)
            if remaining > 0:
                # 这里刻意说得明确：被锁的人需要知道还要等多久
                raise AuthenticationFailed(
                    "Too many failed attempts. "
                    f"Try again in {int(remaining) + 1} seconds."
                )

        user = self.db.get_user(username)
        # 不区分「用户不存在」和「密码错误」，避免用户名枚举
        if user is None or not user.enabled or not self.db.verify(username, password):
            if self.throttle is not None:
                self.throttle.record_failure(keys)
            raise AuthenticationFailed("Authentication failed.")

        if self.throttle is not None:
            self.throttle.record_success(keys)
        self.db.touch_login(username)

    def get_home_dir(self, username: str) -> str:
        return self.shared_dir

    # -- 问候语 -----------------------------------------------------------

    def get_msg_login(self, username: str) -> str:
        return "Login successful."

    def get_msg_quit(self, username: str) -> str:
        return "Goodbye."
