"""ftpd —— 带用户认证与图形界面的 FTP 服务器。

模块划分：
    config  —— 路径与默认值
    db      —— SQLite 用户库与密码哈希
    auth    —— 数据库驱动的 pyftpdlib 认证器
    server  —— FTP 服务生命周期（线程、TLS、日志、自动停止）
    gui     —— Kivy 图形界面
"""

__version__ = "0.2.0"
__all__ = ["__version__"]
