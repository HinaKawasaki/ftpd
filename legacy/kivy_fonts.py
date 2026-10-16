"""中文字体注册。

Kivy 默认的 Roboto 字体不含 CJK 字形，中文会渲染成一个个方块。
这里在系统里找一个可用的中文字体，把它注册成 Kivy 的默认字体；
找不到就保持原样（纯英文界面仍然可用，只是中文会显示为方块）。

也可以用环境变量 ``FTPD_FONT`` 指定自己的字体文件。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)

#: 按优先级排列的候选中文字体，覆盖 Linux / macOS / Windows
CJK_FONT_CANDIDATES: List[str] = [
    # Linux
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJKsc-Regular.otf",
    "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
    "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
    "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
    "/usr/share/fonts/truetype/arphic/uming.ttc",
    # macOS
    "/System/Library/Fonts/PingFang.ttc",
    "/System/Library/Fonts/Hiragino Sans GB.ttc",
    # Windows
    "C:/Windows/Fonts/msyh.ttc",
    "C:/Windows/Fonts/simhei.ttf",
]

CJK_BOLD_CANDIDATES: List[str] = [
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc",
    "C:/Windows/Fonts/msyhbd.ttc",
]


def find_cjk_font() -> Optional[str]:
    """返回第一个存在的中文字体路径。"""
    custom = os.environ.get("FTPD_FONT")
    if custom and Path(custom).expanduser().is_file():
        return str(Path(custom).expanduser())
    for candidate in CJK_FONT_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def register_cjk_font() -> Optional[str]:
    """把中文字体注册为 Kivy 默认字体，返回实际使用的路径。

    失败时只记一条警告，不影响程序继续运行。
    """
    try:
        from kivy.core.text import DEFAULT_FONT, LabelBase
    except Exception:  # pragma: no cover - Kivy 不可用时直接跳过
        return None

    path = find_cjk_font()
    if not path:
        logger.warning("没有找到可用的中文字体，界面里的中文可能显示为方块")
        return None

    bold = next((p for p in CJK_BOLD_CANDIDATES if Path(p).is_file()), None)
    try:
        if bold:
            LabelBase.register(DEFAULT_FONT, fn_regular=path, fn_bold=bold)
        else:
            LabelBase.register(DEFAULT_FONT, fn_regular=path)
    except Exception as exc:  # pragma: no cover - 字体文件损坏之类
        logger.warning("注册中文字体失败：%s", exc)
        return None

    logger.info("已注册中文字体：%s", path)
    return path
