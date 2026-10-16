"""浏览器端到端自检（开发用，不属于项目依赖）。

为什么需要它：``build_page`` 只在真实浏览器里执行，pytest 是碰不到的。
本项目已经两次出现「pytest 全绿、但打开控制台是 500」的情况，
所以留一个用真实浏览器走完整流程的脚本。

依赖 Playwright（不在 requirements 里）：

    pip install playwright
    python tools/browser_check.py --port 21310 --chrome /opt/google/chrome/google-chrome

它会：初始化管理员 → 登录 → 界面加用户 → 启动 FTP → 用 FTP 客户端验证 →
改端口 → 确认页面自动跳转且 FTP 仍在运行。
"""

from __future__ import annotations

import argparse
import ftplib
import io
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeout
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover
    print("需要 Playwright：pip install playwright", file=sys.stderr)
    raise SystemExit(1)

ADMIN_USER, ADMIN_PASS = "root", "adminpass1"
FTP_USER, FTP_PASS = "alice", "secret123"


def open_and_wait(
    page, url: str, selector: str, *, attempts: int = 5, timeout: int = 15_000
) -> None:
    """打开页面并等到指定内容出现，失败就整页重来。

    NiceGUI 的内容是靠 WebSocket 推下来的，而这台机器的回环转发层偶发抽风
    （表现为页面空白，或者 ERR_INVALID_HTTP_RESPONSE）。多点重试能盖过去，
    这是环境的问题，不是应用的问题 —— 用 curl 连打 40 次都是 200。
    """
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            page.wait_for_selector(selector, timeout=timeout)
            return
        except (PlaywrightTimeout, PlaywrightError) as exc:
            last_error = exc
            print(f"   （第 {attempt}/{attempts} 次没打开：{type(exc).__name__}，重试）")
            time.sleep(1)
    assert last_error is not None
    raise last_error


def wait_for(page, selector: str, *, attempts: int = 4, timeout: int = 15_000) -> None:
    """等指定内容出现；没等到就刷新重试。失败时把现场打出来。"""
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            page.wait_for_selector(selector, timeout=timeout)
            return
        except (PlaywrightTimeout, PlaywrightError) as exc:
            last_error = exc
            print(f"   （第 {attempt}/{attempts} 次没等到 {selector!r}，刷新重试）")
            try:
                page.reload(wait_until="domcontentloaded", timeout=30_000)
            except PlaywrightError:
                pass
            time.sleep(1)
    try:
        print("   现场 URL:", page.url)
        print("   现场内容:", page.inner_text("body")[:200].replace("\n", " | "))
    except Exception:
        pass
    assert last_error is not None
    raise last_error


def ftp_roundtrip(port: int, expect_file: str) -> str:
    ftp = ftplib.FTP()
    ftp.connect("127.0.0.1", port, timeout=10)
    try:
        ftp.login(FTP_USER, FTP_PASS)
        names = ftp.nlst()
        assert expect_file in names, f"{expect_file} 不在 {names}"
        buffer = io.BytesIO()
        ftp.retrbinary(f"RETR {expect_file}", buffer.write)
        return buffer.getvalue().decode()
    finally:
        ftp.quit()


def run(port: int, new_port: int, chrome: str, keep_shots: Path | None) -> int:
    # 控制台默认强制 HTTPS，而且是自签证书，所以要忽略证书错误
    base = f"https://127.0.0.1:{port}/webgui/"
    share = Path(tempfile.mkdtemp(prefix="ftpd-browser-"))
    (share / "readme.txt").write_text("hello ftp\n", encoding="utf-8")

    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=chrome, headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        context = browser.new_context(
            ignore_https_errors=True, viewport={"width": 1400, "height": 950}
        )
        page = context.new_page()

        print("1) 首次访问 → 初始化管理员")
        open_and_wait(page, base, "text=第一次使用")
        inputs = page.locator("input")
        inputs.nth(0).fill(ADMIN_USER)
        inputs.nth(1).fill(ADMIN_PASS)
        inputs.nth(2).fill(ADMIN_PASS)
        # 第 4 个输入框是初始化口令；从本机访问不需要填
        # 程序化填值后要留点时间让 NiceGUI 把值同步到服务端，否则点击时服务端还是旧值
        page.wait_for_timeout(800)
        page.get_by_role("button", name="创建并进入").click()
        page.wait_for_selector("text=添加用户", timeout=30_000)
        print("   进入控制台 ✅")

        print("2) 界面添加 FTP 用户")
        page.get_by_label("用户名", exact=True).fill(FTP_USER)
        page.get_by_label("密码", exact=True).fill(FTP_PASS)
        page.wait_for_timeout(800)
        page.get_by_role("button", name="添加用户").click()
        wait_for(page, f"text={FTP_USER}")
        print("   用户已添加 ✅")

        print("3) 启动 FTP 并验证")
        page.locator("div.q-tab:has-text('服务')").click()
        wait_for(page, "text=共享端口")
        page.get_by_label("共享目录（FTP 用户看到的根目录）").fill(str(share))
        page.wait_for_timeout(800)
        page.get_by_role("button", name="启动 FTP").click()
        wait_for(page, "text=FTP 服务：运行中")
        time.sleep(1)
        assert ftp_roundtrip(port, "readme.txt").strip() == "hello ftp"
        print(f"   端口 {port} 上 FTP 可用 ✅")

        print(f"4) 切换到端口 {new_port}，页面应自动跳转")
        page.get_by_label("共享端口").fill(str(new_port))
        page.wait_for_timeout(800)
        page.get_by_role("button", name="应用端口").click()
        page.wait_for_timeout(500)
        page.get_by_role("button", name="切换").click()
        page.wait_for_url(f"**{new_port}**", timeout=45_000)
        wait_for(page, "text=添加用户")
        print(f"   已跳到 {new_port} ✅")

        if keep_shots:
            keep_shots.mkdir(parents=True, exist_ok=True)
            page.locator("div.q-tab:has-text('服务')").click()
            # 等面板真的切换过去再截图，否则拍到的还是上一个标签页
            page.wait_for_selector("text=运行状态", timeout=15_000)
            page.wait_for_timeout(600)
            page.screenshot(path=str(keep_shots / "service.png"))
            print(f"   截图 → {keep_shots / 'service.png'}")

        browser.close()

    print("5) 换端口后 FTP 应仍在运行")
    assert ftp_roundtrip(new_port, "readme.txt").strip() == "hello ftp"
    print(f"   端口 {new_port} 上 FTP 仍可用 ✅")

    print("\n全部通过")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="用真实浏览器自检 Web 控制台")
    parser.add_argument("--port", type=int, default=21310)
    parser.add_argument("--new-port", type=int, default=None)
    parser.add_argument("--chrome", default="/opt/google/chrome/google-chrome")
    parser.add_argument("--screenshots", default=None, help="可选：截图输出目录")
    args = parser.parse_args()
    shots = Path(args.screenshots) if args.screenshots else None
    return run(args.port, args.new_port or args.port + 1, args.chrome, shots)


if __name__ == "__main__":
    raise SystemExit(main())
