#!/usr/bin/env bash
#
# 创建虚拟环境并安装依赖。
#
# 界面用的是 NiceGUI（纯 Python 轮子，支持 Python 3.10 - 3.14），
# 所以直接用系统 Python 就行，不需要额外装解释器。
# 只要版本 >= 3.10 即可。
#
# 用法：
#   ./setup.sh                 安装到 ./.venv
#   VENV_DIR=xyz ./setup.sh    换个目录
#   PYTHON=python3.12 ./setup.sh   指定解释器
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

VENV_DIR="${VENV_DIR:-.venv}"
PYTHON="${PYTHON:-python3}"

# 日志一律走 stderr：脚本里用了命令替换，stdout 要留给返回值
log() { printf '\033[1m==>\033[0m %s\n' "$*" >&2; }

# ---------------------------------------------------------------- 检查解释器
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "错误：找不到 $PYTHON" >&2
    exit 1
fi

version="$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
major="${version%%.*}"
minor="${version##*.}"
if [ "$major" -ne 3 ] || [ "$minor" -lt 10 ]; then
    echo "错误：需要 Python 3.10 及以上，当前是 $version" >&2
    exit 1
fi
log "使用 $PYTHON（$("$PYTHON" -V 2>&1)）"

# ---------------------------------------------------------------- 建环境
rm -rf "$VENV_DIR"
"$PYTHON" -m venv "$VENV_DIR"

# ---------------------------------------------------------------- 装依赖
# pip 镜像偶尔会把连接掐断，所以重试几次
install_with_retry() {
    local attempt
    for attempt in 1 2 3; do
        log "安装依赖（第 $attempt 次尝试）"
        if "$@"; then
            return 0
        fi
        log "第 $attempt 次失败，稍后重试"
        sleep 3
    done
    echo "错误：依赖连续安装失败 3 次，请检查网络后重新执行 ./setup.sh" >&2
    return 1
}

"$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
install_with_retry "$VENV_DIR/bin/python" -m pip install -r requirements-dev.txt

# ---------------------------------------------------------------- 自检
log "自检"
"$VENV_DIR/bin/python" - <<'PY'
from importlib.metadata import PackageNotFoundError, version

for name in ("nicegui", "fastapi", "uvicorn", "pyftpdlib", "pyOpenSSL", "pytest"):
    try:
        print(f"   {name:12s} {version(name)}")
    except PackageNotFoundError:
        print(f"   {name:12s} 未安装")
PY

log "完成。用 ./run.sh 启动，然后浏览器打开 http://<本机IP>:2121/webgui"
