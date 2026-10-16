#!/usr/bin/env bash
#
# 启动 FTP 服务 + Web 控制台（两者共用一个端口）。
# 参数原样传给 ftpd，比如：
#   ./run.sh --port 2121
#   ./run.sh --db /path/to/users.db
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

if [ ! -x .venv/bin/python ]; then
    echo "还没有安装运行环境，请先执行： ./setup.sh" >&2
    exit 1
fi

exec .venv/bin/python -m ftpd "$@"
