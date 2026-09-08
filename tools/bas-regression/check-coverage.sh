#!/usr/bin/env bash
# =============================================================================
# 九章 BAS 规则-测试缺口检查（自研）
#
# 来源：本脚本由本团队自行编写，为 extract.py --check 的便捷封装，
#       未复制任何第三方 WAF 产品的规则、代码或文案。
#
# 用途：扫描 gateway/rules/contrib/CUSTOM_PACK/ 各文件规则 ID 与
#       test/waf/ftw/crs-tests/ 测试目录，报告「有规则无 ftw 测试」的规则 ID。
#       只读规则库，不写任何文件。
#
# 用法：
#   tools/bas-regression/check-coverage.sh           # 报告缺口，退出码恒 0
#   tools/bas-regression/check-coverage.sh --strict  # 存在缺口时退出码 1（CI 用）
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${SCRIPT_DIR}/extract.py" --check "$@"
