#!/usr/bin/env bash
# license-audit.sh —— 许可证合规审计：
#   1. licenses/ 归档完整性（每个组件目录必须有许可证文件）
#   2. 归档许可证文本禁止出现 GPL/AGPL/SSPL 字样（AGENTS.md 红线）
#   3. SBOM 组件许可证必须在允许清单内（NOASSERTION 计警告，需人工复核）
#   4. 必备归档组件逐一核对（与 docs/DEPENDENCIES.md / THIRD_PARTY_NOTICES.md 一致）
# 退出码：0=通过 1=失败 2=用法错误
set -euo pipefail

usage() {
  cat <<'EOF'
用法: license-audit.sh [选项]

许可证合规审计（CI 可重复执行）：
  - licenses/ 归档完整性与禁用许可证（GPL/AGPL/SSPL）扫描
  - docs/SBOM.spdx.json / docs/SBOM.cyclonedx.json 许可证清单审计
  - 必备组件归档核对

选项:
  -h, --help   显示帮助

退出码: 0=通过 1=失败 2=用法错误
EOF
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }
[[ $# -gt 0 ]] && { echo "未知参数: $1" >&2; usage; exit 2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LICENSES_DIR="$REPO_ROOT/licenses"
DOCS_DIR="$REPO_ROOT/docs"

FAIL=0
WARN=0
err()  { echo "[FAIL] $*" >&2; FAIL=1; }
warn() { echo "[WARN] $*"; WARN=1; }
ok()   { echo "[ OK ] $*"; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "缺少必需命令: $1" >&2; exit 1; }; }
require_cmd jq

# ---- 1. 归档完整性 ----
echo "== 1. licenses/ 归档完整性 =="
shopt -s nullglob
for dir in "$LICENSES_DIR"/*/; do
  comp="$(basename "$dir")"
  files=("$dir"*)
  if [[ ${#files[@]} -eq 0 ]]; then
    err "licenses/$comp/ 目录为空"
    continue
  fi
  ok "licenses/$comp/ 已归档（${#files[@]} 个文件）"
done

# ---- 2. 禁用许可证扫描（归档文本） ----
echo "== 2. 禁用许可证扫描 =="
if grep -rIinE 'GNU (AFFERO|GENERAL PUBLIC LICENSE)|Server Side Public License|SSPL|RSALv2|Elastic License v2' \
    "$LICENSES_DIR" 2>/dev/null; then
  err "licenses/ 归档中发现 GPL/AGPL/SSPL 等禁用许可证字样（见上）"
else
  ok "未发现 GPL/AGPL/SSPL 字样"
fi

# ---- 3. SBOM 许可证清单审计 ----
echo "== 3. SBOM 许可证审计 =="
SPDX="$DOCS_DIR/SBOM.spdx.json"
if [[ ! -s "$SPDX" ]]; then
  err "docs/SBOM.spdx.json 不存在（请先运行 scripts/generate-sbom.sh）"
else
  jq empty "$SPDX" || err "docs/SBOM.spdx.json 非法 JSON"
  # 禁止的许可证标识
  forbidden="$(jq -r '.packages[].licenseConcluded' "$SPDX" | grep -Ei 'GPL|AGPL|SSPL|RSAL|Elastic' || true)"
  if [[ -n "$forbidden" ]]; then
    err "SBOM 中发现禁用许可证: $(printf '%s' "$forbidden" | sort -u | tr '\n' ' ')"
  fi
  # 允许的许可证标识（宽松许可证 + NOASSERTION）
  allowed_re='^(Apache-2\.0|MIT|BSD-2-Clause|BSD-3-Clause|ISC|PostgreSQL|OFL-1\.1|curl|CC0-1\.0|NOASSERTION)$'
  unknown="$(jq -r '.packages[].licenseConcluded' "$SPDX" | sort -u | grep -Ev "$allowed_re" || true)"
  if [[ -n "$unknown" ]]; then
    err "SBOM 中发现未在允许清单的许可证: $(printf '%s' "$unknown" | tr '\n' ' ')"
  fi
  noassert_count="$(jq '[.packages[] | select(.licenseConcluded == "NOASSERTION")] | length' "$SPDX")"
  if (( noassert_count > 0 )); then
    warn "SBOM 中 $noassert_count 个组件许可证为 NOASSERTION（多为间接依赖，需人工复核）"
  fi
  total="$(jq '.packages | length' "$SPDX")"
  [[ "$FAIL" -eq 0 ]] && ok "SBOM 许可证审计通过（组件 $total 个）"
fi

# ---- 4. 必备归档组件核对 ----
echo "== 4. 必备归档组件核对 =="
required=(caddy coraza coraza-caddy owasp-crs xcaddy go-ftw curl postgresql valkey valkey-go noto-fonts gofpdf echarts)
for comp in "${required[@]}"; do
  if [[ -d "$LICENSES_DIR/$comp" ]] && find "$LICENSES_DIR/$comp" -type f -print -quit | grep -q .; then
    ok "$comp 已归档"
  else
    err "缺少许可证归档: licenses/$comp/"
  fi
done

echo
if [[ "$FAIL" -ne 0 ]]; then
  echo "许可证审计未通过" >&2
  exit 1
fi
[[ "$WARN" -ne 0 ]] && echo "许可证审计通过（存在警告项，见上）" || echo "许可证审计全部通过"
exit 0
