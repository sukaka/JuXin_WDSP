#!/usr/bin/env bash
# generate-sbom.sh —— 生成 docs/SBOM.spdx.json（SPDX 2.3）与 docs/SBOM.cyclonedx.json（CycloneDX 1.5）。
# 数据来源：
#   Go 依赖   server/go.mod + gateway/modules/jiuzhang_guard/go.mod（go list -m -json all）
#   Node 依赖 web/package.json 顶层 dependencies（npm ls --depth=0 --json，失败回退 package.json）
#   核心组件  与 docs/DEPENDENCIES.md 一致的固化清单（Caddy/Coraza/CRS/PostgreSQL/Valkey/xcaddy 等，
#             含 APM 数据面镜像 ClickHouse/otel-collector-contrib）
# 输出确定性：组件按名称排序；时间戳取 git 最近提交时间（无 git 时用固定值）。
# 退出码：0=成功 1=失败 2=用法错误
set -euo pipefail

usage() {
  cat <<'EOF'
用法: generate-sbom.sh [选项]

生成软件物料清单（SBOM）：
  docs/SBOM.spdx.json      SPDX 2.3 格式
  docs/SBOM.cyclonedx.json CycloneDX 1.5 格式

选项:
  -o, --output-dir DIR   输出目录（默认 <仓库>/docs）
      --offline          跳过 go list / npm ls（仅用 go.mod / package.json 静态解析）
  -h, --help             显示帮助

退出码: 0=成功 1=失败 2=用法错误
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/docs"
OFFLINE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output-dir) OUT_DIR="$2"; shift 2 ;;
    --offline)       OFFLINE=true; shift ;;
    -h|--help)       usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage; exit 2 ;;
  esac
done

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "缺少必需命令: $1" >&2; exit 1; }; }
require_cmd jq
mkdir -p "$OUT_DIR"

# ---- 许可证推断表（宽松许可证；未知一律 NOASSERTION，由 license-audit.sh 审计） ----
license_of() { # license_of NAME
  local n="$1"
  case "$n" in
    github.com/caddyserver/*|github.com/valkey-io/*|echarts|core://caddy|core://coraza|core://coraza-caddy|core://owasp-crs|core://xcaddy|core://go-ftw) echo "Apache-2.0" ;;
    github.com/ClickHouse/*|go.opentelemetry.io/*|core://clickhouse|core://otel-collector-contrib) echo "Apache-2.0" ;; # APM 阶段2 数据面（归档见 licenses/clickhouse*/ch-go/opentelemetry-*/otel-collector-contrib/）
    github.com/jackc/*|github.com/jung-kurt/*|github.com/gomutex/*|github.com/vicanso/*|github.com/wcharczuk/*|github.com/dustin/*|go.uber.org/*|react|react-dom|antd|@ant-design/*|zustand|axios|dayjs|vite|@vitejs/*|typescript|core://gofpdf) echo "MIT" ;;
    github.com/andybalholm/brotli|github.com/go-faster/city|github.com/paulmach/orb|github.com/segmentio/asm) echo "MIT" ;; # clickhouse-go 传递依赖（已逐一对照上游 LICENSE 核实）
    github.com/google/uuid|golang.org/x/*|core://valkey) echo "BSD-3-Clause" ;;
    github.com/go-faster/errors|github.com/pierrec/lz4/*) echo "BSD-3-Clause" ;; # clickhouse-go 传递依赖（含 "Neither the name" 条款，核实为 3-Clause）
    google.golang.org/grpc|google.golang.org/genproto/*) echo "Apache-2.0" ;; # OTLP exporter 传递依赖（APM 链，已逐一对照上游 LICENSE 核实）
    github.com/grpc-ecosystem/grpc-gateway/*|github.com/klauspost/compress) echo "BSD-3-Clause" ;; # OTLP/ch-go 传递依赖（含 "Neither the name" 条款，核实为 3-Clause）
    github.com/golang/freetype) echo "FTL" ;; # freetype-go 双许可 FTL/GPLv2+，本项目选择宽松许可证 FTL
    github.com/redis/go-redis/*) echo "BSD-2-Clause" ;;
    core://postgresql) echo "PostgreSQL" ;;
    core://noto-fonts) echo "OFL-1.1" ;;
    core://curl) echo "curl" ;;
    *) echo "NOASSERTION" ;;
  esac
}

work="$(mktemp -d "${TMPDIR:-/tmp}/jzsbom.XXXXXX")"
trap 'rm -rf "$work"' EXIT
: > "$work/components.tsv"   # name \t version \t source

# ---- Go 依赖 ----
collect_go() { # collect_go MODULE_DIR SOURCE
  local dir="$1" src="$2"
  if [[ "$OFFLINE" == "true" ]] || ! command -v go >/dev/null 2>&1; then
    # 静态解析 go.mod（含 indirect 注释行，仅 require 块）
    awk '/^require \(/,/\)/' "$dir/go.mod" | grep -E '^\s+[a-z]' | \
      awk '{print $1" "$2}' | while read -r name ver; do
        printf '%s\t%s\t%s\n' "$name" "$ver" "$src"
      done >> "$work/components.tsv"
    awk '/^require [^(]/ {print $2" "$3}' "$dir/go.mod" | while read -r name ver; do
      [[ -n "$name" && -n "$ver" ]] && printf '%s\t%s\t%s\n' "$name" "$ver" "$src"
    done >> "$work/components.tsv"
    return 0
  fi
  (cd "$dir" && go list -m -json all) | \
    jq -r 'select(.Main != true) | [.Path, (.Version // "")] | @tsv' | \
    while IFS=$'\t' read -r name ver; do
      printf '%s\t%s\t%s\n' "$name" "$ver" "$src"
    done >> "$work/components.tsv"
}

collect_go "$REPO_ROOT/server" "go:server"
collect_go "$REPO_ROOT/gateway/modules/jiuzhang_guard" "go:jiuzhang_guard"

# ---- Node 顶层依赖 ----
if [[ "$OFFLINE" != "true" ]] && command -v npm >/dev/null 2>&1 && [[ -d "$REPO_ROOT/web/node_modules" ]]; then
  (cd "$REPO_ROOT/web" && npm ls --depth=0 --json 2>/dev/null) | \
    jq -r '.dependencies // {} | to_entries[] | [.key, (.value.version // "")] | @tsv' | \
    while IFS=$'\t' read -r name ver; do
      printf '%s\t%s\t%s\n' "$name" "$ver" "node:web"
    done >> "$work/components.tsv"
else
  jq -r '.dependencies // {} | to_entries[] | [.key, .value] | @tsv' "$REPO_ROOT/web/package.json" | \
    while IFS=$'\t' read -r name ver; do
      printf '%s\t%s\t%s\n' "$name" "${ver#[~^]}" "node:web"
    done >> "$work/components.tsv"
fi

# ---- 核心组件固化清单（与 docs/DEPENDENCIES.md 一致） ----
cat >> "$work/components.tsv" <<'EOF'
core://caddy	v2.11.4	core:gateway
core://coraza	v3.7.0	core:gateway
core://coraza-caddy	v2.5.0	core:gateway
core://owasp-crs	v4.28.0	core:gateway
core://xcaddy	v0.4.5	core:build
core://go-ftw	v2.4.0	core:test
core://postgresql	16.4	core:infra
core://valkey	8.1.8	core:infra
core://noto-fonts	main	core:report
core://curl	8.21.0	core:tool
core://clickhouse	25.8	core:apm
core://otel-collector-contrib	0.154.0	core:apm
EOF

# ---- 规范化：去重（同名同版本）+ 排序 ----
sort -t$'\t' -k1,1 -k2,2 -u "$work/components.tsv" > "$work/sorted.tsv"

# 生成合并 JSON（组件数组）
jq -R -s -c '
  split("\n") | map(select(length > 0)) | map(split("\t")) |
  map({name: .[0], version: .[1], sources: [.[2]]}) |
  group_by(.name + "@" + .version) |
  map({name: .[0].name, version: .[0].version,
       sources: ([.[].sources[]] | unique | sort)})' "$work/sorted.tsv" \
  > "$work/components.json"

# 附加许可证字段
jq -c '.[]' "$work/components.json" | while IFS= read -r comp; do
  name="$(printf '%s' "$comp" | jq -r '.name')"
  printf '%s\n' "$(printf '%s' "$comp" | jq -c --arg lic "$(license_of "$name")" '. + {license: $lic}')"
done | jq -s 'sort_by(.name)' > "$work/final.json"

total="$(jq 'length' "$work/final.json")"
noassertion="$(jq '[.[] | select(.license == "NOASSERTION")] | length' "$work/final.json")"

# ---- 时间戳（确定性：git 最近提交时间；无 git 用固定值） ----
created="$(git -C "$REPO_ROOT" log -1 --format=%cI 2>/dev/null || echo '1970-01-01T00:00:00Z')"

# ---- SPDX 2.3 ----
jq -n \
  --arg created "$created" \
  --arg name "jiuzhang-waf-sbom" \
  --argjson comps "$(jq '[.[] | {
      SPDXID: ("SPDXRef-Package-" + (.name | gsub("[^A-Za-z0-9.-]"; "-"))),
      name: .name,
      versionInfo: .version,
      downloadLocation: "NOASSERTION",
      filesAnalyzed: false,
      licenseConcluded: .license,
      licenseDeclared: .license,
      copyrightText: "NOASSERTION",
      supplier: "NOASSERTION",
      comment: (.sources | join(","))
    }]' "$work/final.json")" \
  '{
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: $name,
    documentNamespace: ("https://jiuzhang.example/sbom/" + $name),
    creationInfo: {created: $created, creators: ["Tool: scripts/generate-sbom.sh"]},
    packages: $comps
  }' > "$OUT_DIR/SBOM.spdx.json"

# ---- CycloneDX 1.5 ----
jq -n \
  --arg created "$created" \
  --argjson comps "$(jq '[.[] | {
      type: "library",
      name: .name,
      version: .version,
      licenses: (if .license == "NOASSERTION"
                 then []
                 else [{license: (if (.license | test("^[A-Za-z0-9.-]+$")) then {id: .license} else {name: .license} end)}] end),
      properties: [{name: "jiuzhang:sources", value: (.sources | join(","))}]
    }]' "$work/final.json")" \
  '{
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    version: 1,
    metadata: {
      timestamp: $created,
      tools: [{vendor: "jiuzhang", name: "generate-sbom.sh"}],
      component: {type: "application", name: "jiuzhang-waf", version: "2.5.4"}
    },
    components: $comps
  }' > "$OUT_DIR/SBOM.cyclonedx.json"

# ---- 校验 JSON 合法 ----
jq empty "$OUT_DIR/SBOM.spdx.json"
jq empty "$OUT_DIR/SBOM.cyclonedx.json"

echo "SBOM 已生成:"
echo "  $OUT_DIR/SBOM.spdx.json"
echo "  $OUT_DIR/SBOM.cyclonedx.json"
echo "组件总数: ${total}（NOASSERTION: ${noassertion}，需 license-audit.sh 复核）"
