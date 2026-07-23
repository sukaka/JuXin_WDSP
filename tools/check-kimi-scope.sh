#!/usr/bin/env bash
# 检查 Kimi 工作树是否只包含允许范围内的未提交前端改动。
set -euo pipefail

usage() {
  cat <<'EOF'
用法: check-kimi-scope.sh WORKTREE BASE_COMMIT [ALLOWED_PREFIX...]

示例:
  tools/check-kimi-scope.sh /tmp/kimi-task abc123 web/

要求:
  - WORKTREE 必须是 Git 工作树根目录；
  - HEAD 必须仍等于 BASE_COMMIT（Kimi 不得提交或改写历史）；
  - 默认允许前缀为 web/；
  - 修改或创建符号链接会被拒绝。

退出码: 0=通过 1=发现越界或历史变更 2=参数/环境错误
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 2 ]]; then
  usage >&2
  exit 2
fi

WORKTREE_INPUT="$1"
BASE_INPUT="$2"
shift 2

if [[ ! -d "$WORKTREE_INPUT" ]]; then
  echo "工作树不存在: $WORKTREE_INPUT" >&2
  exit 2
fi

WORKTREE="$(cd "$WORKTREE_INPUT" && pwd -P)"
GIT_ROOT="$(git -C "$WORKTREE" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$GIT_ROOT" ]]; then
  echo "不是 Git 工作树: $WORKTREE" >&2
  exit 2
fi
GIT_ROOT="$(cd "$GIT_ROOT" && pwd -P)"
if [[ "$WORKTREE" != "$GIT_ROOT" ]]; then
  echo "必须传入 Git 工作树根目录: $GIT_ROOT" >&2
  exit 2
fi

BASE_COMMIT="$(git -C "$WORKTREE" rev-parse --verify "${BASE_INPUT}^{commit}" 2>/dev/null || true)"
if [[ -z "$BASE_COMMIT" ]]; then
  echo "基线不是有效提交: $BASE_INPUT" >&2
  exit 2
fi

if [[ $# -eq 0 ]]; then
  set -- "web/"
fi

ALLOWED_PREFIXES=()
for raw_prefix in "$@"; do
  prefix="${raw_prefix#./}"
  while [[ "$prefix" == */ ]]; do
    prefix="${prefix%/}"
  done
  case "/$prefix/" in
    "//"|*"/../"*|*"/./"*)
      echo "非法允许前缀: $raw_prefix" >&2
      exit 2
      ;;
  esac
  if [[ "$prefix" == /* ]]; then
    echo "允许前缀必须是仓库相对路径: $raw_prefix" >&2
    exit 2
  fi
  ALLOWED_PREFIXES+=("$prefix/")
done

HEAD_COMMIT="$(git -C "$WORKTREE" rev-parse HEAD)"
VIOLATIONS=0
CHANGED_COUNT=0

if [[ "$HEAD_COMMIT" != "$BASE_COMMIT" ]]; then
  echo "越界: HEAD 已变化（Kimi 不得提交或改写历史）" >&2
  echo "  基线: $BASE_COMMIT" >&2
  echo "  当前: $HEAD_COMMIT" >&2
  VIOLATIONS=$((VIOLATIONS + 1))
fi

is_allowed_path() {
  local relative_path="$1"
  local allowed_prefix
  for allowed_prefix in "${ALLOWED_PREFIXES[@]}"; do
    if [[ "$relative_path" == "$allowed_prefix"* ]]; then
      return 0
    fi
  done
  return 1
}

has_symlink_component() {
  local relative_path="$1"
  local current="$WORKTREE"
  local old_ifs="$IFS"
  local component
  local components=()
  IFS='/'
  read -r -a components <<< "$relative_path"
  IFS="$old_ifs"
  for component in "${components[@]}"; do
    current="$current/$component"
    if [[ -L "$current" ]]; then
      return 0
    fi
  done
  return 1
}

base_was_symlink() {
  local relative_path="$1"
  local tree_entry
  tree_entry="$(git -C "$WORKTREE" ls-tree "$BASE_COMMIT" -- "$relative_path")"
  [[ "$tree_entry" == 120000\ * ]]
}

inspect_path() {
  local relative_path="$1"
  CHANGED_COUNT=$((CHANGED_COUNT + 1))
  printf '  %s\n' "$relative_path"

  case "$relative_path" in
    ""|/*|../*|*/../*|*/..|./*|*/./*|*/.)
      echo "越界: 非法仓库相对路径: $relative_path" >&2
      VIOLATIONS=$((VIOLATIONS + 1))
      return
      ;;
  esac

  if ! is_allowed_path "$relative_path"; then
    echo "越界: 不允许修改 $relative_path" >&2
    VIOLATIONS=$((VIOLATIONS + 1))
  fi

  if has_symlink_component "$relative_path" || base_was_symlink "$relative_path"; then
    echo "越界: 不允许通过符号链接修改 $relative_path" >&2
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
}

echo "检测到的改动:"
while IFS= read -r -d '' path; do
  inspect_path "$path"
done < <(git -C "$WORKTREE" diff --name-only --diff-filter=ACDMRTUXB -z "$BASE_COMMIT" --)

while IFS= read -r -d '' path; do
  inspect_path "$path"
done < <(git -C "$WORKTREE" ls-files --others --exclude-standard -z)

if [[ "$CHANGED_COUNT" -eq 0 ]]; then
  echo "  （无文件改动）"
fi

if [[ "$VIOLATIONS" -ne 0 ]]; then
  echo "Kimi 范围检查失败，共发现 $VIOLATIONS 项违规。" >&2
  exit 1
fi

echo "Kimi 范围检查通过：HEAD 未变化，所有改动均在允许范围内。"
