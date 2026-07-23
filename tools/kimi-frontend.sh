#!/usr/bin/env bash
# 在隔离 Git worktree 中调用 Kimi CLI 实现前端任务，并保留本地审计记录。
set -euo pipefail
umask 077

usage() {
  cat <<'EOF'
用法: kimi-frontend.sh TASK_FILE [BASE_REF]

TASK_FILE 必须位于 .agent/tasks/active/ 且扩展名为 .md。
BASE_REF 默认为环境变量 KIMI_BASE_REF；未设置时使用 HEAD。

可选环境变量:
  KIMI_BASE_REF          默认 Git 基线
  KIMI_MODEL             Kimi 模型别名
  KIMI_WORKTREE_PARENT   隔离工作树父目录

退出码:
  0  Kimi 成功且范围检查通过
  2  参数或环境错误
  3  范围检查失败
  4  Kimi CLI 执行失败
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage >&2
  exit 2
fi

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "缺少必需命令: $1" >&2
    exit 2
  }
}

require_cmd git
require_cmd kimi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "$REPO_ROOT" ]]; then
  echo "脚本不在 Git 仓库中。" >&2
  exit 2
fi
REPO_ROOT="$(cd "$REPO_ROOT" && pwd -P)"
SCOPE_CHECK="$SCRIPT_DIR/check-kimi-scope.sh"
if [[ ! -f "$SCOPE_CHECK" ]]; then
  echo "缺少范围检查脚本: $SCOPE_CHECK" >&2
  exit 2
fi

fingerprint_worktree() {
  local root="$1"
  local untracked

  git -C "$root" rev-parse HEAD
  git -C "$root" status --porcelain=v2 -z --untracked-files=all
  git -C "$root" diff --no-ext-diff --no-textconv --binary HEAD --
  while IFS= read -r -d '' untracked; do
    printf '%s\0' "$untracked"
    if [[ -e "$root/$untracked" || -L "$root/$untracked" ]]; then
      git hash-object --no-filters -- "$root/$untracked" 2>/dev/null || printf 'unreadable'
    else
      printf 'missing'
    fi
  done < <(git -C "$root" ls-files --others --exclude-standard -z)
}

fingerprint_other_worktrees() {
  local line
  local root

  while IFS= read -r line; do
    case "$line" in
      worktree\ *)
        root="${line#worktree }"
        if [[ "$root" == "$WORKTREE" ]]; then
          continue
        fi
        printf '%s\0' "$root"
        if [[ -d "$root" ]]; then
          fingerprint_worktree "$root"
        else
          printf 'missing'
        fi
        ;;
    esac
  done < <(git -C "$REPO_ROOT" worktree list --porcelain)
}

fingerprint_refs() {
  git -C "$REPO_ROOT" for-each-ref \
    --format='%(refname)%00%(objectname)%00%(objecttype)'
}

TASK_INPUT="$1"
if [[ "$TASK_INPUT" != /* ]]; then
  TASK_INPUT="$PWD/$TASK_INPUT"
fi
if [[ ! -f "$TASK_INPUT" || -L "$TASK_INPUT" ]]; then
  echo "任务书必须是普通 Markdown 文件且不能是符号链接: $TASK_INPUT" >&2
  exit 2
fi
TASK_DIR="$(cd "$(dirname "$TASK_INPUT")" && pwd -P)"
TASK_PATH="$TASK_DIR/$(basename "$TASK_INPUT")"
case "$TASK_PATH" in
  "$REPO_ROOT"/.agent/tasks/active/*.md) ;;
  *)
    echo "任务书必须位于 $REPO_ROOT/.agent/tasks/active/。" >&2
    exit 2
    ;;
esac

TASK_FILE_NAME="$(basename "$TASK_PATH")"
TASK_ID="${TASK_FILE_NAME%.md}"
if [[ ! "$TASK_ID" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; then
  echo "任务 ID 只能包含字母、数字、下划线和连字符: $TASK_ID" >&2
  exit 2
fi

BASE_REF="${2:-${KIMI_BASE_REF:-HEAD}}"
BASE_COMMIT="$(git -C "$REPO_ROOT" rev-parse --verify "${BASE_REF}^{commit}" 2>/dev/null || true)"
if [[ -z "$BASE_COMMIT" ]]; then
  echo "基线不是有效提交: $BASE_REF" >&2
  exit 2
fi

REPO_NAME="$(basename "$REPO_ROOT")"
DEFAULT_WORKTREE_PARENT="$(dirname "$REPO_ROOT")/.${REPO_NAME}-agent-worktrees"
WORKTREE_PARENT="${KIMI_WORKTREE_PARENT:-$DEFAULT_WORKTREE_PARENT}"
mkdir -p "$WORKTREE_PARENT"
WORKTREE_PARENT="$(cd "$WORKTREE_PARENT" && pwd -P)"
if [[ "$WORKTREE_PARENT" == "/" ]]; then
  echo "工作树父目录不能是文件系统根目录。" >&2
  exit 2
fi
case "$WORKTREE_PARENT/" in
  "$REPO_ROOT/"*)
    echo "工作树父目录必须位于仓库之外: $WORKTREE_PARENT" >&2
    exit 2
    ;;
esac

RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_ID="${TASK_ID}-${RUN_STAMP}-$$"
BRANCH_NAME="agent/kimi-frontend-${RUN_ID}"
WORKTREE="$WORKTREE_PARENT/$RUN_ID"
RUN_DIR="$REPO_ROOT/.agent/runs/$RUN_ID"
mkdir -p "$RUN_DIR"

if [[ -e "$WORKTREE" ]]; then
  echo "工作树路径已存在: $WORKTREE" >&2
  exit 2
fi
if git -C "$REPO_ROOT" show-ref --verify --quiet "refs/heads/$BRANCH_NAME"; then
  echo "分支已存在: $BRANCH_NAME" >&2
  exit 2
fi

{
  printf 'run_id=%s\n' "$RUN_ID"
  printf 'task_id=%s\n' "$TASK_ID"
  printf 'task_file=%s\n' "$TASK_PATH"
  printf 'base_ref=%s\n' "$BASE_REF"
  printf 'base_commit=%s\n' "$BASE_COMMIT"
  printf 'branch=%s\n' "$BRANCH_NAME"
  printf 'worktree=%s\n' "$WORKTREE"
  printf 'kimi_version=%s\n' "$(kimi --version)"
  printf 'started_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$RUN_DIR/metadata.txt"

if ! git -C "$REPO_ROOT" worktree add -b "$BRANCH_NAME" "$WORKTREE" "$BASE_COMMIT" \
  > "$RUN_DIR/worktree.log" 2>&1; then
  echo "创建隔离工作树失败，详情见 $RUN_DIR/worktree.log" >&2
  exit 2
fi

TASK_COPY="$WORKTREE/.kimi-frontend-task.md"
cleanup_task_copy() {
  if [[ -n "${TASK_COPY:-}" && ( -e "$TASK_COPY" || -L "$TASK_COPY" ) ]]; then
    rm -f "$TASK_COPY"
  fi
}
trap cleanup_task_copy EXIT INT TERM HUP
cp "$TASK_PATH" "$TASK_COPY"
chmod 600 "$TASK_COPY"

OTHER_WORKTREES_BEFORE="$(fingerprint_other_worktrees | git hash-object --stdin)"
REFS_BEFORE="$(fingerprint_refs | git hash-object --stdin)"

PROMPT="$(cat <<'EOF'
你是九章 WAF 的受限前端实现者。请先完整阅读仓库根 AGENTS.md 和 .kimi-frontend-task.md，然后完成任务。

硬性边界：
1. 只允许修改 web/ 下与任务直接相关的文件。
2. 不得修改 server/、gateway/、deployment/、docs/、.github/、.agent/、tools/ 或任何 Git 元数据。
3. 不得执行 git commit、git push、merge、rebase、tag、reset 或 checkout。
4. 不得读取、输出或写入凭据、Token、私钥、.env 和真实生产数据。
5. 不做无关重构、依赖升级、遥测或未授权网络调用。
6. 按任务书补充测试并运行其中明确列出的最小验收命令。

结束时仅报告：修改文件及目的、实际运行命令与结果、剩余风险。不要声称已经提交或发布。
EOF
)"
printf '%s\n' "$PROMPT" > "$RUN_DIR/prompt.txt"

KIMI_COMMAND=(kimi)
if [[ -n "${KIMI_MODEL:-}" ]]; then
  KIMI_COMMAND+=(--model "$KIMI_MODEL")
fi
KIMI_COMMAND+=(--prompt "$PROMPT")

set +e
(
  cd "$WORKTREE"
  "${KIMI_COMMAND[@]}"
) > "$RUN_DIR/stdout.log" 2> "$RUN_DIR/stderr.log"
KIMI_EXIT=$?
set -e

cleanup_task_copy
trap - EXIT INT TERM HUP

git -C "$WORKTREE" status --short > "$RUN_DIR/git-status.txt"
git -C "$WORKTREE" diff --stat "$BASE_COMMIT" -- > "$RUN_DIR/diff-stat.txt"

OTHER_WORKTREES_AFTER="$(fingerprint_other_worktrees | git hash-object --stdin)"
REFS_AFTER="$(fingerprint_refs | git hash-object --stdin)"
REPOSITORY_SCOPE_EXIT=0
{
  if [[ "$OTHER_WORKTREES_AFTER" != "$OTHER_WORKTREES_BEFORE" ]]; then
    echo "越界: Kimi 运行期间其他 Git 工作树发生变化。" >&2
    REPOSITORY_SCOPE_EXIT=1
  fi
  if [[ "$REFS_AFTER" != "$REFS_BEFORE" ]]; then
    echo "越界: Kimi 运行期间共享 Git refs 发生变化。" >&2
    REPOSITORY_SCOPE_EXIT=1
  fi
  if [[ "$REPOSITORY_SCOPE_EXIT" -eq 0 ]]; then
    echo "仓库外围检查通过：其他工作树和共享 Git refs 均未变化。"
  fi
} > "$RUN_DIR/repository-scope.log" 2>&1

set +e
bash "$SCOPE_CHECK" "$WORKTREE" "$BASE_COMMIT" "web/" \
  > "$RUN_DIR/scope.log" 2>&1
SCOPE_EXIT=$?
set -e
if [[ "$REPOSITORY_SCOPE_EXIT" -ne 0 ]]; then
  SCOPE_EXIT=1
fi

{
  printf 'kimi_exit=%s\n' "$KIMI_EXIT"
  printf 'scope_exit=%s\n' "$SCOPE_EXIT"
  printf 'repository_scope_exit=%s\n' "$REPOSITORY_SCOPE_EXIT"
  printf 'finished_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$RUN_DIR/result.txt"

echo "Kimi 运行完成。"
echo "  工作树: $WORKTREE"
echo "  分支:   $BRANCH_NAME"
echo "  记录:   $RUN_DIR"
cat "$RUN_DIR/scope.log"
cat "$RUN_DIR/repository-scope.log"

if [[ "$SCOPE_EXIT" -ne 0 ]]; then
  echo "范围检查失败；保留工作树供 Codex 审查，禁止提交。" >&2
  exit 3
fi
if [[ "$KIMI_EXIT" -ne 0 ]]; then
  echo "Kimi CLI 执行失败（退出码 ${KIMI_EXIT}）；详情见本地运行记录。" >&2
  exit 4
fi

echo "下一步：由 Codex 审查差异并独立重跑任务书中的验收命令。"
