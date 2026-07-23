#!/usr/bin/env bash
# 不调用 Kimi 网络服务，验证前端范围检查器的关键安全边界。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
SCOPE_CHECK="$REPO_ROOT/tools/check-kimi-scope.sh"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jz-kimi-harness.XXXXXX")"
cleanup() {
  case "$TMP_ROOT" in
    */jz-kimi-harness.*) rm -rf "$TMP_ROOT" ;;
    *) echo "拒绝清理非测试临时目录: $TMP_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

FIXTURE="$TMP_ROOT/repo"
mkdir -p "$FIXTURE/web" "$FIXTURE/server" "$FIXTURE/web-other"
git -C "$FIXTURE" init -q
git -C "$FIXTURE" config user.name "Harness Test"
git -C "$FIXTURE" config user.email "harness@example.invalid"
printf 'baseline\n' > "$FIXTURE/web/app.txt"
printf 'baseline\n' > "$FIXTURE/server/api.txt"
printf 'baseline\n' > "$FIXTURE/web-other/fake.txt"
git -C "$FIXTURE" add .
git -C "$FIXTURE" commit -q -m "test: baseline"
BASE_COMMIT="$(git -C "$FIXTURE" rev-parse HEAD)"

PASS_COUNT=0

expect_pass() {
  local name="$1"
  shift
  if "$@" > "$TMP_ROOT/last-output.txt" 2>&1; then
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'ok - %s\n' "$name"
  else
    printf 'not ok - %s\n' "$name" >&2
    cat "$TMP_ROOT/last-output.txt" >&2
    exit 1
  fi
}

expect_fail() {
  local name="$1"
  shift
  if "$@" > "$TMP_ROOT/last-output.txt" 2>&1; then
    printf 'not ok - %s（本应失败）\n' "$name" >&2
    cat "$TMP_ROOT/last-output.txt" >&2
    exit 1
  else
    PASS_COUNT=$((PASS_COUNT + 1))
    printf 'ok - %s\n' "$name"
  fi
}

reset_fixture() {
  git -C "$FIXTURE" restore --staged --worktree .
  git -C "$FIXTURE" clean -fdq
}

expect_pass "无改动通过" bash "$SCOPE_CHECK" "$FIXTURE" "$BASE_COMMIT" "web/"

printf 'frontend change\n' > "$FIXTURE/web/app.txt"
expect_pass "web 内受跟踪改动通过" bash "$SCOPE_CHECK" "$FIXTURE" "$BASE_COMMIT" "web/"
reset_fixture

printf 'new frontend file\n' > "$FIXTURE/web/new.txt"
expect_pass "web 内未跟踪文件通过" bash "$SCOPE_CHECK" "$FIXTURE" "$BASE_COMMIT" "web/"
reset_fixture

printf 'backend change\n' > "$FIXTURE/server/api.txt"
expect_fail "server 越界改动失败" bash "$SCOPE_CHECK" "$FIXTURE" "$BASE_COMMIT" "web/"
reset_fixture

printf 'prefix bypass\n' > "$FIXTURE/web-other/fake.txt"
expect_fail "相似路径前缀不能绕过" bash "$SCOPE_CHECK" "$FIXTURE" "$BASE_COMMIT" "web/"
reset_fixture

printf 'outside\n' > "$TMP_ROOT/outside.txt"
ln -s "$TMP_ROOT/outside.txt" "$FIXTURE/web/outside-link"
expect_fail "web 内符号链接失败" bash "$SCOPE_CHECK" "$FIXTURE" "$BASE_COMMIT" "web/"
reset_fixture

expect_fail "无效基线失败" bash "$SCOPE_CHECK" "$FIXTURE" "not-a-commit" "web/"

printf 'committed by agent\n' > "$FIXTURE/web/app.txt"
git -C "$FIXTURE" add web/app.txt
git -C "$FIXTURE" commit -q -m "forbidden agent commit"
expect_fail "Kimi 修改 HEAD 失败" bash "$SCOPE_CHECK" "$FIXTURE" "$BASE_COMMIT" "web/"

mkdir -p "$FIXTURE/tools" "$FIXTURE/.agent/tasks/active" "$FIXTURE/.agent/runs"
cp "$REPO_ROOT/tools/kimi-frontend.sh" "$FIXTURE/tools/kimi-frontend.sh"
cp "$SCOPE_CHECK" "$FIXTURE/tools/check-kimi-scope.sh"
printf '# Test constraints\n' > "$FIXTURE/AGENTS.md"
printf '*\n!.gitignore\n' > "$FIXTURE/.agent/tasks/active/.gitignore"
printf '*\n!.gitignore\n' > "$FIXTURE/.agent/runs/.gitignore"
git -C "$FIXTURE" add AGENTS.md tools .agent
git -C "$FIXTURE" commit -q -m "test: add launcher fixture"
LAUNCH_BASE="$(git -C "$FIXTURE" rev-parse HEAD)"

FAKE_BIN="$TMP_ROOT/fake-bin"
mkdir -p "$FAKE_BIN"
cat > "$FAKE_BIN/kimi" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then
  echo "0.0.0-test"
  exit 0
fi
case "${KIMI_TEST_MODE:-}" in
  other-worktree)
    printf 'tampered by fake Kimi\n' >> "$KIMI_TEST_ATTACK_PATH"
    ;;
  shared-ref)
    git tag "forbidden-kimi-tag"
    ;;
  *)
    echo "missing fake Kimi test mode" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$FAKE_BIN/kimi"

printf '# 越界测试\n' > "$FIXTURE/.agent/tasks/active/escape.md"
set +e
PATH="$FAKE_BIN:$PATH" \
  KIMI_WORKTREE_PARENT="$TMP_ROOT/worktrees" \
  KIMI_TEST_MODE="other-worktree" \
  KIMI_TEST_ATTACK_PATH="$FIXTURE/server/api.txt" \
  bash "$FIXTURE/tools/kimi-frontend.sh" \
    "$FIXTURE/.agent/tasks/active/escape.md" "$LAUNCH_BASE" \
    > "$TMP_ROOT/launcher-output.txt" 2>&1
LAUNCH_EXIT=$?
set -e
if [[ "$LAUNCH_EXIT" -ne 3 ]]; then
  echo "not ok - 启动器未阻止其他工作树越界（退出码 $LAUNCH_EXIT）" >&2
  cat "$TMP_ROOT/launcher-output.txt" >&2
  exit 1
fi
if ! grep -q "其他 Git 工作树发生变化" "$TMP_ROOT/launcher-output.txt"; then
  echo "not ok - 启动器缺少其他工作树越界证据" >&2
  cat "$TMP_ROOT/launcher-output.txt" >&2
  exit 1
fi
PASS_COUNT=$((PASS_COUNT + 1))
echo "ok - 启动器阻止修改其他工作树"

printf '# refs 越界测试\n' > "$FIXTURE/.agent/tasks/active/refs.md"
set +e
PATH="$FAKE_BIN:$PATH" \
  KIMI_WORKTREE_PARENT="$TMP_ROOT/worktrees" \
  KIMI_TEST_MODE="shared-ref" \
  bash "$FIXTURE/tools/kimi-frontend.sh" \
    "$FIXTURE/.agent/tasks/active/refs.md" "$LAUNCH_BASE" \
    > "$TMP_ROOT/launcher-output.txt" 2>&1
LAUNCH_EXIT=$?
set -e
if [[ "$LAUNCH_EXIT" -ne 3 ]]; then
  echo "not ok - 启动器未阻止共享 refs 越界（退出码 $LAUNCH_EXIT）" >&2
  cat "$TMP_ROOT/launcher-output.txt" >&2
  exit 1
fi
if ! grep -q "共享 Git refs 发生变化" "$TMP_ROOT/launcher-output.txt"; then
  echo "not ok - 启动器缺少共享 refs 越界证据" >&2
  cat "$TMP_ROOT/launcher-output.txt" >&2
  exit 1
fi
PASS_COUNT=$((PASS_COUNT + 1))
echo "ok - 启动器阻止修改共享 Git refs"

printf '全部 %s 项 Kimi 前端范围测试通过。\n' "$PASS_COUNT"
