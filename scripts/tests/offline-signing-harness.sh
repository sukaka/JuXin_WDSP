#!/usr/bin/env bash
# shellcheck disable=SC1090
# offline-signing-harness.sh —— 离线交付包 Ed25519 签名/验签体系（MED-23 后续增强）回归测试。
# 约定与 scripts/tests/ops-security-harness.sh 一致：纯 bash、PASS/FAIL 计数、全程在临时目录
# 内进行（安装脚本一律 --dry-run 或伪造包树在验签闸门后即中止，不触碰真实系统状态）。
#
# 覆盖：
#   1. 签名/验签函数：正签正验通过、篡改检出、错密钥检出、指纹计算
#   2. 内嵌公钥与 release-signing.pub 同源（防漂移）
#   3. 裸机安装器：正签通过 / 篡改中止 / 未签名默认中止 / --allow-unsigned 放行且告警
#   4. install.sh 验签闸门：同上四态（伪造包树在闸门后死于 compose 检查，不执行安装）
#   5. build.sh：未配置私钥时跳过签名并醒目告警；配置私钥时产出 .sig 且可验签
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
COMMON="$REPO_ROOT/ops/lib/common.sh"
SIGNING="$REPO_ROOT/ops/lib/signing.sh"
INSTALL="$REPO_ROOT/ops/install/install.sh"
BM_INSTALL="$REPO_ROOT/ops/install/install-gateway-baremetal.sh"
BUILD="$REPO_ROOT/ops/offline-package/build.sh"
BUILD_ALL="$REPO_ROOT/ops/offline-package/build-all.sh"
PUB_FILE="$REPO_ROOT/ops/offline-package/release-signing.pub"

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/jz-signing-harness.XXXXXX")"
cleanup() {
  case "$TMP_ROOT" in
    */jz-signing-harness.*) rm -rf "$TMP_ROOT" ;;
    *) echo "拒绝清理非测试临时目录: $TMP_ROOT" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM HUP

PASS_COUNT=0
FAIL_COUNT=0
pass() { PASS_COUNT=$((PASS_COUNT+1)); printf 'PASS: %s\n' "$*"; }
fail() { FAIL_COUNT=$((FAIL_COUNT+1)); printf 'FAIL: %s\n' "$*" >&2; }
check() { # check NAME CMD...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$name"; else fail "$name"; fi
}

# 宿主架构（伪造 manifest 用）
case "$(uname -m)" in
  x86_64|amd64)  HOST_ARCH="amd64" ;;
  aarch64|arm64) HOST_ARCH="arm64" ;;
  *) echo "harness 不支持宿主架构: $(uname -m)" >&2; exit 1 ;;
esac

# ---------- 0. 语法检查 ----------
for f in "$COMMON" "$SIGNING" "$INSTALL" "$BM_INSTALL" "$BUILD" "$BUILD_ALL"; do
  check "bash -n $(basename "$f")" bash -n "$f"
done

# ---------- 1. 测试密钥对与签名/验签函数 ----------
openssl genpkey -algorithm ED25519 -out "$TMP_ROOT/rel.key" 2>/dev/null
openssl pkey -in "$TMP_ROOT/rel.key" -pubout -out "$TMP_ROOT/rel.pub" 2>/dev/null
openssl genpkey -algorithm ED25519 -out "$TMP_ROOT/evil.key" 2>/dev/null
openssl pkey -in "$TMP_ROOT/evil.key" -pubout -out "$TMP_ROOT/evil.pub" 2>/dev/null

printf 'fake offline package payload\n' > "$TMP_ROOT/pkg.tar.gz"
(
  source "$COMMON"; source "$SIGNING"
  ed25519_sign_file "$TMP_ROOT/rel.key" "$TMP_ROOT/pkg.tar.gz" "$TMP_ROOT/pkg.tar.gz.sig" \
    && ed25519_verify_file "$TMP_ROOT/rel.pub" "$TMP_ROOT/pkg.tar.gz" "$TMP_ROOT/pkg.tar.gz.sig"
) && pass "正签正验通过（Ed25519 round-trip）" || fail "正签正验"

printf 'fake offline package payload tampered\n' > "$TMP_ROOT/pkg-evil.tar.gz"
cp "$TMP_ROOT/pkg.tar.gz.sig" "$TMP_ROOT/pkg-evil.tar.gz.sig"
(
  source "$COMMON"; source "$SIGNING"
  rc=0; ed25519_verify_file "$TMP_ROOT/rel.pub" "$TMP_ROOT/pkg-evil.tar.gz" "$TMP_ROOT/pkg-evil.tar.gz.sig" 2>/dev/null || rc=$?
  [[ "$rc" -eq 1 ]]
) && pass "篡改包体验签失败" || fail "篡改包体验签检出"

(
  source "$COMMON"; source "$SIGNING"
  rc=0; ed25519_verify_file "$TMP_ROOT/evil.pub" "$TMP_ROOT/pkg.tar.gz" "$TMP_ROOT/pkg.tar.gz.sig" 2>/dev/null || rc=$?
  [[ "$rc" -eq 1 ]]
) && pass "错误公钥验签失败" || fail "错误公钥验签检出"

(
  source "$COMMON"; source "$SIGNING"
  rc=0; ed25519_verify_sidecar "$TMP_ROOT/no-sig.tar.gz" || rc=$?
  [[ "$rc" -eq 2 ]]
) && pass "无旁车签名返回 2（交调用方按策略处置）" || fail "无旁车签名返回码"

(
  source "$COMMON"; source "$SIGNING"
  fp_lib="$(ed25519_pubkey_fingerprint "$TMP_ROOT/rel.pub")"
  fp_cli="$(openssl pkey -pubin -in "$TMP_ROOT/rel.pub" -outform DER | shasum -a 256 | awk '{print $1}')"
  [[ -n "$fp_lib" && "$fp_lib" == "$fp_cli" ]]
) && pass "公钥指纹计算与 openssl 手工计算一致" || fail "公钥指纹计算"

# ---------- 2. 内嵌公钥与 release-signing.pub 同源（防漂移） ----------
for script in "$INSTALL" "$BM_INSTALL"; do
  (
    embedded="$(awk '/^WDSP_RELEASE_PUBKEY_PEM=/{flag=1} flag{print} /-----END PUBLIC KEY-----"/{exit}' "$script" \
      | sed -e 's/^WDSP_RELEASE_PUBKEY_PEM="//' -e 's/"$//')"
    [[ -n "$embedded" ]] || exit 1
    printf '%s\n' "$embedded" > "$TMP_ROOT/embedded.pub"
    source "$COMMON"; source "$SIGNING"
    [[ "$(ed25519_pubkey_fingerprint "$TMP_ROOT/embedded.pub")" == "$(ed25519_pubkey_fingerprint "$PUB_FILE")" ]]
  ) && pass "$(basename "$script") 内嵌公钥与 release-signing.pub 同源" \
    || fail "$(basename "$script") 内嵌公钥漂移"
done

# ---------- 3. 裸机安装器验签闸门（--dry-run） ----------
fake_pkg() { # fake_pkg OUT_TAR [evil]
  local d="$TMP_ROOT/fakepkg-src" out="$1"
  rm -rf "$d"
  mkdir -p "$d/gateway-linux-${HOST_ARCH}/rules/crs"
  printf '#!/bin/sh\necho fake-caddy\n' > "$d/gateway-linux-${HOST_ARCH}/caddy"
  chmod +x "$d/gateway-linux-${HOST_ARCH}/caddy"
  if [[ "${2:-}" == "evil" ]]; then
    printf 'evil\n' >> "$d/gateway-linux-${HOST_ARCH}/caddy"
  fi
  printf '2.11.4 h1:fake\n' > "$d/gateway-linux-${HOST_ARCH}/VERSION"
  printf '# fake crs\n' > "$d/gateway-linux-${HOST_ARCH}/rules/crs/crs-setup.conf"
  printf '<html>block</html>\n' > "$d/gateway-linux-${HOST_ARCH}/blockpage.html"
  cp "$REPO_ROOT/deployment/baremetal/Caddyfile.bootstrap" "$d/gateway-linux-${HOST_ARCH}/"
  cp "$REPO_ROOT/deployment/systemd/jiuzhang-gateway.service" "$d/gateway-linux-${HOST_ARCH}/"
  (cd "$d/gateway-linux-${HOST_ARCH}" && shasum -a 256 caddy > sha256sums)
  tar -czf "$out" -C "$d" "gateway-linux-${HOST_ARCH}"
}

# 3.1 正签正验（旁车 .sha256 + .sig 齐全）
P_SIGNED="$TMP_ROOT/gw-signed.tar.gz"
fake_pkg "$P_SIGNED"
(cd "$TMP_ROOT" && shasum -a 256 "$(basename "$P_SIGNED")" > "$(basename "$P_SIGNED").sha256")
(
  source "$COMMON"; source "$SIGNING"
  ed25519_sign_file "$TMP_ROOT/rel.key" "$P_SIGNED" "$P_SIGNED.sig"
)
SIGNED_OUT="$TMP_ROOT/gw-signed.out"
if WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/rel.pub" bash "$BM_INSTALL" --package "$P_SIGNED" --dry-run > "$SIGNED_OUT" 2>&1 \
   && grep -q "真实性验签通过" "$SIGNED_OUT" && grep -q "整包哈希校验通过" "$SIGNED_OUT"; then
  pass "裸机包正签正验：--dry-run 通过且纵深哈希校验保留"
else
  fail "裸机包正签正验（输出见 ${SIGNED_OUT}）"
fi

# 3.2 篡改包体 + 过期签名：解压前验签失败中止
P_TAMPER="$TMP_ROOT/gw-tamper.tar.gz"
fake_pkg "$P_TAMPER" evil
(cd "$TMP_ROOT" && shasum -a 256 "$(basename "$P_TAMPER")" > "$(basename "$P_TAMPER").sha256")
cp "$P_SIGNED.sig" "$P_TAMPER.sig"
TAMPER_OUT="$TMP_ROOT/gw-tamper.out"
if WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/rel.pub" bash "$BM_INSTALL" --package "$P_TAMPER" --dry-run > "$TAMPER_OUT" 2>&1; then
  fail "篡改裸机包应被验签拒绝"
else
  if grep -q "验签失败" "$TAMPER_OUT" && ! grep -q "SHA256 校验通过" "$TAMPER_OUT"; then
    pass "篡改裸机包：验签失败即中止（未走到解压后校验）"
  else
    fail "篡改裸机包拒绝但输出异常（输出见 ${TAMPER_OUT}）"
  fi
fi

# 3.3 未签名默认中止
P_NOSIG="$TMP_ROOT/gw-nosig.tar.gz"
fake_pkg "$P_NOSIG"
(cd "$TMP_ROOT" && shasum -a 256 "$(basename "$P_NOSIG")" > "$(basename "$P_NOSIG").sha256")
NOSIG_OUT="$TMP_ROOT/gw-nosig.out"
if WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/rel.pub" bash "$BM_INSTALL" --package "$P_NOSIG" --dry-run > "$NOSIG_OUT" 2>&1; then
  fail "未签名裸机包默认应中止"
else
  grep -q "未签名" "$NOSIG_OUT" \
    && pass "未签名裸机包默认中止（fail-closed）" \
    || fail "未签名裸机包中止但输出异常（输出见 ${NOSIG_OUT}）"
fi

# 3.4 未签名 + --allow-unsigned：放行且醒目告警
ALLOW_OUT="$TMP_ROOT/gw-allow.out"
if WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/rel.pub" bash "$BM_INSTALL" --package "$P_NOSIG" --dry-run --allow-unsigned > "$ALLOW_OUT" 2>&1 \
   && grep -q "allow-unsigned 已放行未签名包" "$ALLOW_OUT"; then
  pass "未签名裸机包 --allow-unsigned 放行且醒目告警"
else
  fail "裸机包 --allow-unsigned 放行路径（输出见 ${ALLOW_OUT}）"
fi

# ---------- 4. install.sh 验签闸门（伪造包树，闸门后死于 compose 检查） ----------
mk_fake_tree() { # mk_fake_tree DIR —— 伪造解压目录 + 同级 tar.gz + .sha256
  local dir="$1"
  rm -rf "$dir" "$dir.tar.gz" "$dir.tar.gz.sha256" "$dir.tar.gz.sig"
  mkdir -p "$dir"
  jq -n --arg arch "$HOST_ARCH" '{product:"t", edition:"waf", version:"0.0.0", arch:$arch}' > "$dir/manifest.json"
  printf 'fake full offline package\n' > "$TMP_ROOT/tree-payload"
  tar -czf "$dir.tar.gz" -C "$TMP_ROOT" tree-payload
  (cd "$TMP_ROOT" && shasum -a 256 "$(basename "$dir.tar.gz")" > "$(basename "$dir.tar.gz").sha256")
}

# 4.1 正签正验：闸门通过，随后死于 compose 缺失（不执行任何安装动作）
T1="$TMP_ROOT/tree-signed"
mk_fake_tree "$T1"
(
  source "$COMMON"; source "$SIGNING"
  ed25519_sign_file "$TMP_ROOT/rel.key" "$T1.tar.gz" "$T1.tar.gz.sig"
)
T1_OUT="$TMP_ROOT/tree-signed.out"
( cd "$T1" && WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/rel.pub" bash "$INSTALL" --no-firewall --skip-accounts ) > "$T1_OUT" 2>&1
if grep -q "真实性验签通过" "$T1_OUT" && grep -q "整包哈希校验通过" "$T1_OUT" \
   && grep -q "compose 文件不存在" "$T1_OUT" && ! grep -q "验签失败\|未签名" "$T1_OUT"; then
  pass "install.sh 正签正验：闸门通过且纵深校验保留（随后按预期死于 compose 检查）"
else
  fail "install.sh 正签正验（输出见 ${T1_OUT}）"
fi

# 4.2 篡改包体：验签失败中止
T2="$TMP_ROOT/tree-tampered"
mk_fake_tree "$T2"
cp "$T1.tar.gz.sig" "$T2.tar.gz.sig"
printf 'tampered payload appended\n' >> "$T2.tar.gz"
T2_OUT="$TMP_ROOT/tree-tampered.out"
( cd "$T2" && WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/rel.pub" bash "$INSTALL" --no-firewall --skip-accounts ) > "$T2_OUT" 2>&1
if [[ "$?" -ne 0 ]] && grep -q "验签失败" "$T2_OUT" && ! grep -q "compose 文件不存在" "$T2_OUT"; then
  pass "install.sh 篡改包：验签失败 fail-closed 中止"
else
  fail "install.sh 篡改包（输出见 ${T2_OUT}）"
fi

# 4.3 未签名默认中止
T3="$TMP_ROOT/tree-unsigned"
mk_fake_tree "$T3"
T3_OUT="$TMP_ROOT/tree-unsigned.out"
( cd "$T3" && WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/rel.pub" bash "$INSTALL" --no-firewall --skip-accounts ) > "$T3_OUT" 2>&1
if [[ "$?" -ne 0 ]] && grep -q "未签名" "$T3_OUT" && ! grep -q "compose 文件不存在" "$T3_OUT"; then
  pass "install.sh 未签名包默认中止（提示需官方签名包）"
else
  fail "install.sh 未签名包默认中止（输出见 ${T3_OUT}）"
fi

# 4.4 未签名 + --allow-unsigned：醒目告警后放行（随后死于 compose 检查）
T4_OUT="$TMP_ROOT/tree-allow.out"
( cd "$T3" && WDSP_PACKAGE_PUBLIC_KEY="$TMP_ROOT/rel.pub" bash "$INSTALL" --no-firewall --skip-accounts --allow-unsigned ) > "$T4_OUT" 2>&1
if grep -q "allow-unsigned 已放行未签名包" "$T4_OUT" && grep -q "compose 文件不存在" "$T4_OUT"; then
  pass "install.sh --allow-unsigned 放行且醒目告警"
else
  fail "install.sh --allow-unsigned 放行路径（输出见 ${T4_OUT}）"
fi

# ---------- 5. build.sh 签名行为 ----------
BUILD_OUT_DIR_U="$TMP_ROOT/dist-unsigned"
U_OUT="$TMP_ROOT/build-unsigned.out"
if bash "$BUILD" -v 0.0.0-harness -p waf -a "$HOST_ARCH" --skip-images -o "$BUILD_OUT_DIR_U" > "$U_OUT" 2>&1; then
  U_PKG="$BUILD_OUT_DIR_U/jiuzhang-waf-offline-0.0.0-harness-${HOST_ARCH}.tar.gz"
  if [[ -f "$U_PKG" && ! -f "$U_PKG.sig" ]] \
     && grep -q "产物将不签名" "$U_OUT" && grep -q "离线交付包未签名" "$U_OUT" \
     && tar -xOf "$U_PKG" "jiuzhang-waf-offline-0.0.0-harness-${HOST_ARCH}/manifest.json" | grep -q '"signed": false'; then
    pass "build.sh 未配置私钥：跳过签名 + 醒目告警 + manifest 标记 signed=false"
  else
    fail "build.sh 未签名产物标记（输出见 ${U_OUT}）"
  fi
else
  fail "build.sh 未签名构建执行失败（输出见 ${U_OUT}）"
fi

BUILD_OUT_DIR_S="$TMP_ROOT/dist-signed"
S_OUT="$TMP_ROOT/build-signed.out"
if WDSP_SIGNING_KEY="$TMP_ROOT/rel.key" bash "$BUILD" -v 0.0.0-harness -p waf -a "$HOST_ARCH" --skip-images -o "$BUILD_OUT_DIR_S" > "$S_OUT" 2>&1; then
  S_PKG="$BUILD_OUT_DIR_S/jiuzhang-waf-offline-0.0.0-harness-${HOST_ARCH}.tar.gz"
  s_ok=true
  [[ -f "$S_PKG.sig" ]] || { s_ok=false; printf '缺整包 .sig\n' >&2; }
  (
    source "$COMMON"; source "$SIGNING"
    ed25519_verify_file "$TMP_ROOT/rel.pub" "$S_PKG" "$S_PKG.sig"
  ) || { s_ok=false; printf '整包 .sig 验签失败\n' >&2; }
  tar -tzf "$S_PKG" | grep -q "gateway-linux-${HOST_ARCH}.tar.gz.sig" \
    || { s_ok=false; printf '内嵌裸机包缺 .sig\n' >&2; }
  tar -xOf "$S_PKG" "jiuzhang-waf-offline-0.0.0-harness-${HOST_ARCH}/manifest.json" | grep -q '"signed": true' \
    || { s_ok=false; printf 'manifest 未标记 signed=true\n' >&2; }
  [[ "$s_ok" == "true" ]] && pass "build.sh 配置私钥：整包与内嵌裸机包均产出可验签 .sig，manifest signed=true" \
    || fail "build.sh 签名产物完整性（输出见 ${S_OUT}）"
else
  fail "build.sh 签名构建执行失败（输出见 ${S_OUT}）"
fi

# 配置无效私钥路径必须报错（不得静默降级为未签名）
check "build.sh 私钥路径无效时 fail-closed" \
  bash -c "WDSP_SIGNING_KEY=/nonexistent.key bash '$BUILD' -v 0.0.0-harness -p waf -a '$HOST_ARCH' --skip-images -o '$TMP_ROOT/dist-bad' >/dev/null 2>&1; [[ \$? -eq 1 ]]"

check "build-all.sh usage 说明 WDSP_SIGNING_KEY" \
  bash -c "bash '$BUILD_ALL' --help 2>&1 | grep -q WDSP_SIGNING_KEY"

printf '\n========== harness 结果: PASS=%d FAIL=%d ==========\n' "$PASS_COUNT" "$FAIL_COUNT"
[[ "$FAIL_COUNT" -eq 0 ]]
