#!/usr/bin/env bash
# signing.sh —— 离线交付包 Ed25519 签名/验签公共函数（OpenSSL 3.x 标准能力，无新增依赖）。
# 依赖：调用方须先 source ops/lib/common.sh（require_cmd / sha256_of / log_*）。
#
# 信任模型（MED-23 复核结论方案①）：
#   发布侧用私钥（WDSP_SIGNING_KEY 指定，绝不入库）对整包 tar.gz 签名，产出旁车
#   <包>.sig（base64 单行）；安装端用脚本内嵌的可信公钥（WDSP_RELEASE_PUBKEY_PEM，
#   与 ops/offline-package/release-signing.pub 同源）在解压/执行任何包内容之前验签，
#   失败 fail-closed 中止。验签通过后旁车 .sha256 与包内清单校验保留为纵深。
#
# 签名格式：openssl pkeyutl -sign -rawin（Ed25519 纯签名，无预哈希），
# 旁车文件为 base64 编码的 64 字节签名。

# ed25519_sign_file PRIVKEY_PEM INPUT OUT_SIG —— 生成 base64 签名旁车。
ed25519_sign_file() {
  local key="$1" input="$2" out="$3"
  require_cmd openssl
  [[ -f "$key" ]] || { log_err "签名私钥不存在: $key"; return 1; }
  local raw
  raw="$(mktemp "${TMPDIR:-/tmp}/jzsig.XXXXXX")"
  if ! openssl pkeyutl -sign -inkey "$key" -rawin -in "$input" -out "$raw" 2>/dev/null; then
    rm -f "$raw"
    log_err "Ed25519 签名失败: $input（请确认 $key 为 Ed25519 私钥）"
    return 1
  fi
  base64 < "$raw" > "$out"
  rm -f "$raw"
}

# ed25519_verify_file PUBKEY_PEM INPUT SIG_B64 —— 验签，0=通过 1=失败。
ed25519_verify_file() {
  local pub="$1" input="$2" sig="$3"
  require_cmd openssl
  local raw rc
  raw="$(mktemp "${TMPDIR:-/tmp}/jzsigv.XXXXXX")"
  if ! base64 -d < "$sig" > "$raw" 2>/dev/null; then
    rm -f "$raw"
    log_err "签名旁车 base64 解码失败: $sig"
    return 1
  fi
  openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in "$input" -sigfile "$raw" >/dev/null 2>&1
  rc=$?
  rm -f "$raw"
  return "$rc"
}

# ed25519_pubkey_fingerprint PUBKEY_PEM —— 公钥指纹（DER 的 SHA-256），用于文档公示与轮换核对。
ed25519_pubkey_fingerprint() {
  local pub="$1"
  require_cmd openssl
  openssl pkey -pubin -in "$pub" -outform DER 2>/dev/null | sha256_of | awk '{print $1}'
}

# ed25519_verify_sidecar ARCHIVE —— 用旁车 <ARCHIVE>.sig 对整包验签（安装端闸门）。
# 信任锚：生产模式只能使用调用方脚本内嵌的 WDSP_RELEASE_PUBKEY_PEM。
# WDSP_PACKAGE_PUBLIC_KEY 仅在调用方明确设置 WDSP_DEVELOPMENT_MODE=1 时可用，
# 供本地开发自验，不得作为生产轮换或交付配置。
# 返回：0=验签通过 1=验签失败 2=无旁车签名（由调用方按 --allow-unsigned 策略处置）。
ed25519_verify_sidecar() {
  local archive="$1" sig="$1.sig" pub_tmp=""
  [[ -f "$sig" ]] || return 2
  [[ -f "$archive" ]] || { log_err "签名旁车存在但包文件缺失: $archive"; return 1; }
  local pub="${WDSP_PACKAGE_PUBLIC_KEY:-}"
  if [[ -n "$pub" && "${WDSP_DEVELOPMENT_MODE:-0}" != "1" ]]; then
    log_err "生产验签拒绝 WDSP_PACKAGE_PUBLIC_KEY 覆盖固定信任根；仅 development 模式允许测试公钥"
    return 1
  fi
  if [[ -z "$pub" ]]; then
    [[ -n "${WDSP_RELEASE_PUBKEY_PEM:-}" ]] || { log_err "调用方未提供可信公钥（WDSP_RELEASE_PUBKEY_PEM 为空）"; return 1; }
    pub_tmp="$(mktemp "${TMPDIR:-/tmp}/jzpub.XXXXXX")"
    chmod 600 "$pub_tmp"
    printf '%s\n' "$WDSP_RELEASE_PUBKEY_PEM" > "$pub_tmp"
    pub="$pub_tmp"
  fi
  local rc=0
  ed25519_verify_file "$pub" "$archive" "$sig" || rc=$?
  [[ -n "$pub_tmp" ]] && rm -f "$pub_tmp"
  if [[ "$rc" -ne 0 ]]; then
    log_err "离线包 Ed25519 验签失败: ${archive}（包或签名被篡改/非官方签发）"
    return 1
  fi
  return 0
}
