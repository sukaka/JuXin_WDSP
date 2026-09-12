#!/usr/bin/env bash
# AT-12: an attacker-controlled package, signing key and public key cannot
# replace the fixed release trust root used by the official installer.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_SCRIPT="$REPO_ROOT/ops/install/install.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-attacker-package.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

ATTACK_DIR="$TMP_ROOT/attacker-release"
ATTACK_ARCHIVE="$ATTACK_DIR.tar.gz"
ATTACK_KEY="$TMP_ROOT/attacker-ed25519.key"
ATTACK_PUB="$TMP_ROOT/attacker-ed25519.pub"
mkdir -p "$ATTACK_DIR/ops/lib" "$ATTACK_DIR/ops/offline-package"

# The archive deliberately includes the attacker's verification script and
# public key.  The trusted installer must source neither of them.
printf '%s\n' '{"delivery_mode":"production","arch":"arm64"}' > "$ATTACK_DIR/manifest.json"
printf '%s\n' '# attacker-controlled verifier: must never be sourced by the official installer' \
  'ed25519_verify_sidecar() { return 0; }' > "$ATTACK_DIR/ops/lib/signing.sh"
openssl genpkey -algorithm ED25519 -out "$ATTACK_KEY" >/dev/null 2>&1
openssl pkey -in "$ATTACK_KEY" -pubout -out "$ATTACK_PUB" >/dev/null 2>&1
cp "$ATTACK_PUB" "$ATTACK_DIR/ops/offline-package/release-signing.pub"
tar -C "$ATTACK_DIR" -czf "$ATTACK_ARCHIVE" manifest.json ops
openssl pkeyutl -sign -inkey "$ATTACK_KEY" -rawin -in "$ATTACK_ARCHIVE" \
  -out "$TMP_ROOT/attacker.sig.raw" >/dev/null 2>&1
base64 < "$TMP_ROOT/attacker.sig.raw" > "$ATTACK_ARCHIVE.sig"

expect_rejection() {
  local name="$1"
  local expected="$2"
  local log="$TMP_ROOT/${name}.log"
  shift 2
  if (cd "$ATTACK_DIR" && "$@") >"$log" 2>&1; then
    echo "${name}: attacker package was unexpectedly accepted" >&2
    exit 1
  fi
  grep -Fq -- "$expected" "$log" || {
    echo "${name}: expected rejection message was not emitted" >&2
    exit 1
  }
}

# A public key shipped inside the package cannot make its own signature trusted.
expect_rejection embedded-key-ignored "离线包验签失败" \
  env -u WDSP_PACKAGE_PUBLIC_KEY bash "$INSTALL_SCRIPT" --no-firewall --skip-accounts

# Production explicitly rejects an environment attempt to replace the root too.
expect_rejection environment-key-rejected "生产验签拒绝 WDSP_PACKAGE_PUBLIC_KEY 覆盖固定信任根" \
  env WDSP_PACKAGE_PUBLIC_KEY="$ATTACK_PUB" bash "$INSTALL_SCRIPT" --no-firewall --skip-accounts

# The development escape hatch cannot downgrade an attacker-marked production package.
expect_rejection production-no-unsigned-bypass "--allow-unsigned 仅允许 manifest.delivery_mode=development" \
  env -u WDSP_PACKAGE_PUBLIC_KEY bash "$INSTALL_SCRIPT" --allow-unsigned --no-firewall --skip-accounts

echo "attacker package gate passed (fixed root + no production unsigned bypass)"
