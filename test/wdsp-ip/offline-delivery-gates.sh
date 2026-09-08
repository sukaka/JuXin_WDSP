#!/usr/bin/env bash
# IP-01/IP-02/IP-05: verify the offline delivery mode boundary and traceability sidecar.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_SCRIPT="$REPO_ROOT/ops/offline-package/build.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-delivery-gates.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

formal_log="$TMP_ROOT/formal.log"
formal_output="$TMP_ROOT/formal-output"
if env -u WDSP_SIGNING_KEY bash "$BUILD_SCRIPT" \
  --version 1.0.0 \
  --product wdsp \
  --arch amd64 \
  --skip-images \
  --output "$formal_output" >"$formal_log" 2>&1; then
  echo "formal build unexpectedly succeeded without WDSP_SIGNING_KEY" >&2
  exit 1
fi
grep -Fq "正式离线包必须签名" "$formal_log"

development_output="$TMP_ROOT/development-output"
env -u WDSP_SIGNING_KEY bash "$BUILD_SCRIPT" \
  --version 1.0.0 \
  --product wdsp \
  --arch amd64 \
  --development \
  --skip-images \
  --output "$development_output" >"$TMP_ROOT/development.log" 2>&1

artifact="$development_output/jiuzhang-wdsp-offline-1.0.0-amd64.tar.gz"
traceability="$development_output/jiuzhang-wdsp-offline-1.0.0-amd64.traceability.json"
scan_report="$development_output/jiuzhang-wdsp-offline-1.0.0-amd64.scan.json"
test -f "$artifact"
test -f "$traceability"
test -f "$scan_report"
test ! -e "$artifact.sig"

jq -e '
  .delivery_mode == "development" and
  .traceability.product_line == "wdsp" and
  .traceability.protection_form == "STANDARD_OFFLINE" and
  (.traceability.release_id | length > 0) and
  (.traceability.build_commit | length > 0) and
  (.traceability.delivery_id | length > 0) and
  (.traceability.hardware_requirements | type == "array") and
  .traceability.digest_binding.artifact_digest_scope == "external-final-archive" and
  .traceability.digest_binding.scan_report_digest_scope == "external-scan-report" and
  .traceability.signature.signed == false
' <(tar -xOf "$artifact" '*/manifest.json') >/dev/null

jq -e '
  .result == "PASS" and
  (.input.sha256 | test("^[0-9a-f]{64}$")) and
  (.manifest.sha256 | test("^[0-9a-f]{64}$")) and
  (.manifest.files_manifest_sha256 | test("^[0-9a-f]{64}$"))
' "$scan_report" >/dev/null

jq -e '
  (.artifact_digest | test("^[0-9a-f]{64}$")) and
  (.scan_report_digest | test("^[0-9a-f]{64}$")) and
  (.manifest_sha256 | test("^[0-9a-f]{64}$")) and
  (.files_manifest_sha256 | test("^[0-9a-f]{64}$")) and
  .signature.signed == false
' "$traceability" >/dev/null

mkdir -p "$TMP_ROOT/extracted"
tar -xzf "$artifact" -C "$TMP_ROOT/extracted"
gateway_archive="$TMP_ROOT/gateway-linux-amd64.tar.gz"
cp "$TMP_ROOT/extracted/jiuzhang-wdsp-offline-1.0.0-amd64/gateway-linux-amd64.tar.gz" "$gateway_archive"
test "$(tar -xOf "$gateway_archive" '*/delivery_mode')" = "development"
tar -xOf "$gateway_archive" '*/sha256sums' | grep -Eq '^[0-9a-f]{64}[[:space:]]+delivery_mode$'

bash -n "$BUILD_SCRIPT" "$REPO_ROOT/ops/offline-package/build-all.sh" \
  "$REPO_ROOT/ops/install/install-gateway-baremetal.sh"
echo "offline delivery gates passed (formal fail-closed + development traceability)"
