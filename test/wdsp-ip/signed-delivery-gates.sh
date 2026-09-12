#!/usr/bin/env bash
# IP-01/IP-05/IP-09: exercise the formal signed-build path with ephemeral test material.
# This proves the signing/traceability mechanics only. It is not production key evidence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_SCRIPT="$REPO_ROOT/ops/offline-package/build.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-signed-gates.XXXXXX")"
trap 'rm -rf "$TMP_ROOT"' EXIT

require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "missing command: $1" >&2; exit 1; }; }
require_cmd openssl
require_cmd jq
require_cmd tar

private_key="$TMP_ROOT/ephemeral-ed25519.pem"
public_key="$TMP_ROOT/ephemeral-ed25519.pub.pem"
openssl genpkey -algorithm ED25519 -out "$private_key" >/dev/null 2>&1
openssl pkey -in "$private_key" -pubout -out "$public_key" >/dev/null 2>&1

output="$TMP_ROOT/output"
WDSP_SIGNING_KEY="$private_key" bash "$BUILD_SCRIPT" \
  --version 1.0.0 \
  --product wdsp \
  --arch amd64 \
  --skip-images \
  --output "$output" >"$TMP_ROOT/build.log" 2>&1

artifact="$output/jiuzhang-wdsp-offline-1.0.0-amd64.tar.gz"
artifact_sig="$artifact.sig"
traceability="$output/jiuzhang-wdsp-offline-1.0.0-amd64.traceability.json"
traceability_sig="$traceability.sig"
scan_report="$output/jiuzhang-wdsp-offline-1.0.0-amd64.scan.json"

test -s "$artifact"
test -s "$artifact_sig"
test -s "$traceability"
test -s "$traceability_sig"

verify_signature() {
  local input="$1" signature="$2" raw_sig
  raw_sig="$TMP_ROOT/$(basename "$signature").raw"
  openssl base64 -d -A -in "$signature" -out "$raw_sig" 2>/dev/null
  openssl pkeyutl -verify -pubin -inkey "$public_key" -rawin \
    -in "$input" -sigfile "$raw_sig" >/dev/null 2>&1
}

verify_signature "$artifact" "$artifact_sig"
verify_signature "$traceability" "$traceability_sig"

jq -e '
  .delivery_mode == "production" and
  .signed == true and
  .traceability.signature.signed == true and
  .traceability.signature.algorithm == "Ed25519" and
  (.traceability.release_id | length > 0) and
  (.traceability.build_commit | length > 0)
' <(tar -xOf "$artifact" '*/manifest.json') >/dev/null

jq -e '
  .result == "PASS" and
  (.input.sha256 | test("^[0-9a-f]{64}$")) and
  (.manifest.files_manifest_sha256 | test("^[0-9a-f]{64}$"))
' "$scan_report" >/dev/null

jq -e '
  .signature.signed == true and
  .signature.algorithm == "Ed25519" and
  (.artifact_digest | test("^[0-9a-f]{64}$")) and
  (.scan_report_digest | test("^[0-9a-f]{64}$"))
' "$traceability" >/dev/null

echo "signed delivery gates passed (ephemeral key; production trust-root evidence excluded)"
