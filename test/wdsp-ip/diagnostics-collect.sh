#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/wdsp-diagnostics-test.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin" "$TMP/out" "$TMP/unpacked"
printf '%s\n' 'APP_PASSWORD=super-secret' 'EXTRA_HOST=https://user:pass@example.test' > "$TMP/env"
printf '%s\n' 'services: {}' > "$TMP/compose.yml"

cat > "$TMP/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args="$*"
if [[ "$args" == *"--version"* ]]; then
  echo 'Docker version 28.0.0'
elif [[ "$args" == *"compose version"* ]]; then
  echo 'Docker Compose version v2.36.0'
elif [[ "$args" == *"logs"* ]]; then
  printf '%s\n' 'api | Authorization: Bearer original-token' 'api | Cookie: session=original-cookie' 'api | {"token":"original-json-token","request_body":"customer-body"}' 'api | -----BEGIN PRIVATE KEY-----' 'api | PRIVATE KEY DATA' 'api | -----END PRIVATE KEY-----'
elif [[ "$args" == *"system df"* ]]; then
  echo 'Images space usage: 0B'
else
  echo 'NAME IMAGE STATUS'
fi
EOF

cat > "$TMP/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '{"status":"ok","access_token":"original-health-token","response_body":"customer-response"}'
EOF
chmod +x "$TMP/bin/docker" "$TMP/bin/curl"

WDSP_RELEASE_ID='delivery-test/2026 09 07' PATH="$TMP/bin:$PATH" bash "$ROOT/ops/diagnostics/collect.sh" \
  --output "$TMP/out" \
  --compose-file "$TMP/compose.yml" \
  --env-file "$TMP/env" \
  --api-url 'http://127.0.0.1:18081' \
  --log-lines 2 >/dev/null

archive="$(find "$TMP/out" -type f -name 'diagnostics-*.tar.gz' -print -quit)"
[[ -n "$archive" ]]
tar -xzf "$archive" -C "$TMP/unpacked"

if rg -n --hidden --glob '!diagnostic-manifest.txt' \
  'super-secret|user:pass|original-token|original-cookie|original-json-token|customer-body|original-health-token|customer-response|PRIVATE KEY DATA' \
  "$TMP/unpacked"; then
  echo 'diagnostic package contains unredacted sensitive data' >&2
  exit 1
fi

test -s "$TMP/unpacked/diagnostic-manifest.txt"
rg -q 'policy_version=wdsp-diagnostics-v1' "$TMP/unpacked/diagnostic-manifest.txt"
rg -q '^release_id=delivery-test20260907$' "$TMP/unpacked/diagnostic-manifest.txt"
rg -q '^package_scope=customer_support_allowlist$' "$TMP/unpacked/diagnostic-manifest.txt"
rg -q '^private_debug_archive=not_in_customer_package$' "$TMP/unpacked/diagnostic-manifest.txt"
rg -q '\[REDACTED' "$TMP/unpacked/compose-logs.txt"
rg -q '\[REDACTED' "$TMP/unpacked/api-health.json"
echo 'diagnostics collect redaction test passed'
