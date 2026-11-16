#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CONFIG=${1:-"$ROOT/config.local.properties"}
if [[ ! -f "$CONFIG" ]]; then
  printf 'configuration not found: %s\n' "$CONFIG" >&2
  exit 2
fi
if [[ -z "${JIUZHANG_IDENTITY_SALT:-}" ]]; then
  printf 'JIUZHANG_IDENTITY_SALT is required (at least 32 random bytes)\n' >&2
  exit 2
fi
"$ROOT/scripts/build.sh" >/dev/null
exec java -jar "$ROOT/dist/jiuzhang-api-security.jar" "$CONFIG"
