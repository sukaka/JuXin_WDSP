#!/usr/bin/env bash
# AUTHZ-01 真实 Provider E2E 环境门禁回归。
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_SCRIPT="$SCRIPT_DIR/authz-cross-module-contract.sh"

assert_blocked() {
  local label="$1"
  shift
  local output status
  set +e
  output="$(AUTHZ_REQUIRE_REAL_PROVIDER=1 "$@" "$CONTRACT_SCRIPT" 2>&1)"
  status=$?
  set -e
  if [[ "$status" -ne 3 ]]; then
    echo "${label}: expected exit 3, got ${status}" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  case "$output" in
    *"AUTHZ-01 real Provider E2E: BLOCKED/ENVIRONMENT_UNAVAILABLE"*) ;;
    *)
      echo "${label}: missing BLOCKED/ENVIRONMENT_UNAVAILABLE output" >&2
      printf '%s\n' "$output" >&2
      exit 1
      ;;
  esac
}

assert_blocked "invalid Provider address" env AUTHZ_REAL_PROVIDER_ADDR="invalid"

echo "AUTHZ-01 real Provider environment gate: PASS"
