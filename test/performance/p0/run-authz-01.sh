#!/usr/bin/env bash
set -euo pipefail

# AUTHZ-01 P0-02 component runner.
#
# The default local mode is a reproducible Go microbenchmark only. It reports
# raw -count samples plus nearest-rank P50/P95/P99, reciprocal throughput, and
# allocation metrics; it makes no gateway capacity or soak claim. Formal mode
# requires an operator-provided dedicated environment assertion and plan, and
# is BLOCKED when either is absent.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
p0_dir="$repo_root/test/performance/p0"
module_dir="$repo_root/gateway/dynamic_security"
bench_mode=${AUTHZ_BENCH_MODE:-local}
bench_time=${AUTHZ_BENCHTIME:-1s}
bench_count=${AUTHZ_BENCHCOUNT:-5}
output_dir=${AUTHZ_BENCH_OUTPUT_DIR:-"${TMPDIR:-/tmp}/authz-01-$(date +%Y%m%dT%H%M%S)"}
raw_output="$output_dir/go-benchmark.txt"
report_output="$output_dir/go-benchmark.json"

case "$bench_mode" in
  local)
    report_status=LOCAL_ONLY
    report_scope=authz-01-local-microbenchmark
    report_reason=LOCAL_SHORT_TEST_ONLY
    ;;
  formal)
    report_status=FORMAL_COMPONENT
    report_scope=authz-01-formal-microbenchmark-component
    report_reason=FORMAL_ENVIRONMENT_ASSERTED
    if [[ "${AUTHZ_FORMAL_ENVIRONMENT_READY:-0}" != "1" || -z "${AUTHZ_FORMAL_ENV_ID:-}" ]]; then
      report_status=BLOCKED
      report_reason=ENVIRONMENT_UNAVAILABLE
    elif [[ -z "${AUTHZ_FORMAL_PLAN:-}" || ! -f "${AUTHZ_FORMAL_PLAN}" ]]; then
      report_status=BLOCKED
      report_reason=FORMAL_PLAN_MISSING
    fi
    ;;
  *)
    echo "[authz-01] invalid AUTHZ_BENCH_MODE=$bench_mode (expected local or formal)" >&2
    exit 2
    ;;
esac

mkdir -p "$output_dir"

if [[ "$report_status" == "BLOCKED" ]]; then
  PYTHONPATH="$p0_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m p0bench.go_bench \
    --output "$report_output" --status BLOCKED --scope "$report_scope" \
    --reason "$report_reason" --environment-id "${AUTHZ_FORMAL_ENV_ID:-}" \
    --formal-plan "${AUTHZ_FORMAL_PLAN:-}" --relation-count 200000
  echo "[authz-01] status=BLOCKED reason=$report_reason report=$report_output"
  exit 3
fi

cd "$module_dir"

echo "[authz-01] decision matrix"
go test ./detectors -run '^TestEvaluateAuthorizationDecisionMatrix$' -count=1

echo "[authz-01] raw Go benchmark (200k relation pair; count=$bench_count, benchtime=$bench_time)"
go test ./detectors -run '^$' -bench '^BenchmarkEvaluateAuthorization(AuthzPair|Paired)$' \
  -benchmem -benchtime="$bench_time" -count="$bench_count" >"$raw_output" 2>&1
cat "$raw_output"

report_args=(
  --input "$raw_output" --output "$report_output" --status "$report_status"
  --scope "$report_scope" --reason "$report_reason"
  --environment-id "${AUTHZ_FORMAL_ENV_ID:-}" --formal-plan "${AUTHZ_FORMAL_PLAN:-}"
  --relation-count 200000
)
race_status=NOT_RUN
race_reason=RACE_NOT_REQUESTED
race_rc=0
if [[ "${AUTHZ_RACE:-0}" == "1" ]]; then
  echo "[authz-01] race acceptance (decision matrix)"
  if go test -race ./detectors -run '^TestEvaluateAuthorizationDecisionMatrix$' -count=1; then
    race_status=PASS
    race_reason=RACE_DECISION_MATRIX_PASS
  else
    race_rc=$?
    [[ "$race_rc" -eq 0 ]] && race_rc=1
    race_status=FAIL
    race_reason=RACE_DECISION_MATRIX_FAILED
  fi
fi
report_args+=(--race-status "$race_status" --race-reason "$race_reason")
if [[ -n "${AUTHZ_MAX_P95_DELTA_MS:-}" ]]; then
  report_args+=(--max-p95-delta-ms "$AUTHZ_MAX_P95_DELTA_MS")
fi
report_rc=0
PYTHONPATH="$p0_dir${PYTHONPATH:+:$PYTHONPATH}" python3 -m p0bench.go_bench "${report_args[@]}" || report_rc=$?

echo "[authz-01] status=$report_status report=$report_output raw=$raw_output"
[[ "$report_rc" -eq 0 ]] || exit "$report_rc"
[[ "$race_rc" -eq 0 ]] || exit "$race_rc"
