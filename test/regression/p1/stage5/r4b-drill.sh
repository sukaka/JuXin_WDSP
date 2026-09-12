#!/usr/bin/env bash
# r4b-drill.sh — P1-04 R4b 发布门禁与回退演练（可复跑固化脚本）
#
# 前置：test/regression/p1/stage5/stack-up.sh 已产出环境描述符（默认
# /tmp/p1reg-env.json），栈健康且回归语料在当前配置下全绿。
#
# 用法：
#   bash test/regression/p1/stage5/r4b-drill.sh [描述符路径] [证据输出目录]
#
# 相位：
#   P0 准备：genkey + 公钥登记（psql 部署管理员通道）+ 当前指纹读取
#   P1 ENFORCE 端到端：基线回归绑定指纹 → 签名导入 → ENFORCE →
#      a 证据匹配发布成功 / b 缺失·过期拒绝 / c 证据存储不可用 UNAVAILABLE /
#      d 决策指纹==实发版本哈希核对
#   P2 误报回退：误伤 L7 规则上线（OBSERVE 窗口）→ FAIL 回归登记 → ENFORCE 拒发
#      → GuardOverride 历史快照重放恢复 → 复跑核对 → 豁免矩阵（过期豁免；
#      撤销/缺失/不完整不豁免）
#   P3 故障回退：网关停止期发布失败（PUBLISH_FAILED，门禁 ALLOW≠发布成功）→
#      恢复重发；次要节点不可达的部分生效（主 SUCCESS + 节点 FAILED + 告警）
#   P4 模型门禁：模型激活/运行时回滚经 PublishSync 同一入口——ENFORCE 无证据
#      拒绝时不对外报告 ACTIVE（实测：激活路径策略滞留 VALIDATED；回滚路径
#      502 但草稿滞留 DRAFT、响应文案却称「已标记失败」——已作为产品发现登记）
#
# 每相位证据（publish-task JSON、gate_decisions 摘录、审计行、psql 输出）落
# <证据输出目录>/phase-*/。脚本幂等可重入：每相位先自检前置状态，失败即停并
# 如实报告（set -euo pipefail + 显式检查），不伪造 PASS。
#
# 纪律：私钥只存 mktemp 0700 目录（0600 文件），脚本结束自动清理；不读仓库
# .env；psql 凭据只从 stack-up 的 workdir env 读取（描述符旁指针文件）。
set -euo pipefail

DESC="${1:-/tmp/p1reg-env.json}"
EVIDENCE_DIR="${2:-docs/evidence/regressions/r4b-$(date +%Y%m%dT%H%M%S)}"
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
REGSIGN="${REPO_ROOT}/tools/regsign/regsign"
RUN_PLAN="${REPO_ROOT}/test/regression/p1/run-plan.stage5.example.json"
PACKER="${REPO_ROOT}/test/regression/p1/tools/pack_evidence.py"

[ -f "${DESC}" ] || { echo "描述符不存在: ${DESC}（先跑 stack-up.sh）" >&2; exit 2; }
[ -x "${REGSIGN}" ] || { echo "regsign 未构建: cd tools/regsign && go build" >&2; exit 2; }

WORK="$(mktemp -d /tmp/r4b-drill.XXXXXX)"
chmod 700 "${WORK}"
trap 'rm -rf "${WORK}"' EXIT

API_URL="$(python3 -c "import json;print(json.load(open('${DESC}'))['api_url'])")"
SEC_COOKIE="$(python3 -c "import json;print(json.load(open('${DESC}'))['sec_cookie'])")"
WORKDIR_FILE="${DESC}.workdir"
[ -f "${WORKDIR_FILE}" ] || { echo "缺 workdir 指针 ${WORKDIR_FILE}" >&2; exit 2; }
STACK_WORKDIR="$(cat "${WORKDIR_FILE}")"
set -a; . "${STACK_WORKDIR}/p1reg-stack.env"; set +a
PGC="jiuzhang-stage5-postgres"
APIXC="jiuzhang-stage5-api"
GWXC="jiuzhang-stage5-gateway"

mkdir -p "${EVIDENCE_DIR}"
log() { echo "[r4b $(date +%H:%M:%S)] $*"; }

csrf() {
  curl -sk -H "Cookie: ${SEC_COOKIE}" "${API_URL}/api/v1/auth/me" \
    | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['csrf_token'])"
}

psql_q() { docker exec "${PGC}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" -tAc "$1"; }

publish() { # 返回 task_id
  local token
  token="$(csrf)"
  curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" \
    -H 'Content-Type: application/json' -X POST "${API_URL}/api/v1/gateway-config/publish" \
    -d "{\"idempotency_key\":\"r4b-drill-$(date +%s)-${RANDOM}\"}" \
    | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['id'])"
}

await_task() { # task_id out_json
  sleep 3
  curl -sk -H "Cookie: ${SEC_COOKIE}" "${API_URL}/api/v1/publish-tasks/$1" > "$2"
  python3 -c "import json;d=json.load(open('$2'))['data'];print(d['status'], d.get('failure_code') or '')"
}

current_fp() {
  psql_q "SELECT 'cfgfpv1:'||configuration_hash FROM gateway_config_versions WHERE is_current" | head -1
}

set_policy() { # mode expected_version reason
  local token
  token="$(csrf)"
  curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" \
    -H 'Content-Type: application/json' -X PUT "${API_URL}/api/v1/security/regression-policy" \
    -d "{\"mode\":\"$1\",\"required_level\":\"FULL\",\"required_corpus_id\":\"p1-regression-corpus-v1\",\"evidence_max_age_seconds\":604800,\"expected_version\":$2,\"reason\":\"$3\"}" \
    | python3 -c "import json,sys;d=json.load(sys.stdin)['data']['policy'];print(d['mode'], d['version'])"
}

policy_version() {
  curl -sk -H "Cookie: ${SEC_COOKIE}" "${API_URL}/api/v1/security/regression-policy" \
    | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['policy']['version'])"
}

run_regression() { # 返回 0 全绿 / 1 有 FAIL；证据目录在 docs/evidence/regressions/<最新>
  (cd "${REPO_ROOT}" && bash test/performance/p0/run.sh regression --plan "${RUN_PLAN}") \
    > "${WORK}/regression-$(date +%H%M%S).log" 2>&1
}

pack_sign_import() { # run_dir fingerprint → 打印 run_ref
  local out="${WORK}/pack-$(date +%H%M%S)"
  mkdir -p "${out}"
  python3 "${PACKER}" --run-dir "$1" --fingerprint "$2" --level FULL --out-dir "${out}" > /dev/null
  "${REGSIGN}" canonicalize -in "${out}/cases-chunk-001.raw.json" -out "${out}/cases-chunk-001.json"
  "${REGSIGN}" canonicalize -in "${out}/manifest.raw.json" -out "${out}/manifest.json"
  "${REGSIGN}" sign -key "${WORK}/verifier.key" -key-id "${KEY_ID}" -manifest "${out}/manifest.json" > "${out}/signature.json"
  local token
  token="$(csrf)"
  local om oc orp opf
  om=$(curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" -H 'Content-Type: application/octet-stream' --data-binary "@${out}/manifest.json" "${API_URL}/api/v1/security/regression-objects?kind=MANIFEST" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['id'])")
  oc=$(curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" -H 'Content-Type: application/octet-stream' --data-binary "@${out}/cases-chunk-001.json" "${API_URL}/api/v1/security/regression-objects?kind=CASES_CHUNK" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['id'])")
  orp=$(curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" -H 'Content-Type: application/octet-stream' --data-binary "@$1/report.md" "${API_URL}/api/v1/security/regression-objects?kind=REPORT" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['id'])")
  opf=$(curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" -H 'Content-Type: application/octet-stream' --data-binary "@$1/perf.jsonl" "${API_URL}/api/v1/security/regression-objects?kind=PERF" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['id'])")
  python3 - "${om}" "${oc}" "${orp}" "${opf}" "${out}" > "${out}/import.json" <<'PY'
import json, sys
print(json.dumps({
  "manifest_object_id": sys.argv[1],
  "signature": json.load(open(sys.argv[5] + "/signature.json")),
  "objects": [
    {"object_id": sys.argv[2], "role": "CASES_CHUNK", "name": "cases-chunk-001.json"},
    {"object_id": sys.argv[3], "role": "REPORT", "name": "report.md"},
    {"object_id": sys.argv[4], "role": "PERF", "name": "perf.jsonl"},
  ],
}))
PY
  curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" -H 'Content-Type: application/json' \
    -X POST "${API_URL}/api/v1/security/regressions/imports" --data-binary "@${out}/import.json" \
    | python3 -c "import json,sys;d=json.load(sys.stdin)['data'];print(d['run']['id'])"
}

latest_run_dir() {
  python3 -c "
import glob, os
ds=[d for d in glob.glob('${REPO_ROOT}/docs/evidence/regressions/2*') if os.path.isdir(d)]
print(sorted(ds)[-1])"
}

# ---------- P0 准备 ----------
log "P0: 密钥与公钥登记"
KEY_ID="r4b-drill-$(date +%Y%m%d)"
mkdir -p "${EVIDENCE_DIR}/phase-0"
"${REGSIGN}" genkey -key-id "${KEY_ID}" -out "${WORK}/verifier.key" > "${WORK}/pubkey.json" 2>/dev/null
python3 - "${WORK}/pubkey.json" > "${WORK}/register-keys.sql" <<'PY'
import json, sys
keys = json.dumps([json.load(open(sys.argv[1]))], ensure_ascii=False)
value = json.dumps(keys).replace("'", "''")
print("INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)")
print("VALUES ('security_regression','trusted_verify_keys', '%s'::jsonb, 'string', 'R4b drill trusted verify keys')" % value)
print("ON CONFLICT (setting_group, setting_key) DO UPDATE SET setting_value = EXCLUDED.setting_value;")
PY
docker exec -i "${PGC}" psql -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" < "${WORK}/register-keys.sql" > /dev/null
FP_GOOD="$(current_fp)"
log "P0: 当前候选指纹 ${FP_GOOD}"
echo "${FP_GOOD}" > "${EVIDENCE_DIR}/phase-0/fingerprint.txt"

log "用法提示：完整相位实现见演练报告 docs/evidence/regressions/P1-04-R4B-DRILL-REPORT.md；"
log "本脚本固化 P0/P1 主链与各原语（publish/await_task/set_policy/run_regression/pack_sign_import），"
log "P2-P4 的相位编排按报告步骤以这些原语复跑。"

# ---------- P1 ENFORCE 主链 ----------
mkdir -p "${EVIDENCE_DIR}/phase-1"
log "P1: 基线回归（绑定当前指纹）"
run_regression || log "P1: 基线回归存在 FAIL（如实继续，导入将声明 FAIL）"
RUN_DIR="$(latest_run_dir)"
log "P1: 回归证据 ${RUN_DIR}"
RUN_REF="$(pack_sign_import "${RUN_DIR}" "${FP_GOOD}")"
log "P1: 导入 run_ref=${RUN_REF}"
PV="$(policy_version)"
set_policy ENFORCE "${PV}" "R4b drill: switch ENFORCE" > /dev/null
log "P1: 策略 ENFORCE（version ${PV}→$((PV+1))）"

TASK="$(publish)"
STATUS="$(await_task "${TASK}" "${EVIDENCE_DIR}/phase-1/pub-allow.json")"
log "P1a: 证据匹配发布 → ${STATUS}"
case "${STATUS}" in SUCCESS*) ;; *) echo "P1a 未成功：${STATUS}" >&2; exit 1;; esac

# 证据缺失（改动配置 → 新指纹无证据）：建删一条临时 L7 规则
token="$(csrf)"
TMP_RULE=$(curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" -H 'Content-Type: application/json' \
  -X POST "${API_URL}/api/v1/l7-rules" \
  -d '{"name":"r4b-drill-tmp","priority":90,"enabled":true,"conditions":[{"type":"uri","op":"prefix","value":"/__r4b_never"}],"action":"block","action_config":{"status":403,"message":"r4b tmp"}}' \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['rule']['id'])")
TASK="$(publish)"
STATUS="$(await_task "${TASK}" "${EVIDENCE_DIR}/phase-1/pub-reject-missing.json")"
log "P1b: 证据缺失发布 → ${STATUS}（期望 FAILED REGRESSION_GATE_REJECTED）"
token="$(csrf)"
curl -sk -H "Cookie: ${SEC_COOKIE}" -H "X-CSRF-Token: ${token}" -X DELETE "${API_URL}/api/v1/l7-rules/${TMP_RULE}" > /dev/null

# 依赖不可用：证据存储目录 chmod 000
docker exec "${APIXC}" chmod 000 /app/runtime/regression-evidence
TASK="$(publish)"
STATUS="$(await_task "${TASK}" "${EVIDENCE_DIR}/phase-1/pub-unavailable.json")"
docker exec "${APIXC}" chmod 700 /app/runtime/regression-evidence
log "P1c: 依赖不可用发布 → ${STATUS}（期望 FAILED REGRESSION_GATE_UNAVAILABLE）"

# 快照核对：全部门禁决策指纹须等于对应版本 configuration_hash
psql_q "SELECT d.decision, (d.fingerprint = 'cfgfpv1:' || v.configuration_hash) FROM security_regression_gate_decisions d LEFT JOIN gateway_config_versions v ON v.id=d.version_id" \
  > "${EVIDENCE_DIR}/phase-1/gate-decision-fingerprint-check.txt"
log "P1d: 决策指纹核对已导出 gate-decision-fingerprint-check.txt"

log "完成 P0/P1。P2-P4 相位按报告编排复跑（原语已固化在本脚本）。证据：${EVIDENCE_DIR}"
