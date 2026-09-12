#!/usr/bin/env bash
# EXC-15 迁移试运行：000130/000131/000132 up+down 在含历史脏数据的库上验证。
# 任务书 docs/tasks/wdsp-p0/P0-04_DECISION_SCOPED_EXCEPTIONS.md 验收要求「迁移试运行报告」。
#
# 流程：
#   1. 在一次性测试 PG 容器建独立 scratch 库（不碰 jiuzhang_waf_test）
#   2. 依序应用 000001..000129（回到 000130 之前的旧 schema）
#   3. 插入 6 条历史例外脏数据（GLOBAL / LOG_ONLY / 空规则 / 绑定缺失 / 合法 / 已删除）
#   4. 应用 000130 up → 校验 NEEDS_REVIEW 标记与 unsupported_reasons 文案
#   5. 应用 000131/000132 up → 校验 final_decision 列（含 security_events 分区级联）
#   6. 依次 down 132/131/130 → 校验列消失、历史行数据完好（回退无损）
#   7. 再次 up 130/131/132（幂等性：IF NOT EXISTS 重跑不报错），结束后 drop scratch 库
#
# 用法：bash exc15-migration-trial.sh <日志输出路径>
# 环境：PG_CONTAINER（默认 p0s3-pg）/ PGUSER / PGPASS（容器内 psql 本地 trust 免密时忽略）
set -euo pipefail

LOG="${1:?usage: $0 <log-file>}"
PG_CONTAINER="${PG_CONTAINER:-p0s3-pg}"
PGUSER="${PGUSER:-jiuzhang}"
TRIAL_DB="p0s4_mig_trial"
# 脚本位于 docs/evidence/releases/<pkg>/artifacts/，向上五级为仓库根
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../../.." && pwd)"
MIG_DIR="$REPO_ROOT/server/migrations"

psqlc() { local db="$1"; shift; docker exec -i "$PG_CONTAINER" psql -U "$PGUSER" -d "$db" -v ON_ERROR_STOP=1 "$@"; }
psqlf() { docker exec -i "$PG_CONTAINER" psql -U "$PGUSER" -d "$TRIAL_DB" -v ON_ERROR_STOP=1 -q < "$1"; }
psqlq() { docker exec -i "$PG_CONTAINER" psql -U "$PGUSER" -d "$TRIAL_DB" -v ON_ERROR_STOP=1 -At -c "$1"; }

CHECKS=0; FAILED=0
check() { # <名称> <实际> <期望子串>
  CHECKS=$((CHECKS+1))
  if echo "$2" | grep -qF "$3"; then
    echo "PASS  $1 (=$2)"
  else
    FAILED=$((FAILED+1)); echo "FAIL  $1 (实际='$2' 期望含='$3')"
  fi
}

{
echo "============================================================"
echo "EXC-15 迁移试运行  $(date '+%F %T %z')"
echo "目标容器 $PG_CONTAINER  库 $TRIAL_DB  迁移目录 $MIG_DIR"
echo "============================================================"

echo "[setup] 重建 scratch 库 $TRIAL_DB"
psqlc postgres -q -c "DROP DATABASE IF EXISTS $TRIAL_DB;" -c "CREATE DATABASE $TRIAL_DB;"

echo "[up] 应用 000001..000129（旧 schema）"
for f in "$MIG_DIR"/000*.up.sql; do
  v="$(basename "$f" | cut -c1-6)"
  [ "$v" -le 129 ] || break
  psqlf "$f" >/dev/null
done
check "旧 schema 无 validation_status 列" \
  "$(psqlq "SELECT count(*) FROM information_schema.columns WHERE table_name='exception_policies' AND column_name='validation_status'")" "0"

echo "[seed] 插入 6 条历史例外脏数据"
docker exec -i "$PG_CONTAINER" psql -U "$PGUSER" -d "$TRIAL_DB" -v ON_ERROR_STOP=1 -q <<'SQL'
INSERT INTO exception_policies (name, scope_type, application_id, exception_action, rule_ids, rule_tags, methods, uri_prefix, status) VALUES
 ('E1-global',      'GLOBAL',      NULL, 'REMOVE_RULE', '[942100]', '[]', '["GET"]',  '/api', 'ENABLED'),
 ('E2-logonly',     'APPLICATION', gen_random_uuid(), 'LOG_ONLY',   '[942100]', '[]', '["GET"]',  '/api', 'ENABLED'),
 ('E3-norules',     'APPLICATION', gen_random_uuid(), 'REMOVE_RULE', '[]',      '[]', '["GET"]',  '/api', 'ENABLED'),
 ('E4-nobinding',   'APPLICATION', NULL, 'REMOVE_RULE', '[942100]', '[]', '["POST"]', '/pay', 'DISABLED'),
 ('E5-valid',       'APPLICATION', gen_random_uuid(), 'REMOVE_RULE', '[942100]', '[]', '["POST"]','/api', 'ENABLED'),
 ('E6-deleted',     'GLOBAL',      NULL, 'LOG_ONLY',    '[]',       '[]', '[]',       '',     'ENABLED');
UPDATE exception_policies SET deleted_at = now() WHERE name = 'E6-deleted';
SQL
check "脏数据行数" "$(psqlq "SELECT count(*) FROM exception_policies")" "6"

echo "[up] 应用 000130（例外范围契约扩展列 + 历史标记）"
psqlf "$MIG_DIR/000130_exception_scope_contract.up.sql" >/dev/null

check "E1 GLOBAL → NEEDS_REVIEW" \
  "$(psqlq "SELECT validation_status FROM exception_policies WHERE name='E1-global'")" "NEEDS_REVIEW"
check "E1 原因含 GLOBAL 文案" \
  "$(psqlq "SELECT unsupported_reasons::text FROM exception_policies WHERE name='E1-global'")" "GLOBAL"
check "E2 LOG_ONLY → NEEDS_REVIEW" \
  "$(psqlq "SELECT validation_status FROM exception_policies WHERE name='E2-logonly'")" "NEEDS_REVIEW"
check "E2 原因含仅观察文案" \
  "$(psqlq "SELECT unsupported_reasons::text FROM exception_policies WHERE name='E2-logonly'")" "仅观察"
check "E3 空规则 → NEEDS_REVIEW" \
  "$(psqlq "SELECT validation_status FROM exception_policies WHERE name='E3-norules'")" "NEEDS_REVIEW"
check "E3 原因含缺少目标规则文案" \
  "$(psqlq "SELECT unsupported_reasons::text FROM exception_policies WHERE name='E3-norules'")" "缺少目标规则"
check "E4 绑定缺失 → NEEDS_REVIEW" \
  "$(psqlq "SELECT validation_status FROM exception_policies WHERE name='E4-nobinding'")" "NEEDS_REVIEW"
check "E5 合法 → 保持 VALID" \
  "$(psqlq "SELECT validation_status FROM exception_policies WHERE name='E5-valid'")" "VALID"
check "E5 无 unsupported_reasons" \
  "$(psqlq "SELECT unsupported_reasons::text FROM exception_policies WHERE name='E5-valid'")" "[]"
check "E6 已删除 → 不标记（保持 VALID）" \
  "$(psqlq "SELECT validation_status FROM exception_policies WHERE name='E6-deleted'")" "VALID"
check "标记不改 status 本身（E2 仍 ENABLED）" \
  "$(psqlq "SELECT status FROM exception_policies WHERE name='E2-logonly'")" "ENABLED"
check "新增列默认值 target_engine=WAF" \
  "$(psqlq "SELECT DISTINCT target_engine FROM exception_policies")" "WAF"

echo "[up] 应用 000131/000132（final_decision 列）"
psqlf "$MIG_DIR/000131_api_runtime_events_final_decision.up.sql" >/dev/null
psqlf "$MIG_DIR/000132_security_events_final_decision.up.sql" >/dev/null
check "api_runtime_events.final_decision 存在" \
  "$(psqlq "SELECT count(*) FROM information_schema.columns WHERE table_name='api_runtime_events' AND column_name='final_decision'")" "1"
check "security_events.final_decision 存在" \
  "$(psqlq "SELECT count(*) FROM information_schema.columns WHERE table_name='security_events' AND column_name='final_decision'")" "1"
PART="$(psqlq "SELECT inhrelid::regclass::text FROM pg_inherits WHERE inhparent='security_events'::regclass LIMIT 1" 2>/dev/null || true)"
if [ -n "$PART" ]; then
  check "分区级联：$PART.final_decision 存在" \
    "$(psqlq "SELECT count(*) FROM information_schema.columns WHERE table_name='$(echo "$PART" | tr -d '\"')' AND column_name='final_decision'")" "1"
else
  echo "SKIP  分区级联（security_events 当前无分区——空库为预期）"
fi

echo "[down] 依次回退 000132/000131/000130"
psqlf "$MIG_DIR/000132_security_events_final_decision.down.sql" >/dev/null
psqlf "$MIG_DIR/000131_api_runtime_events_final_decision.down.sql" >/dev/null
psqlf "$MIG_DIR/000130_exception_scope_contract.down.sql" >/dev/null
check "down 后 final_decision 列消失（api_runtime_events）" \
  "$(psqlq "SELECT count(*) FROM information_schema.columns WHERE table_name='api_runtime_events' AND column_name='final_decision'")" "0"
check "down 后 final_decision 列消失（security_events）" \
  "$(psqlq "SELECT count(*) FROM information_schema.columns WHERE table_name='security_events' AND column_name='final_decision'")" "0"
check "down 后 exception_policies 扩展列消失" \
  "$(psqlq "SELECT count(*) FROM information_schema.columns WHERE table_name='exception_policies' AND column_name IN ('target_engine','api_rule_refs','resolved_rule_ids','source_event_id','validation_status','compiled_fingerprint','unsupported_reasons')")" "0"
check "down 后历史行完好（6 行）" \
  "$(psqlq "SELECT count(*) FROM exception_policies")" "6"
check "down 后历史数据原值（E2 仍 LOG_ONLY/ENABLED）" \
  "$(psqlq "SELECT exception_action||'/'||status FROM exception_policies WHERE name='E2-logonly'")" "LOG_ONLY/ENABLED"

echo "[up] 重跑 000130/000131/000132（幂等性：IF NOT EXISTS）"
psqlf "$MIG_DIR/000130_exception_scope_contract.up.sql" >/dev/null
psqlf "$MIG_DIR/000131_api_runtime_events_final_decision.up.sql" >/dev/null
psqlf "$MIG_DIR/000132_security_events_final_decision.up.sql" >/dev/null
check "重跑后历史脏数据再次被标记（E1 NEEDS_REVIEW）" \
  "$(psqlq "SELECT validation_status FROM exception_policies WHERE name='E1-global'")" "NEEDS_REVIEW"

echo "[cleanup] drop scratch 库"
psqlc postgres -q -c "DROP DATABASE IF EXISTS $TRIAL_DB;"

echo "============================================================"
echo "EXC-15 迁移试运行汇总: 检查 $CHECKS 失败 $FAILED"
echo "============================================================"
} 2>&1 | tee "$LOG"

[ "$FAILED" -eq 0 ]
