#!/usr/bin/env bash
# 九章 CUSTOM_PACK 二次阻断评估（post-contrib blocking）集成验证
#
# 背景：CRS 阻断评估 REQUEST-949 位于 crs/rules/ 内部，晚于它加载的
# contrib 规则包 / 插件 after / 管理面自定义规则命中（block 动作）只累加异常分数，
# 不会再次进入阈值评估 —— 修复前 CUSTOM_PACK 的 CRITICAL 命中在 PROTECT 模式下
# 仍被放行（仅出事件）。修复后由 gateway/rules/jiuzhang/post-contrib-blocking.conf
# 在全部计分规则之后二次汇总 PL 分数并阻断。
#
# 探针选择说明：SSTI {{7*7}} 会同时命中 CRS 934200（crs/rules 内，949 可直接阻断），
# 无法隔离 contrib 贡献；{{7+7}} 只命中 CUSTOM_PACK attack-coverage.conf 1001101
# （CRS 934200 要求 {{...}} 内含 ( / * / __，+ 号不命中），403 只能来自二次阻断评估。
#
# 依赖 stage5 编排（+ wdsp 覆盖亦可）：
#   docker compose --env-file .env -f deployment/docker-compose.stage5.yml up -d --build
# 用法：bash test/waf/scripts/custom-pack-blocking-tests.sh
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/stage5-setup.sh"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

# 发请求到网关并断言状态码
check() {
  local name="$1" want="$2" path="$3"; shift 3
  local status
  status=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$@" "$GATEWAY_URL$path")
  [ "$status" = "$want" ] && record "$name" 1 "status=$status" || record "$name" 0 "status=$status want=$want"
}

# 切换应用防护模式（PUT 需携带乐观锁 version）
s5_set_mode() {
  local mode="$1" cookie="/tmp/s5-$SEC_USER.txt"
  local body
  body=$(curl -s -b "$cookie" "$API_URL/api/v1/applications/$APP_ID" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
print(json.dumps({'name':d['name'],'description':d.get('description') or '',
 'business_owner':d.get('business_owner') or '','technical_owner':d.get('technical_owner') or '',
 'protection_mode':'$mode','version':d['version']}))" 2>/dev/null)
  curl -s -o /dev/null -w "%{http_code}" -b "$cookie" -X PUT "$API_URL/api/v1/applications/$APP_ID" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $SEC_CSRF" -d "$body"
}

# 最近一条 BLOCK 事件详情中包含的规则 ID 列表（空格分隔）
latest_block_rules() {
  local cookie="/tmp/s5-$SEC_USER.txt" eid target
  # 在近 5 条 BLOCK 事件中按内容（含 1001101 的 SSTI 探针事件）定位；
  # 纯时序取最新在三个阻断探针并发的采集序下不稳定（selftest/sqli 探针后落库却时标更新）。
  target=$(curl -s -b "$cookie" "$API_URL/api/v1/security-events?page_size=5" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
ids=[e['id'] for e in items if e.get('action')=='BLOCK']
print(' '.join(ids))" 2>/dev/null)
  for eid in $target; do
    matches=$(curl -s -b "$cookie" "$API_URL/api/v1/security-events/$eid" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
print(' '.join(str(m['rule_id']) for m in (d.get('matches') or [])))" 2>/dev/null)
    case " $matches " in
      *" 1001101 "*) echo "$matches"; return 0 ;;
    esac
  done
  # 兜底：找不到 SSTI 事件时回退最新一条（保持失败输出可诊断）
  eid=$(echo "$target" | awk '{print $1}')
  [ -z "$eid" ] && return 0
  curl -s -b "$cookie" "$API_URL/api/v1/security-events/$eid" | python3 -c "
import json,sys
d=json.load(sys.stdin)['data']
print(' '.join(str(m['rule_id']) for m in (d.get('matches') or [])))" 2>/dev/null
}

echo "============================================================"
echo "九章 CUSTOM_PACK 二次阻断评估验证  gateway=$GATEWAY_URL api=$API_URL"
echo "============================================================"

# ---------- 准备：登录 / 应用 ----------
SYS_CSRF=$(s5_ensure_sysadmin) || exit 1
SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
[ -z "$SEC_CSRF" ] && { echo "ERROR: sec login failed"; exit 1; }
APP_ID=$(s5_ensure_app "$SEC_CSRF")
echo "[setup] app=$APP_ID"

# ---------- 1. PROTECT 模式 + 发布 ----------
RC=$(s5_set_mode "PROTECT")
[ "$RC" = "200" ] && record "应用切换 PROTECT 模式" 1 || { record "应用切换 PROTECT 模式" 0 "status=$RC"; echo "ABORT"; exit 1; }
PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] && record "PROTECT 配置发布成功" 1 || { record "PROTECT 配置发布成功" 0 "$PUB"; echo "ABORT"; exit 1; }

# ---------- 2. 核心用例：CUSTOM_PACK phase-2 CRITICAL 命中应 403 ----------
# attack-coverage.conf id:1001101（SSTI 算术探针，severity CRITICAL，+5 分达默认阈值 5）。
# {{7+7}} 不命中 CRS 934200（需 ( / * / __），修复前该请求 200 放行，修复后 403。
check "custom-pack-ssti-phase2-403（核心回归）" 403 "/echo" \
  -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'payload={{7+7}}'

# ---------- 3. 对照组 ----------
# phase:1 直接阻断的自定义规则（jiuzhang-custom 9000001），不经过异常评分，始终 403
check "phase1-直阻规则仍-403（对照）" 403 "/jiuzhang-rule-selftest"
# CRS 主包经典 SQLi 仍 403（CRS 949 自身阻断评估未受影响）
check "crs-sqli-仍-403（回归）" 403 "/echo?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"
# 正常请求不误伤（二次评估不得产生假阳性）
check "normal-get-200（不误伤）" 200 "/echo?page=1"
check "normal-post-200（不误伤）" 200 "/echo" \
  -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'name=zhangsan&page=1'

# ---------- 4. 事件归因：阻断必须来自二次评估而非 CRS 949 ----------
# 最新 BLOCK 事件的匹配规则应包含 CUSTOM_PACK 1001101 与二次评估 9000104，
# 且不含 CRS 949110/949111（证明 949 评估时分数未达阈值，阻断由后置二次评估完成）
sleep 5
RULES=" $(latest_block_rules) "
[ "${RULES#* 1001101 }" != "$RULES" ] && record "事件含 CUSTOM_PACK 规则 1001101" 1 || record "事件含 CUSTOM_PACK 规则 1001101" 0 "rules=$RULES"
[ "${RULES#* 9000104 }" != "$RULES" ] && record "事件含二次阻断评估规则 9000104" 1 || record "事件含二次阻断评估规则 9000104" 0 "rules=$RULES"
[ "${RULES#* 949110 }" = "$RULES" ] && [ "${RULES#* 949111 }" = "$RULES" ] \
  && record "事件不含 CRS 949 阻断（归因正确）" 1 || record "事件不含 CRS 949 阻断（归因正确）" 0 "rules=$RULES"

# ---------- 5. OBSERVE 模式：同一请求应放行（DetectionOnly 自动降级 deny） ----------
RC=$(s5_set_mode "OBSERVE")
[ "$RC" = "200" ] && record "应用切换 OBSERVE 模式" 1 || record "应用切换 OBSERVE 模式" 0 "status=$RC"
PUB=$(s5_publish "$SEC_CSRF")
[ "$PUB" = "PUBLISH_OK" ] && record "OBSERVE 配置发布成功" 1 || record "OBSERVE 配置发布成功" 0 "$PUB"
CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" \
  -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-urlencode 'payload={{7+7}}' \
  "$GATEWAY_URL/echo")
[ "$CODE" != "403" ] && [ "$CODE" != "429" ] && record "OBSERVE 模式同一请求放行不阻断（=${CODE}）" 1 || record "OBSERVE 模式同一请求放行不阻断" 0 "status=$CODE"

# ---------- 6. 还原 OFF（stage5 其他用例假设该应用为 OFF，避免污染环境） ----------
s5_set_mode "OFF" > /dev/null
s5_publish "$SEC_CSRF" > /dev/null

echo "============================================================"
echo "CUSTOM_PACK 二次阻断评估验证：$PASS/$TOTAL 通过，$FAIL 失败"
if [ "$FAIL" -gt 0 ]; then printf '失败项：\n'; printf '  %s\n' "${FAILED[@]}"; fi
echo "============================================================"
[ "$FAIL" = "0" ]
