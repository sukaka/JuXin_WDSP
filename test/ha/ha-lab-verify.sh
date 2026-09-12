#!/usr/bin/env bash
# 九章双节点 HA lab 验证（docs/HA_TWO_NODE_DESIGN.md §6 场景落地）
#
# 覆盖场景（每场景独立函数，可单独跑）：
#   S1 配置一致性：登记两节点 + 扇出发布 → /nodes/consistency consistent=true，
#      两节点 last_sync_result=SUCCESS、心跳 ACTIVE；
#   S2 共享计数（任务书 §123 形态）：behavior_store=valkey 下，同身份写请求
#      A60（直连 gw-a）+ B60（直连 gw-b）+ 10 经 LB，阈值 100 → 共 130>100
#      触发统一 RATE_LIMIT（429）；按节点直连分段断言证明跨节点共享计数
#      （若为单节点内存计数，60/60 分段各自不越限，B 段零阻断）；
#   S3 故障摘除：docker stop gw-b → LB 摘除 + 流量全走 A（事件按节点归因断言）
#      + 节点视图 STALE → start gw-b → --resume 恢复补丁态配置 → 心跳 ACTIVE
#      → 采集追平（停前计数 + 期间/恢复后新增 == 恢复后计数，零丢失零双计）；
#   S4 发布中故障：停 gw-b 后发布（等价"发布瞬间杀 B"的确定形态）→ 主发布成功、
#      B 记 FAILED + CONFIG_PUBLISH_FAILED 告警 → B 恢复（--resume 回旧版，
#      一致性视图如实报不一致 + CONFIG_HASH_MISMATCH 告警）→ 重发对齐 consistent=true；
#   S5 管理面中断：停 api → 网关持续防护（SQLi 仍 403、正常流量仍通）→
#      期间事件积压 → 恢复后采集追平（停机期间探针事件全量入库）。
#
# 环境前置：
#   1. docker / docker compose v2 可用；
#   2. ha-lab 栈已启动（仓库根目录）：
#        docker compose -f deployment/ha-lab/docker-compose.ha-lab.yml up -d --build
#      （脚本前置检查会按需自动构建 nodepatch 工具镜像，主栈镜像由上面的 --build 产出）
#   3. 本机 18880-18883/15932/15979 端口空闲（编排注释有说明）；
#   4. 依赖 curl + python3（与 test/waf/scripts/ 既有 harness 相同）。
#   清理：docker compose -f deployment/ha-lab/docker-compose.ha-lab.yml down -v
#
# 用法：
#   bash test/ha/ha-lab-verify.sh                 # 全部场景（S1→S5，约 15-20 分钟，S3 含 5 分钟 STALE 窗口等待）
#   bash test/ha/ha-lab-verify.sh --scenario S2   # 单跑某场景（前置 setup 幂等自动执行）
#
# 退出码：0=所选场景全部通过；1=存在断言失败；2=环境前置不满足（docker/栈/端口/镜像）。
#
# 注意（lab 形态如实声明，详见编排文件头注释）：
#   - gateway_node/心跳周期由 nodepatch 在每次发布后逐节点补丁（发布扇出为同构配置，
#     按节点注入是发布通道后续工程）；
#   - api-runtime-events 为双节点共写追加式事件总线（管理面当前单采集器单路径；
#     生产每节点独立日志+独立采集器为后续工程）；事件归因断言直读 PostgreSQL
#     （api_runtime_events.gateway_node 列，只读校验，不绕任何权限/审计写路径）。

set -u
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/deployment/ha-lab/docker-compose.ha-lab.yml"

# ---- 环境变量（可被同名环境覆盖；默认值与编排文件一致） ----
export API_URL="${API_URL:-http://127.0.0.1:18883}"
LB_URL="${LB_URL:-http://127.0.0.1:18880}"
GW_A_URL="${GW_A_URL:-http://127.0.0.1:18881}"
GW_B_URL="${GW_B_URL:-http://127.0.0.1:18882}"
export GATEWAY_URL="$LB_URL"            # stage5-setup.sh 的 s5_req 默认经 LB
export HOST_HEADER="${HOST_HEADER:-waf-ha.local}"
export APP_CODE="${APP_CODE:-haha}"
export VALKEY_CONTAINER="${VALKEY_CONTAINER:-jiuzhang-ha-valkey}"
export VALKEY_PASSWORD="${VALKEY_PASSWORD:?需先 export 与 ha-lab compose 同源的 VALKEY_PASSWORD（compose 已改为必填注入，无默认值）}"
PG_CONTAINER="${PG_CONTAINER:-jiuzhang-ha-postgres}"
API_CONTAINER="${API_CONTAINER:-jiuzhang-ha-api}"
GW_A="${GW_A:-jiuzhang-ha-gw-a}"
GW_B="${GW_B:-jiuzhang-ha-gw-b}"
PG_DB="${POSTGRES_DB:-jiuzhang_waf}"
PG_USER="${POSTGRES_USER:-jiuzhang}"
HB_SECONDS="${HB_SECONDS:-30}"          # 网关心跳周期（网关侧合法范围 30-300）
HA_IDENTITY_SALT="${HA_IDENTITY_SALT:-ha-lab-identity-salt-20260821}"

# 每次运行唯一标识（含字母，路径段不会被归一化为 {id}/{hex}，端点键逐运行隔离）
RUN_ID="r$(date +%s)x$RANDOM"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# 复用阶段5 公共 harness（登录/建用户/发布/请求工具函数）
source "$REPO_ROOT/test/waf/scripts/stage5-setup.sh"

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() {
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}

# 等待下一个自然分钟边界 +2s（行为/限速滑窗按自然分钟对齐，防跨窗计数重置）
wait_minute_boundary() {
  local s=$((10#$(date +%S)))
  sleep $(( 62 - s ))
}

# ha_ensure_sysadmin 系统管理员登录（复跑幂等版）：
# 首轮强制改密后账号密码已是 SYS_NEW_PWD，s5_ensure_sysadmin 只会试 SYS_PWD，
# 这里先试 SYS_PWD 再回退 SYS_NEW_PWD；仍需改密时以当前可用密码为旧密码改到 SYS_NEW_PWD。
ha_ensure_sysadmin() {
  local cur_pwd="$SYS_PWD" csrf
  csrf=$(s5_login "$SYS_USER" "$cur_pwd")
  if [ -z "$csrf" ]; then cur_pwd="$SYS_NEW_PWD"; csrf=$(s5_login "$SYS_USER" "$cur_pwd"); fi
  [ -n "$csrf" ] || { echo "ERROR: sysadmin login failed" >&2; return 1; }
  # /auth/me 会轮换 CSRF token，后续写操作必须使用其响应中的新 token
  local me must
  me=$(curl -s -b "/tmp/s5-$SYS_USER.txt" "$API_URL/api/v1/auth/me")
  csrf=$(echo "$me" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['csrf_token'])" 2>/dev/null)
  must=$(echo "$me" | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('user',{}).get('must_change_password', False))" 2>/dev/null)
  if [ "$must" = "True" ] && [ "$cur_pwd" != "$SYS_NEW_PWD" ]; then
    curl -s -b "/tmp/s5-$SYS_USER.txt" -X POST "$API_URL/api/v1/auth/change-password" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
      -d "{\"old_password\":\"$cur_pwd\",\"new_password\":\"$SYS_NEW_PWD\"}" > /dev/null
    csrf=$(s5_login "$SYS_USER" "$SYS_NEW_PWD")
  fi
  echo "$csrf"
}

# ---- 基础工具 ----

# ha_psql 直读 PostgreSQL（只读校验查询/设置播种；容器内本地 socket trust）
ha_psql() {
  docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" -tA 2>/dev/null
}

# ha_psql_scalar 执行 SQL 并取第一行第一列
ha_psql_scalar() {
  echo "$1" | ha_psql | head -1
}

# nodepatch：经 compose tools 一次性容器对单节点打身份补丁（gateway_node + 心跳周期）
# $1: a|b  $2: 节点名  $3: 可选 source 侧（a|b；首次纳管引导时从源节点读配置）
# 返回码：0=已补丁；2=目标节点无 guard 处理器（首次发布前，调用方按场景容忍）；
#         1=硬错误（连接/协议失败）
ha_patch_node() {
  local side="$1" node="$2" src="${3:-}" out rc
  local extra=()
  [ -n "$src" ] && extra=(-source-sock "/sock/$src/admin.sock")
  out=$(docker compose -f "$COMPOSE_FILE" --profile tools run --rm -T --no-deps \
    nodepatch -sock "/sock/$side/admin.sock" -node "$node" -heartbeat "$HB_SECONDS" ${extra[@]+"${extra[@]}"} 2>&1)
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "  [nodepatch $node rc=$rc] $out" >&2
    return $rc
  fi
  echo "$out" | grep -o "已补丁 [0-9]* 个" | head -1
  return 0
}

# 双节点身份补丁（每次发布后必须重打：扇出 /load 会把节点身份重置回基准值）。
# 单侧 rc=2（该节点尚未拿到 guard 配置，如首次发布前的 gw-b）仅记录不失败；
# rc=1（连接失败，如节点停机）如实失败返回。
ha_patch_nodes() {
  local ra rb rca=0 rcb=0
  ra=$(ha_patch_node a gw-a) || rca=$?
  rb=$(ha_patch_node b gw-b) || rcb=$?
  [ $rca -eq 1 ] || [ $rcb -eq 1 ] && return 1
  echo "  [nodepatch] gw-a ${ra:-跳过} / gw-b ${rb:-跳过}"
  return 0
}

# 发布并等待成功，随后重打双节点身份补丁；输出 PUBLISH_OK/PUBLISH_FAILED/PUBLISH_TIMEOUT
ha_publish() {
  local csrf="$1" cookie="/tmp/s5-$SEC_USER.txt"
  local task st
  task=$(curl -s -b "$cookie" -X POST "$API_URL/api/v1/gateway-config/publish" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d "{\"idempotency_key\":\"ha-$RUN_ID-$RANDOM\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  [ -n "$task" ] || { echo "PUBLISH_SUBMIT_FAILED"; return 1; }
  st=""
  for _ in $(seq 1 90); do
    st=$(curl -s -b "$cookie" "$API_URL/api/v1/publish-tasks/$task" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
    case "$st" in
      SUCCESS) break;;
      FAILED) echo "PUBLISH_FAILED"; return 1;;
    esac
    sleep 1
  done
  [ "$st" = "SUCCESS" ] || { echo "PUBLISH_TIMEOUT(st=$st)"; return 1; }
  ha_patch_nodes || { echo "PATCH_FAILED"; return 1; }
  echo "PUBLISH_OK"
}

# 播种 gateway_runtime 组设置（behavior_store=valkey 共享计数 / 写限速阈值 100 / 身份盐）。
# 管理面 PUT 仅支持既有行（乐观锁），行播种走 psql（lab fixture，幂等 upsert）。
ha_seed_settings() {
  docker exec -i "$PG_CONTAINER" psql -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1 <<SQL
INSERT INTO system_settings (setting_group, setting_key, setting_value, value_type, description)
VALUES ('gateway_runtime','behavior_store','"valkey"','string','ha-lab：双节点共享行为/限速计数'),
       ('gateway_runtime','api_write_rate_per_minute','"100"','string','ha-lab：S2 写限速阈值'),
       ('gateway_runtime','identity_salt','"$HA_IDENTITY_SALT"','string','ha-lab：身份指纹盐（lab 固定值）')
ON CONFLICT (setting_group, setting_key) DO UPDATE
SET setting_value = EXCLUDED.setting_value, updated_at = now(), version = system_settings.version + 1;
SQL
}

# 确保 HA 测试应用存在（PROTECT：WAF 真实阻断，供 S5 防护持续性断言）
ha_ensure_app() {
  local csrf="$1" cookie="/tmp/s5-$SEC_USER.txt"
  local existing
  existing=$(curl -s -b "$cookie" "$API_URL/api/v1/applications?keyword=$APP_CODE" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(next((i['id'] for i in items if i.get('code')=='$APP_CODE'),''))" 2>/dev/null)
  if [ -n "$existing" ]; then echo "$existing"; return 0; fi
  local appid
  appid=$(curl -s -b "$cookie" -X POST "$API_URL/api/v1/applications" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d "{\"code\":\"$APP_CODE\",\"name\":\"HA双节点验证应用\",\"description\":\"ha-lab S1-S5 场景\",\"business_owner\":\"test\",\"technical_owner\":\"test\",\"protection_mode\":\"PROTECT\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  [ -n "$appid" ] || { echo ""; return 1; }
  curl -s -b "$cookie" -X POST "$API_URL/api/v1/applications/$appid/domains" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d "{\"hostname\":\"$HOST_HEADER\",\"is_primary\":true,\"http_enabled\":true,\"https_enabled\":false,\"http_port\":8080,\"redirect_http_to_https\":false}" > /dev/null
  curl -s -b "$cookie" -X POST "$API_URL/api/v1/applications/$appid/upstreams" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d '{"name":"testorigin","scheme":"http","host":"testorigin","port":8081,"weight":1,"priority":1,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":10,"health_check_timeout_seconds":3,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false}' > /dev/null
  curl -s -b "$cookie" -X POST "$API_URL/api/v1/applications/$appid/enable" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" > /dev/null
  echo "$appid"
}

# 确保「版本标记」敏感类型存在（S4 用其 ENABLED/DISABLED 切换制造可观测的策略版本差）
ha_ensure_marker_type() {
  local csrf="$1" cookie="/tmp/s5-$SEC_USER.txt"
  local id
  id=$(curl -s -b "$cookie" "$API_URL/api/v1/api-security/sensitive-types?keyword=ha-lab-version-marker&page_size=5" \
    | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(next((i['id'] for i in items if i.get('name')=='ha-lab-version-marker'),''))" 2>/dev/null)
  if [ -z "$id" ]; then
    id=$(curl -s -b "$cookie" -X POST "$API_URL/api/v1/api-security/sensitive-types" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
      -d '{"name":"ha-lab-version-marker","description":"ha-lab S4 策略版本变更标记（匹配 lab 合成串，不打真实流量）","category":"lab","level":"GENERAL","data_type":"HA_MARKER","locations":["json"],"keywords":[],"regex":"HA-MARKER-[0-9]+","status":"DISABLED"}' \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  fi
  echo "$id"
}

# 置版本标记类型启用/禁用（$1=id $2=ENABLED|DISABLED）
ha_marker_set() {
  local csrf="$3" cookie="/tmp/s5-$SEC_USER.txt"
  curl -s -o /dev/null -w "%{http_code}" -b "$cookie" -X PATCH \
    "$API_URL/api/v1/api-security/sensitive-types/$1" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" -d "{\"status\":\"$2\"}"
}

# 版本标记当前状态（ENABLED/DISABLED；S4 幂等前置判断用）
ha_marker_status() {
  curl -s -b "/tmp/s5-$SEC_USER.txt" \
    "$API_URL/api/v1/api-security/sensitive-types?keyword=ha-lab-version-marker&page_size=5" \
    | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
hit=[i for i in items if i.get('name')=='ha-lab-version-marker']
print(hit[0].get('status') if hit else '')" 2>/dev/null
}

# 打流：$1=base_url $2=path $3=token $4=次数；输出 "放行数 429数 其他数"
ha_burst() {
  local base="$1" path="$2" token="$3" n="$4"
  local ok=0 blocked=0 other=0 i code
  for i in $(seq 1 "$n"); do
    code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" \
      -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
      -X POST -d "{\"n\":$i}" "$base$path")
    case "$code" in
      429) blocked=$((blocked+1));;
      2*|404) ok=$((ok+1));;
      *) other=$((other+1)); echo "  [burst] 非预期状态码 $code" >&2;;
    esac
  done
  echo "$ok $blocked $other"
}

# 节点视图字段：$1=节点名 $2=字段（status/event_count/last_sync_result/last_policy_version/last_seen_at）
ha_node_field() {
  curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/nodes" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
hit=[n for n in items if n.get('node_name')=='$1']
print(hit[0].get('$2') if hit else '')" 2>/dev/null
}

# 事件计数（psql 直读，按节点归因；$1=节点名 $2=endpoint_key 可空）
ha_event_count() {
  local sql="SELECT count(*) FROM api_runtime_events WHERE gateway_node='$1'"
  [ -n "${2:-}" ] && sql="$sql AND endpoint_key='$2'"
  ha_psql_scalar "$sql"
}

# 一致性视图字段（consistent/evaluated_nodes）
ha_consistency_field() {
  curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/nodes/consistency" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data'].get('$1'))" 2>/dev/null
}

# 告警计数（$1=alert_type $2=component；累计口径，含历史）
ha_alert_count() {
  curl -s -b "/tmp/s5-$SEC_USER.txt" \
    "$API_URL/api/v1/system-alerts?alert_type=$1&component=$2&page_size=1" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null
}

# OPEN 告警计数（$1=alert_type $2=component；仅未关闭行）
ha_alert_open_count() {
  curl -s -b "/tmp/s5-$SEC_USER.txt" \
    "$API_URL/api/v1/system-alerts?alert_type=$1&component=$2&status=OPEN&page_size=1" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null
}

# 清场：把既有 OPEN 告警全部处置为 RESOLVED（$1=alert_type $2=component $3=CSRF）。
# 告警引擎对同 type+component 的未关闭告警做合并（occurrence_count+1，不增行），
# 复跑时「行数增长」断言会恒假；触发前先清场，使「新建 OPEN 行」成为可观测信号。
ha_resolve_open_alerts() {
  local csrf="$3" cookie="/tmp/s5-$SEC_USER.txt" ids id
  ids=$(curl -s -b "$cookie" \
    "$API_URL/api/v1/system-alerts?alert_type=$1&component=$2&status=OPEN&page_size=50" \
    | python3 -c "import json,sys
for i in json.load(sys.stdin)['data'].get('items') or []: print(i['id'])" 2>/dev/null)
  for id in $ids; do
    curl -s -o /dev/null -b "$cookie" -X POST "$API_URL/api/v1/system-alerts/$id/resolve" \
      -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" -d ''
  done
}

# 运行时事件计数（管理面接口，$1=endpoint_key $2=final_action 可空；-G 编码查询参数）
ha_api_event_total() {
  local args=(--data-urlencode "page_size=1" --data-urlencode "endpoint_key=$1")
  [ -n "${2:-}" ] && args+=(--data-urlencode "final_action=$2")
  curl -s -b "/tmp/s5-$SEC_USER.txt" -G "${args[@]}" \
    "$API_URL/api/v1/api-security/runtime/events" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['total'])" 2>/dev/null
}

# 容器是否在运行
ha_running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = "true" ]; }

# 异常退出时尽量恢复栈完整（停掉的容器拉起来），避免污染后续场景/复跑
cleanup_on_exit() {
  ha_running "$GW_B" 2>/dev/null || docker start "$GW_B" >/dev/null 2>&1
  ha_running "$API_CONTAINER" 2>/dev/null || docker start "$API_CONTAINER" >/dev/null 2>&1
  return 0
}
trap cleanup_on_exit EXIT

# ---- 前置检查 ----
preflight() {
  command -v docker >/dev/null || { echo "ERROR: docker 不可用"; exit 2; }
  docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose v2 不可用"; exit 2; }
  command -v curl >/dev/null && command -v python3 >/dev/null || { echo "ERROR: 需要 curl 与 python3"; exit 2; }
  [ -f "$COMPOSE_FILE" ] || { echo "ERROR: 编排文件缺失 $COMPOSE_FILE"; exit 2; }
  if ! curl -s -o /dev/null --max-time 3 "$API_URL/api/v1/health"; then
    echo "ERROR: ha-lab 栈未就绪（$API_URL 不可达）。先执行："
    echo "  docker compose -f deployment/ha-lab/docker-compose.ha-lab.yml up -d --build"
    exit 2
  fi
  for u in "$LB_URL" "$GW_A_URL" "$GW_B_URL"; do
    curl -s -o /dev/null --max-time 3 -H "Host: $HOST_HEADER" "$u/" \
      || { echo "ERROR: $u 不可达（ha-lab 栈未就绪）"; exit 2; }
  done
  # nodepatch 工具镜像缺失则自动构建（锁定基础镜像，秒级）
  if ! docker image inspect jiuzhang-ha-nodepatch:ha-lab >/dev/null 2>&1; then
    echo "[preflight] 构建 nodepatch 工具镜像..."
    docker compose -f "$COMPOSE_FILE" --profile tools build nodepatch >/dev/null 2>&1 \
      || { echo "ERROR: nodepatch 镜像构建失败"; exit 2; }
  fi
}

# ---- S0 前置准备（幂等）：登录/应用/设置/发布/登记 ----
# 结束后状态：应用 PROTECT 已发布；gateway_runtime 三键生效；两节点身份补丁+心跳 30s；
# 两节点已登记（sync_enabled=true）且至少完成一次扇出发布。
setup() {
  echo "------------------------------------------------------------"
  echo "S0 前置准备（登录/应用/设置/发布/节点登记）"
  SYS_CSRF=$(ha_ensure_sysadmin) || { echo "ERROR: sysadmin 登录失败"; exit 2; }
  SEC_CSRF=$(s5_ensure_secuser "$SYS_CSRF")
  [ -n "$SEC_CSRF" ] || { echo "ERROR: sec 登录失败"; exit 2; }
  APP_ID=$(ha_ensure_app "$SEC_CSRF")
  [ -n "$APP_ID" ] || { echo "ERROR: 创建应用失败"; exit 2; }
  MARKER_ID=$(ha_ensure_marker_type "$SEC_CSRF")
  echo "[setup] app=$APP_ID marker=${MARKER_ID:-none}"

  ha_seed_settings || { echo "ERROR: gateway_runtime 设置播种失败"; exit 2; }
  echo "[setup] gateway_runtime: behavior_store=valkey api_write_rate_per_minute=100 identity_salt=***"

  echo "[setup] 首次发布（主通道 → gw-a）..."
  local p1
  p1=$(ha_publish "$SEC_CSRF")
  echo "$p1" | tail -1 | grep -q PUBLISH_OK || { echo "ERROR: 首次发布失败: $p1"; exit 2; }

  # 首次纳管引导：gw-b 尚在引导配置（无 guard 处理器，发布扇出只推登记节点），
  # 从 gw-a 的发布态配置复制改写身份后 /load（节点注册握手协议未交付前的
  # lab 引导动作，见 nodepatch 头注释）；此后 gw-b 心跳上报、进入节点视图可登记
  echo "[setup] gw-b 首次纳管引导（从 gw-a 发布态复制 + 改写身份）..."
  local boot
  boot=$(ha_patch_node b gw-b a) || { echo "ERROR: gw-b 引导失败: $boot"; exit 2; }
  echo "  [bootstrap] gw-b $boot"

  # 打流让端点资产有数据，并等心跳把两节点送入节点视图
  ha_burst "$LB_URL" "/api/json" "ha-setup-$RUN_ID" 3 > /dev/null
  local i na nb
  for i in $(seq 1 20); do
    na=$(ha_node_field gw-a status); nb=$(ha_node_field gw-b status)
    [ -n "$na" ] && [ -n "$nb" ] && break
    sleep 3
  done
  if [ -z "$na" ] || [ -z "$nb" ]; then
    echo "ERROR: 节点视图未出现 gw-a/gw-b（心跳/采集链路未通）a='$na' b='$nb'"; exit 2
  fi
  echo "[setup] 节点视图已见 gw-a($na) gw-b($nb)"

  # 登记两节点（admin_addr=各节点 Admin Socket 在 api 容器内的可达路径）
  local ida idb
  ida=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/nodes" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(next((n['id'] for n in items if n.get('node_name')=='gw-a'),''))" 2>/dev/null)
  idb=$(curl -s -b "/tmp/s5-$SEC_USER.txt" "$API_URL/api/v1/api-security/nodes" | python3 -c "
import json,sys
items=json.load(sys.stdin)['data'].get('items') or []
print(next((n['id'] for n in items if n.get('node_name')=='gw-b'),''))" 2>/dev/null)
  [ -n "$ida" ] && [ -n "$idb" ] || { echo "ERROR: 节点 ID 获取失败"; exit 2; }
  local rc1 rc2
  rc1=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$SEC_USER.txt" -X PATCH \
    "$API_URL/api/v1/api-security/nodes/$ida" -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $SEC_CSRF" \
    -d '{"admin_addr":"/var/run/caddy/admin.sock","sync_enabled":true}')
  rc2=$(curl -s -o /dev/null -w "%{http_code}" -b "/tmp/s5-$SEC_USER.txt" -X PATCH \
    "$API_URL/api/v1/api-security/nodes/$idb" -H 'Content-Type: application/json' \
    -H "X-CSRF-Token: $SEC_CSRF" \
    -d '{"admin_addr":"/var/run/caddy-node-b/admin.sock","sync_enabled":true}')
  [ "$rc1" = "200" ] && [ "$rc2" = "200" ] || { echo "ERROR: 节点登记失败 rc=$rc1/$rc2"; exit 2; }
  echo "[setup] 两节点已登记（gw-a=/var/run/caddy/admin.sock gw-b=/var/run/caddy-node-b/admin.sock）"

  echo "[setup] 二次发布（扇出两节点）..."
  local p2
  p2=$(ha_publish "$SEC_CSRF")
  echo "$p2" | tail -1 | grep -q PUBLISH_OK || { echo "ERROR: 扇出发布失败: $p2"; exit 2; }
  echo "[setup] 完成"
}

# ---- S1 配置一致性：登记 + 扇出发布 → consistent=true ----
s1() {
  echo "------------------------------------------------------------"
  echo "S1 配置一致性（扇出发布 + /nodes/consistency）"
  local sa sb ra rb
  sa=$(ha_node_field gw-a status); sb=$(ha_node_field gw-b status)
  [ "$sa" = "ACTIVE" ] && record "S1 节点 gw-a 心跳 ACTIVE" 1 || record "S1 节点 gw-a 心跳 ACTIVE" 0 "status=$sa"
  [ "$sb" = "ACTIVE" ] && record "S1 节点 gw-b 心跳 ACTIVE" 1 || record "S1 节点 gw-b 心跳 ACTIVE" 0 "status=$sb"

  ra=$(ha_node_field gw-a last_sync_result); rb=$(ha_node_field gw-b last_sync_result)
  [ "$ra" = "SUCCESS" ] && record "S1 gw-a 扇出结果 SUCCESS" 1 || record "S1 gw-a 扇出结果 SUCCESS" 0 "got=$ra"
  [ "$rb" = "SUCCESS" ] && record "S1 gw-b 扇出结果 SUCCESS" 1 || record "S1 gw-b 扇出结果 SUCCESS" 0 "got=$rb"

  # 心跳/事件收集有秒级延迟，一致性视图短轮询
  local cons="" evaln=0 i
  for i in $(seq 1 20); do
    cons=$(ha_consistency_field consistent); evaln=$(ha_consistency_field evaluated_nodes)
    [ "$cons" = "True" ] && [ "$evaln" = "2" ] && break
    sleep 3
  done
  [ "$cons" = "True" ] && [ "$evaln" = "2" ] \
    && record "S1 一致性视图 consistent=true（两节点同版本）" 1 \
    || record "S1 一致性视图 consistent=true（两节点同版本）" 0 "consistent=$cons evaluated=$evaln"
}

# ---- S2 共享计数：A60 + B60 + LB10，阈值 100 → 统一 RATE_LIMIT ----
s2() {
  echo "------------------------------------------------------------"
  echo "S2 共享计数（behavior_store=valkey，同身份跨节点写限速）"
  local path="/v1/ha-s2-$RUN_ID"
  local ek="POST $path"
  local token="ha-s2-token-$RUN_ID"
  local base_a base_b
  base_a=$(ha_event_count gw-a "$ek"); base_b=$(ha_event_count gw-b "$ek")
  base_a=${base_a:-0}; base_b=${base_b:-0}

  wait_minute_boundary
  echo "[S2] 窗口起点就绪：gw-a 直连 60 写（应全部放行，计数 1-60）"
  local r1 r2 r3 ok1 bl1 ok2 bl2 ok3 bl3
  r1=$(ha_burst "$GW_A_URL" "$path" "$token" 60); read -r ok1 bl1 _ <<< "$r1"
  [ "$bl1" = "0" ] && [ "$ok1" = "60" ] \
    && record "S2 A 段 60 写全放行（未越限）" 1 \
    || record "S2 A 段 60 写全放行（未越限）" 0 "ok=$ok1 blocked=$bl1"

  echo "[S2] gw-b 直连 60 写（共享计数 61-120：后 20 应 429）"
  r2=$(ha_burst "$GW_B_URL" "$path" "$token" 60); read -r ok2 bl2 _ <<< "$r2"
  # 共享计数成立：B 段计数从 61 起，101-120 共 20 次阻断；若为节点内存计数则 B 段 1-60 全放行
  [ "$bl2" = "20" ] && [ "$ok2" = "40" ] \
    && record "S2 B 段 40 放行 + 20×429（跨节点共享计数生效）" 1 \
    || record "S2 B 段 40 放行 + 20×429（跨节点共享计数生效）" 0 "ok=$ok2 blocked=${bl2}（内存计数时 blocked=0）"

  echo "[S2] 经 LB 再打 10 写（计数 121-130，应全部 429）"
  r3=$(ha_burst "$LB_URL" "$path" "$token" 10); read -r ok3 bl3 _ <<< "$r3"
  [ "$bl3" = "10" ] \
    && record "S2 LB 入口 10 写全部 429（统一限速对客户端唯一生效）" 1 \
    || record "S2 LB 入口 10 写全部 429（统一限速对客户端唯一生效）" 0 "ok=$ok3 blocked=$bl3"

  # 事件入库断言（采集 2s 轮询 + 余量；按本次运行唯一端点精确计数）
  local want=$((bl2 + bl3)) got=0 i
  for i in $(seq 1 15); do
    got=$(ha_api_event_total "$ek" RATE_LIMIT); got=${got:-0}
    [ "$got" -ge "$want" ] 2>/dev/null && break
    sleep 2
  done
  [ "$got" -ge "$want" ] && [ "$want" -gt 0 ] \
    && record "S2 RATE_LIMIT 事件入库（=${got}，预期≥${want}）" 1 \
    || record "S2 RATE_LIMIT 事件入库（=${got}，预期≥${want}）" 0

  # 按节点归因：B 段直连的 20 次 429 必须落在 gw-b
  local eb=0
  for i in $(seq 1 10); do
    eb=$(ha_event_count gw-b "$ek"); eb=${eb:-0}
    [ "$eb" -ge $((base_b + 60)) ] 2>/dev/null && break
    sleep 2
  done
  [ "$eb" -ge $((base_b + 60)) ] 2>/dev/null \
    && record "S2 事件按节点归因（gw-b 新增 60 条 = 40 OBSERVE + 20 RATE_LIMIT）" 1 \
    || record "S2 事件按节点归因（gw-b 新增 60 条）" 0 "gw-b=$eb base=$base_b"
}

# ---- S3 故障摘除：停 B → LB 摘除 + 全走 A + STALE → 恢复 ACTIVE + 采集追平 ----
s3() {
  echo "------------------------------------------------------------"
  echo "S3 故障摘除与恢复（docker stop/start gw-b）"
  local ek_a="POST /v1/ha-s3a-$RUN_ID"   # 停机前/后直连 B 的探针端点
  local ek_lb="POST /v1/ha-s3lb-$RUN_ID" # 停机期间经 LB 的探针端点
  local pa="/v1/ha-s3a-$RUN_ID" plb="/v1/ha-s3lb-$RUN_ID"
  local tok="ha-s3-$RUN_ID"

  # 停机前基线：B 直连 5 探针（验证按节点归因链路）
  ha_burst "$GW_B_URL" "$pa" "$tok-pre" 5 > /dev/null
  local cb0 i
  for i in $(seq 1 15); do
    cb0=$(ha_event_count gw-b "$ek_a"); cb0=${cb0:-0}
    [ "$cb0" -ge 5 ] 2>/dev/null && break
    sleep 2
  done
  [ "$cb0" -ge 5 ] 2>/dev/null \
    && record "S3 前置：gw-b 直连探针按节点归因（=$cb0/5）" 1 \
    || record "S3 前置：gw-b 直连探针按节点归因（=$cb0/5）" 0

  echo "[S3] docker stop gw-b"
  docker stop "$GW_B" > /dev/null || { record "S3 stop gw-b" 0; return; }
  sleep 3

  # 停机期间经 LB 打 12 探针：客户端应基本无感（LB 重试/摘除），事件应全落 gw-a。
  # 阈值 ≥11/12：docker stop 硬停瞬间正在途中的那一个请求可能被直接重置
  # （Caddy 优雅退出不挽留已RST的连接，LB 重试只对尚未建立连接的请求生效），
  # 丢 1 个在途请求是硬停故障的诚实行为，不要求 12/12 满分。
  local r ok bl
  r=$(ha_burst "$LB_URL" "$plb" "$tok-lb" 12); read -r ok bl _ <<< "$r"
  [ "$ok" -ge 11 ] 2>/dev/null \
    && record "S3 停机期间 LB 流量 ≥11/12 无感通过（摘除+重试生效）" 1 \
    || record "S3 停机期间 LB 流量 ≥11/12 无感通过" 0 "ok=$ok blocked=$bl"

  local ca=0 cb=0
  for i in $(seq 1 15); do
    ca=$(ha_event_count gw-a "$ek_lb"); ca=${ca:-0}
    [ "$ca" -ge 11 ] 2>/dev/null && break
    sleep 2
  done
  # 事件数与无感通过数同口径（≥11）：被重置的在途请求由 LB 直接 502，
  # 未进入任何网关的 guard 管线，不产生 api_runtime_event。
  cb=$(ha_event_count gw-b "$ek_lb"); cb=${cb:-0}
  [ "$ca" -ge 11 ] && [ "$cb" = "0" ] \
    && record "S3 流量全走 A（gw-a=$ca 条事件，gw-b=0）" 1 \
    || record "S3 流量全走 A（gw-a=$ca 条事件，gw-b=0）" 0 "a=$ca b=$cb"

  # 节点视图 STALE（心跳 30s 中断 → 5min 窗口 + 清扫 1min 周期，轮询 ≤8min）
  echo "[S3] 等待 gw-b 状态转为 STALE（5 分钟活性窗口 + 清扫周期，最长 8 分钟）..."
  local st="" t0=$(date +%s)
  while :; do
    st=$(ha_node_field gw-b status)
    [ "$st" = "STALE" ] && break
    [ $(( $(date +%s) - t0 )) -ge 480 ] && break
    sleep 15
  done
  [ "$st" = "STALE" ] \
    && record "S3 gw-b 失联转 STALE（节点视图如实呈现）" 1 \
    || record "S3 gw-b 失联转 STALE" 0 "status=$st"
  # 如实说明：节点失联当前无独立告警类型（词表见 systemalerts/rules.go）；
  # 失联兜底 = 节点视图 STALE/SILENT + 版本漂移时的一致性告警（S4 覆盖）

  echo "[S3] docker start gw-b（--resume 恢复停机前补丁态配置）"
  docker start "$GW_B" > /dev/null
  local st2="" t1=$(date +%s)
  while :; do
    st2=$(ha_node_field gw-b status)
    [ "$st2" = "ACTIVE" ] && break
    [ $(( $(date +%s) - t1 )) -ge 150 ] && break
    sleep 5
  done
  [ "$st2" = "ACTIVE" ] \
    && record "S3 gw-b 恢复 ACTIVE（autosave 恢复配置，心跳自愈，无需重发）" 1 \
    || record "S3 gw-b 恢复 ACTIVE" 0 "status=$st2"

  # 采集追平/零丢失零双计：恢复后 B 直连 5 探针 → B 计数 == 停前 + 期间(0) + 恢复后(5)
  ha_burst "$GW_B_URL" "$pa" "$tok-post" 5 > /dev/null
  local cb1=0
  for i in $(seq 1 15); do
    cb1=$(ha_event_count gw-b "$ek_a"); cb1=${cb1:-0}
    [ "$cb1" -ge $((cb0 + 5)) ] 2>/dev/null && break
    sleep 2
  done
  [ "$cb1" = "$((cb0 + 5))" ] 2>/dev/null \
    && record "S3 采集追平零丢失零双计（gw-b: 停前=$cb0 恢复后=$cb1=停前+5）" 1 \
    || record "S3 采集追平零丢失零双计" 0 "before=$cb0 after=$cb1 want=$((cb0+5))"
}

# ---- S4 发布中故障：停 B 发布 → 主成功 B 记 FAILED + 告警 → 恢复后重发对齐 ----
s4() {
  echo "------------------------------------------------------------"
  echo "S4 发布中故障（停 gw-b 后发布 → FAILED + 告警 → 恢复重发对齐）"
  # 幂等前置：上一轮 S4 以「标记 ENABLED + 重发对齐」收尾，直接再 ENABLE 是无操作，
  # 发布产不出版本差、漂移不可观测（实测复现）。标记非 DISABLED 时先复位并向双节点
  # 发布，收敛出旧版基线 V0（首轮标记本就是 DISABLED，跳过不多花一次发布）。
  local mcur mrc0 p0
  mcur=$(ha_marker_status)
  if [ "$mcur" != "DISABLED" ]; then
    echo "[S4] 标记残留 ${mcur}，先 DISABLE 并发布收敛基线 V0"
    mrc0=$(ha_marker_set "$MARKER_ID" DISABLED "$SEC_CSRF")
    [ "$mrc0" = "200" ] || { record "S4 版本标记复位" 0 "status=$mrc0"; return; }
    p0=$(ha_publish "$SEC_CSRF")
    echo "$p0" | tail -1 | grep -q PUBLISH_OK || { record "S4 基线发布（标记复位收敛 V0）" 0 "$p0"; return; }
  fi
  # 版本变更杠杆：启用版本标记敏感类型（ENABLED+regex 进入 api_policy_version 哈希）
  local mrc
  mrc=$(ha_marker_set "$MARKER_ID" ENABLED "$SEC_CSRF")
  [ "$mrc" = "200" ] || { record "S4 版本标记启用" 0 "status=$mrc"; return; }

  # 触发前清场：告警引擎对同 type+component 未关闭告警做合并（occurrence_count+1
  # 不增行），复跑时行数不变；先处置存量 OPEN，使本次「新建 OPEN 行」可观测
  ha_resolve_open_alerts CONFIG_PUBLISH_FAILED API_GATEWAY_NODE_SYNC "$SEC_CSRF"

  echo "[S4] docker stop gw-b 后发起发布（等价发布瞬间杀 B 的确定形态）"
  docker stop "$GW_B" > /dev/null
  sleep 2
  local p3
  p3=$(ha_publish "$SEC_CSRF")
  # 注意：ha_publish 末尾的 nodepatch 对停机节点会失败——属预期，单独重打 A 即可
  if echo "$p3" | grep -q "PUBLISH_OK\|PATCH_FAILED"; then
    ha_patch_node a gw-a > /dev/null 2>&1
    record "S4 停机发布主流程 SUCCESS（次节点失败不阻断）" 1
  else
    record "S4 停机发布主流程 SUCCESS（次节点失败不阻断）" 0 "$p3"
  fi

  local rb="" i
  for i in $(seq 1 10); do
    rb=$(ha_node_field gw-b last_sync_result)
    [ "$rb" = "FAILED" ] && break
    sleep 2
  done
  [ "$rb" = "FAILED" ] \
    && record "S4 gw-b 扇出结果记 FAILED（last_sync_* 如实回填）" 1 \
    || record "S4 gw-b 扇出结果记 FAILED" 0 "got=$rb"

  local al=0
  for i in $(seq 1 15); do
    al=$(ha_alert_open_count CONFIG_PUBLISH_FAILED API_GATEWAY_NODE_SYNC); al=${al:-0}
    [ "$al" -ge 1 ] 2>/dev/null && break
    sleep 2
  done
  [ "$al" -ge 1 ] 2>/dev/null \
    && record "S4 产生 CONFIG_PUBLISH_FAILED 告警（组件 API_GATEWAY_NODE_SYNC）" 1 \
    || record "S4 产生 CONFIG_PUBLISH_FAILED 告警" 0 "open=$al"

  echo "[S4] docker start gw-b（--resume 回停机前旧版配置 → 一致性视图应如实报漂移）"
  docker start "$GW_B" > /dev/null
  local cons="" t0=$(date +%s)
  while :; do
    cons=$(ha_consistency_field consistent)
    [ "$cons" = "False" ] && break
    [ $(( $(date +%s) - t0 )) -ge 150 ] && break
    sleep 5
  done
  [ "$cons" = "False" ] \
    && record "S4 恢复后漂移可见（consistent=false：B 旧版 vs A 新版）" 1 \
    || record "S4 恢复后漂移可见（consistent=false）" 0 "consistent=$cons"

  # 一致性告警（sweeper 1min 周期产出 CONFIG_HASH_MISMATCH）
  local am=0 t1=$(date +%s)
  while :; do
    am=$(ha_alert_count CONFIG_HASH_MISMATCH API_GATEWAY_NODES); am=${am:-0}
    [ "$am" -ge 1 ] 2>/dev/null && break
    [ $(( $(date +%s) - t1 )) -ge 150 ] && break
    sleep 5
  done
  [ "$am" -ge 1 ] 2>/dev/null \
    && record "S4 版本漂移产 CONFIG_HASH_MISMATCH 告警" 1 \
    || record "S4 版本漂移产 CONFIG_HASH_MISMATCH 告警" 0

  echo "[S4] 重发对齐"
  local p4
  p4=$(ha_publish "$SEC_CSRF")
  echo "$p4" | tail -1 | grep -q PUBLISH_OK || { record "S4 重发对齐" 0 "$p4"; return; }
  local rb2 cons2="" t2=$(date +%s)
  rb2=$(ha_node_field gw-b last_sync_result)
  while :; do
    cons2=$(ha_consistency_field consistent)
    [ "$cons2" = "True" ] && break
    [ $(( $(date +%s) - t2 )) -ge 150 ] && break
    sleep 5
  done
  [ "$rb2" = "SUCCESS" ] \
    && record "S4 重发后 gw-b 扇出 SUCCESS" 1 \
    || record "S4 重发后 gw-b 扇出 SUCCESS" 0 "got=$rb2"
  [ "$cons2" = "True" ] \
    && record "S4 重发后一致性恢复 consistent=true" 1 \
    || record "S4 重发后一致性恢复 consistent=true" 0 "consistent=$cons2"
}

# ---- S5 管理面中断：停 api → 防护持续 → 恢复后事件追平 ----
s5() {
  echo "------------------------------------------------------------"
  echo "S5 管理面中断（停 api → 网关持续防护 → 恢复追平）"
  local sqli="/echo?q=1'%20OR%20'1'='1"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$LB_URL$sqli")
  [ "$code" = "403" ] \
    && record "S5 前置：SQLi 被 403 阻断（PROTECT 生效基线）" 1 \
    || record "S5 前置：SQLi 被 403 阻断（PROTECT 生效基线）" 0 "status=$code"

  local ek="POST /v1/ha-s5-$RUN_ID" pa="/v1/ha-s5-$RUN_ID"
  local ev0
  ev0=$(ha_api_event_total "$ek" ""); ev0=${ev0:-0}

  echo "[S5] docker stop api"
  docker stop "$API_CONTAINER" > /dev/null || { record "S5 stop api" 0; return; }
  sleep 3

  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$LB_URL$sqli")
  [ "$code" = "403" ] \
    && record "S5 api 停止期间 SQLi 仍 403（最近配置持续生效）" 1 \
    || record "S5 api 停止期间 SQLi 仍 403" 0 "status=$code"

  code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $HOST_HEADER" "$LB_URL/")
  case "$code" in
    2*) record "S5 api 停止期间正常流量仍转发（=${code}）" 1;;
    *)  record "S5 api 停止期间正常流量仍转发" 0 "status=$code";;
  esac

  echo "[S5] 停机期间经 LB 打 6 探针（事件积压于事件总线）"
  ha_burst "$LB_URL" "$pa" "ha-s5-$RUN_ID" 6 > /dev/null

  echo "[S5] docker start api"
  docker start "$API_CONTAINER" > /dev/null
  local i up=0
  for i in $(seq 1 30); do
    curl -s -o /dev/null --max-time 3 "$API_URL/api/v1/health" && { up=1; break; }
    sleep 4
  done
  [ "$up" = "1" ] \
    && record "S5 api 恢复（健康检查通过）" 1 \
    || { record "S5 api 恢复（健康检查通过）" 0; return; }

  # 事件追平：停机期间 6 探针全量入库（断点续采）
  local ev1=0
  for i in $(seq 1 30); do
    ev1=$(ha_api_event_total "$ek" ""); ev1=${ev1:-0}
    [ "$ev1" -ge $((ev0 + 6)) ] 2>/dev/null && break
    sleep 3
  done
  [ "$ev1" = "$((ev0 + 6))" ] 2>/dev/null \
    && record "S5 恢复后事件追平（停前=$ev0 恢复后=$ev1=停前+6，零丢失零双计）" 1 \
    || record "S5 恢复后事件追平" 0 "before=$ev0 after=$ev1 want=$((ev0+6))"
}

# ---- 主流程 ----
SCENARIO=""
while [ $# -gt 0 ]; do
  case "$1" in
    --scenario) SCENARIO=$(echo "$2" | tr 'a-z' 'A-Z'); shift 2;;
    --scenario=*) SCENARIO=$(echo "${1#*=}" | tr 'a-z' 'A-Z'); shift;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -40
      exit 0;;
    *) echo "未知参数: $1（支持 --scenario S1..S5）"; exit 2;;
  esac
done
case "$SCENARIO" in
  ""|S1|S2|S3|S4|S5) ;;
  *) echo "未知场景: ${SCENARIO}（可选 S1..S5）"; exit 2;;
esac

echo "============================================================"
echo "九章双节点 HA lab 验证  api=$API_URL lb=$LB_URL"
echo "  gw-a=$GW_A_URL gw-b=$GW_B_URL run=$RUN_ID scenario=${SCENARIO:-ALL}"
echo "============================================================"

preflight
setup

case "$SCENARIO" in
  "") s1; s2; s3; s4; s5;;
  S1) s1;;
  S2) s2;;
  S3) s3;;
  S4) s4;;
  S5) s5;;
esac

echo "============================================================"
echo "HA lab 验证：$PASS/$TOTAL 通过，$FAIL 失败"
if [ "$FAIL" -gt 0 ]; then printf '失败项：\n'; printf '  %s\n' "${FAILED[@]}"; fi
echo "============================================================"
[ "$FAIL" = "0" ]
