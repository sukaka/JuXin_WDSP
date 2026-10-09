#!/usr/bin/env bash
# chain_proxy.sh —— httpchain trusted-proxy 链路辅助：setup 注册 docker-bridge
# 可信代理并发布；cleanup 删除并发布。供 test/httpchain/run.py chains 调用。
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../../waf/scripts/stage5-setup.sh"

csrf=$(s5_login sec_admin_s5 'SecAdmin@S5!2026')
[ -n "$csrf" ] || { echo "ERROR: login failed" >&2; exit 1; }

SUBNET=$(docker network inspect jiuzhang-stage5_stage5-net --format '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)
[ -n "$SUBNET" ] || SUBNET="172.19.0.0/16"

publish() {
  local task st i
  task=$(curl -s -b "/tmp/s5-sec_admin_s5.txt" -X POST "$API_URL/api/v1/gateway-config/publish" \
    -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
    -d "{\"idempotency_key\":\"chain-proxy-$(date +%s%N)\"}" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['id'])" 2>/dev/null)
  for i in $(seq 1 30); do
    st=$(curl -s -b "/tmp/s5-sec_admin_s5.txt" "$API_URL/api/v1/publish-tasks/$task" \
      | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['status'])" 2>/dev/null)
    case "$st" in SUCCESS) echo PUBLISH_OK; return 0;; FAILED) echo PUBLISH_FAILED; return 1;; esac
    sleep 1
  done
  echo PUBLISH_TIMEOUT; return 1
}

case "${1:-}" in
  setup)
    s5_post /api/v1/trusted-proxies \
      "{\"name\":\"chain-bridge\",\"cidr\":\"$SUBNET\",\"header_type\":\"X_FORWARDED_FOR\",\"priority\":100}" \
      "$csrf" > /dev/null
    publish
    ;;
  cleanup)
    # 删除所有覆盖 docker 网桥连接源的 ENABLED 代理（不限名称：本脚本自建 chain-bridge
    # 与 stage5-gateway-tests 每次运行遗留的 docker-bridge；保留不覆盖连接源的演示种子）
    CONN_IP="172.19.0.1"
    for id in $(curl -s -b "/tmp/s5-sec_admin_s5.txt" "$API_URL/api/v1/trusted-proxies?page_size=100" | CONN_IP="$CONN_IP" python3 -c "
import json,sys,ipaddress,os
conn = ipaddress.ip_address(os.environ['CONN_IP'])
items = json.load(sys.stdin)['data'].get('items') or []
for i in items:
    try:
        if i.get('status') == 'ENABLED' and conn in ipaddress.ip_network(i['cidr']):
            print(i['id'])
    except Exception:
        pass" 2>/dev/null); do
      curl -s -o /dev/null -b "/tmp/s5-sec_admin_s5.txt" -X DELETE "$API_URL/api/v1/trusted-proxies/$id" -H "X-CSRF-Token: $csrf"
    done
    publish
    ;;
  *) echo "用法: chain_proxy.sh setup|cleanup" >&2; exit 2 ;;
esac
