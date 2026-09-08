#!/usr/bin/env bash
# 九章 TLS 会话票据主备共享 lab 验证（docs/HA_ACTIVE_STANDBY_DESIGN.md §7.2 V4）：
#   - node-a/node-b 同一票据密钥：在 a 取票据 → 在 b 恢复必须成功（Reused）；
#   - node-c 不同票据密钥（对照）：同一张票据在 c 恢复必须失败回退全握手（New）；
#   - 网关镜像须含 tls.stek.jiuzhang 模块（list-modules 断言）。
# 依赖：docker compose -f gateway/stek-lab/docker-compose.stek-lab.yml up -d
# 用法：bash gateway/stek-lab/stek-lab-tests.sh
set -u

TOTAL=0; PASS=0; FAIL=0; FAILED=()
record() { # name ok(1/0) [detail]
  local name="$1" ok="$2" detail="${3:-}"
  TOTAL=$((TOTAL+1))
  if [ "$ok" = "1" ]; then PASS=$((PASS+1)); echo "PASS  $name"
  else FAIL=$((FAIL+1)); FAILED+=("$name: $detail"); echo "FAIL  $name ($detail)"; fi
}
wait_cond() { # desc cmd...
  local desc="$1"; shift; local i
  for i in $(seq 1 30); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "[err] 等待超时: $desc"; return 1
}
CLIENT=steklab-client

echo "============================================================"
echo "九章 TLS 会话票据主备共享 lab 验证"
echo "node-a/node-b 同密钥（主备同一份发布 JSON）；node-c 异密钥（对照）"
echo "============================================================"

# ---------- 0. 前提 ----------
docker ps --format '{{.Names}}' | grep -qx steklab-node-a || { echo "ERROR: 容器未运行，请先 up 编排"; exit 1; }
docker exec steklab-node-a caddy list-modules 2>/dev/null | grep -q "tls.stek.jiuzhang" \
  && record "t0-stek-module-registered" 1 || record "t0-stek-module-registered" 0 "tls.stek.jiuzhang 未注册进网关镜像"
wait_cond "client 容器 openssl 就绪" docker exec "$CLIENT" sh -c "command -v openssl >/dev/null" \
  && record "t0-client-openssl" 1 || record "t0-client-openssl" 0 "openssl 未就绪"
wait_cond "node-a HTTPS 就绪" docker exec "$CLIENT" sh -c "openssl s_client -connect node-a:8443 -servername stek.test </dev/null 2>/dev/null | grep -q 'Cipher is'" \
  && record "t0-node-a-https" 1 || record "t0-node-a-https" 0 "node-a HTTPS 未就绪"
wait_cond "node-b HTTPS 就绪" docker exec "$CLIENT" sh -c "openssl s_client -connect node-b:8443 -servername stek.test </dev/null 2>/dev/null | grep -q 'Cipher is'" \
  && record "t0-node-b-https" 1 || record "t0-node-b-https" 0 "node-b HTTPS 未就绪"

# ---------- 1. 在 node-a 取票据 ----------
echo ""
echo "---- 1. node-a 取票据 ----"
docker exec "$CLIENT" sh -c "openssl s_client -connect node-a:8443 -servername stek.test -sess_out /tmp/sess.pem </dev/null >/dev/null 2>&1"
docker exec "$CLIENT" sh -c "test -s /tmp/sess.pem && openssl sess_id -in /tmp/sess.pem -noout -text 2>/dev/null | grep -q 'Session-ID'" \
  && record "t1-ticket-acquired" 1 || record "t1-ticket-acquired" 0 "未取得会话票据"

# ---------- 2. 同密钥 node-b 恢复：必须 Reused ----------
echo ""
echo "---- 2. node-b 跨节点恢复（同密钥） ----"
OUT_B=$(docker exec "$CLIENT" sh -c "openssl s_client -connect node-b:8443 -servername stek.test -sess_in /tmp/sess.pem </dev/null 2>&1")
echo "[info] node-b 握手首行: $OUT_B"
echo "$OUT_B" | grep -q "^Reused" \
  && record "t2-cross-node-resumed" 1 || record "t2-cross-node-resumed" 0 "跨节点恢复失败（应为 Reused）: $OUT_B"

# ---------- 3. 异密钥 node-c 恢复：必须 New（回退全握手） ----------
echo ""
echo "---- 3. node-c 恢复（异密钥对照） ----"
OUT_C=$(docker exec "$CLIENT" sh -c "openssl s_client -connect node-c:8443 -servername stek.test -sess_in /tmp/sess.pem </dev/null 2>&1")
echo "[info] node-c 握手首行: $OUT_C"
echo "$OUT_C" | grep -q "^New" \
  && record "t3-wrong-key-full-handshake" 1 || record "t3-wrong-key-full-handshake" 0 "异密钥应回退全握手（New）: $OUT_C"

echo ""
echo "============================================================"
echo "结果: PASS=$PASS FAIL=$FAIL (TOTAL=$TOTAL)"
if [ "$FAIL" -gt 0 ]; then
  echo "失败用例:"
  for f in "${FAILED[@]}"; do echo "  - $f"; done
  exit 1
fi
echo "全部通过"
