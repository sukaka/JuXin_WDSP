#!/usr/bin/env bash
# 生成两套自签压测专用证书（RSA-2048 与 ECDSA-P256），用于对比不同算法在兆芯 KH-40000 等平台上的 HTTPS CPS 性能。
# 安全提醒：生成产物仅限隔离压测环境，切勿提交到 Git 或用于生产站点！
set -euo pipefail

OUT_DIR="./test-certs"
DOMAIN="bench.wdsp.local"
DAYS=365

usage() {
  cat <<'EOF'
用法: gen-test-certs.sh [--out-dir DIR] [--domain NAME] [--days N]

输出：
  <out-dir>/bench-rsa2048.crt  / bench-rsa2048.key
  <out-dir>/bench-ecdsa-p256.crt / bench-ecdsa-p256.key
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --days) DAYS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v openssl >/dev/null 2>&1 || { echo "错误: 未找到 openssl 命令" >&2; exit 1; }
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

EXT_CFG="$(mktemp)"
trap 'rm -f "$EXT_CFG"' EXIT
cat <<EOF > "$EXT_CFG"
[req]
distinguished_name = dn
x509_extensions = v3_ext
prompt = no

[dn]
CN = ${DOMAIN}

[v3_ext]
subjectAltName = DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

# 1. RSA-2048
openssl req -x509 -nodes -newkey rsa:2048 -days "$DAYS" \
  -keyout "${OUT_DIR}/bench-rsa2048.key" \
  -out "${OUT_DIR}/bench-rsa2048.crt" \
  -config "$EXT_CFG" >/dev/null 2>&1
chmod 600 "${OUT_DIR}/bench-rsa2048.key"

# 2. ECDSA-P256 (prime256v1)
openssl ecparam -name prime256v1 -genkey -noout -out "${OUT_DIR}/bench-ecdsa-p256.key"
openssl req -new -x509 -days "$DAYS" \
  -key "${OUT_DIR}/bench-ecdsa-p256.key" \
  -out "${OUT_DIR}/bench-ecdsa-p256.crt" \
  -config "$EXT_CFG" >/dev/null 2>&1
chmod 600 "${OUT_DIR}/bench-ecdsa-p256.key"

echo "[certs] 已生成两套测试证书（域名: ${DOMAIN}，仅限隔离压测使用，请勿入库）:"
ls -lh "${OUT_DIR}"/bench-rsa2048.* "${OUT_DIR}"/bench-ecdsa-p256.*
