#!/usr/bin/env bash
# 生成 HTTP/3 旁路实验用自签证书（仅 deployment/http3-lab 使用，禁止复用到其他环境）。
# 产物：deployment/http3-lab/.runtime/tls.crt / tls.key（未提交 Git，见同目录 .gitignore）
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p .runtime

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout .runtime/tls.key -out .runtime/tls.crt \
  -days 7 -subj "/CN=http3lab.local" \
  -addext "subjectAltName=DNS:localhost,DNS:http3lab.local,IP:127.0.0.1"

echo "generated: .runtime/tls.crt .runtime/tls.key (7 天有效，仅本实验)"
