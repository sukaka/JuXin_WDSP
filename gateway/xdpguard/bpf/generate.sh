#!/usr/bin/env bash
# eBPF/XDP 丢包程序离线再生成脚本（Phase 9D-2，可选预编译 ELF 对象）。
#
# 日常构建无需执行本脚本：gateway/xdpguard/bpf_spec.go 使用纯 Go cilium/ebpf/asm
# 构造等价的 verifier-clean CollectionSpec，满足 CGO_ENABLED=0 零 clang 跨平台编译。
# 若运维需生成独立 CO-RE ELF 对象供 `--bpf-obj` 参数加载，可在锁定版本的 golang 容器内执行：
#   gateway/xdpguard/bpf/generate.sh
#
# 需要 Docker 且容器可读取宿主机（Docker VM）/sys/kernel/btf/vmlinux（--privileged）。
# 生成环境无法直达 deb.debian.org 时可用 APT_MIRROR 指定镜像源。
set -euo pipefail

# 锁定生成环境（禁止 latest；与 gateway/go.mod 的 go 1.25.6 及 cilium/ebpf v0.22.0 对齐）。
IMAGE="${GENERATE_IMAGE:-golang:1.25.6-bookworm}"
BPF2GO_VERSION="v0.22.0"
APT_MIRROR="${APT_MIRROR:-mirrors.tuna.tsinghua.edu.cn}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

docker run --rm -i --privileged \
  -e BPF2GO_VERSION="${BPF2GO_VERSION}" \
  -e APT_MIRROR="${APT_MIRROR}" \
  -e GOPACKAGE=xdpguard \
  -v "${GATEWAY_DIR}:/src" -w /src \
  "${IMAGE}" bash -s <<'EOS'
set -euo pipefail
if [ -f /etc/apt/sources.list.d/debian.sources ]; then
  sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources
else
  sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list
fi
apt-get update -qq
apt-get install -y -qq --no-install-recommends clang llvm bpftool libbpf-dev >/dev/null
cd xdpguard/bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
go run "github.com/cilium/ebpf/cmd/bpf2go@${BPF2GO_VERSION}" \
  -cc clang -cflags '-O2 -g -Wall -Werror' -target bpfel,bpfeb \
  xdpDrop xdp_drop.c
rm -f vmlinux.h
echo '生成完成：xdpdrop_bpfel.go/.o xdpdrop_bpfeb.go/.o'
EOS
