#!/usr/bin/env bash
# eBPF 抓包程序再生成脚本（Phase 2）。
#
# 在锁定版本的 golang 容器内执行：bpftool 从运行内核 BTF 现取 vmlinux.h
# （CO-RE 所需，不提交入库），bpf2go（与 go.mod 锁定的 cilium/ebpf 同版本）
# 生成 tccapture_bpfel.go/.o 与 tccapture_bpfeb.go/.o 并提交。
#
# 用法（在 wdsp-agent/ 目录下）：
#   internal/ebpfcapture/generate.sh
#
# 需要 Docker；容器须可读取宿主机（Docker VM）/sys/kernel/btf/vmlinux（--privileged）。
# 生成环境无法直达 deb.debian.org 时可用 APT_MIRROR 指定镜像源。
set -euo pipefail

# 锁定生成环境（禁止 latest；与 go.mod 的 go 1.25.6 对齐）。
IMAGE="${GENERATE_IMAGE:-golang:1.25.6-bookworm}"
BPF2GO_VERSION="v0.22.0" # 与 go.mod github.com/cilium/ebpf 保持一致
APT_MIRROR="${APT_MIRROR:-mirrors.tuna.tsinghua.edu.cn}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

docker run --rm -i --privileged \
  -e BPF2GO_VERSION="${BPF2GO_VERSION}" \
  -e APT_MIRROR="${APT_MIRROR}" \
  -e GOPACKAGE=ebpfcapture \
  -v "${AGENT_DIR}:/src" -w /src \
  "${IMAGE}" bash -s <<'EOS'
set -euo pipefail
if [ -f /etc/apt/sources.list.d/debian.sources ]; then
  sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list.d/debian.sources
else
  sed -i "s|deb.debian.org|${APT_MIRROR}|g" /etc/apt/sources.list
fi
apt-get update -qq
apt-get install -y -qq --no-install-recommends clang llvm bpftool libbpf-dev >/dev/null
cd internal/ebpfcapture
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
go run "github.com/cilium/ebpf/cmd/bpf2go@${BPF2GO_VERSION}" \
  -cc clang -cflags '-O2 -g -Wall -Werror' -target bpfel,bpfeb \
  tcCapture tc_capture.c
rm -f vmlinux.h
echo '生成完成：tccapture_bpfel.go/.o tccapture_bpfeb.go/.o'
EOS
