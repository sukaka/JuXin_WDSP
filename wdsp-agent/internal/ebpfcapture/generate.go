// Package ebpfcapture eBPF/TC 旁路抓包后端（Phase 2）。
//
// 架构：tc_capture.c 经 bpf2go 生成 tccapture_bpf{el,eb}.go + .o（已提交，
// 日常 go build 无需 clang）；用户态 Backend（backend_linux.go）经
// cilium/ebpf TCX link 逐网卡挂载 ingress+egress，ringbuf 读事件后复用
// capture.DecodePacket 进入与 AF_PACKET 完全相同的 consumer 管线。
//
// 重新生成（需 Docker；vmlinux.h 由容器内 bpftool 现取，不入库）：
//
//	wdsp-agent/internal/ebpfcapture/generate.sh
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.22.0 -cc clang -cflags "-O2 -g -Wall -Werror" -target bpfel,bpfeb tcCapture tc_capture.c
package ebpfcapture
