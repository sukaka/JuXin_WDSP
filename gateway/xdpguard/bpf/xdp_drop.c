//go:build ignore

// 九章 WDSP Phase 9D-2 eBPF/XDP 内核态快速丢包程序（CO-RE）。
//
// 处理顺序：
//   1. 解析 Ethernet 头（14B）及可选 1~2 层 802.1Q / 802.1AD VLAN 标签；
//   2. IPv4（0x0800）：校验首部边界与版本/IHL，以源 IP 构造 /32 LPM key 查询 blocked_v4；
//      命中则累加 per-CPU 统计 drop_stats[0] 并返回 XDP_DROP；
//   3. IPv6（0x86DD）：校验 40B 首部边界与版本，以源 IP 构造 /128 LPM key 查询 blocked_v6；
//      命中则累加 per-CPU 统计 drop_stats[1] 并返回 XDP_DROP；
//   4. 其余流量（非 IP、畸形短包、未命中黑名单）累加 drop_stats[2] 并返回 XDP_PASS（Fail-Open）。
//
// 说明：
//   - 本文件用于需要外部预编译 ELF 对象（--bpf-obj）或离线审计时使用，
//     日常构建由 gateway/xdpguard/bpf_spec.go 纯 Go asm 构造等价指令集，无需 clang / CGO。
//   - 与 gateway/xdpguard/bpf_spec.go 保持相同的 Map 名、尺寸、键布局与统计索引。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

#define STAT_IDX_DROPPED_V4 0
#define STAT_IDX_DROPPED_V6 1
#define STAT_IDX_PASSED     2

#define MAX_BLOCKED_ENTRIES 131072

struct lpm_key_v4 {
	__u32 prefixlen;
	__u8  data[4];
};

struct lpm_key_v6 {
	__u32 prefixlen;
	__u8  data[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_BLOCKED_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v4);
	__type(value, __u32);
} blocked_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, MAX_BLOCKED_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_key_v6);
	__type(value, __u32);
} blocked_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} drop_stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *cnt = bpf_map_lookup_elem(&drop_stats, &idx);
	if (cnt)
		(*cnt)++;
}

SEC("xdp")
int xdp_jiuzhang_drop(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		goto pass;

	__u16 h_proto = bpf_ntohs(eth->h_proto);
	void *nh = (void *)(eth + 1);

	// 最多展开两层 VLAN（802.1Q / 802.1AD QinQ），无循环便于旧内核 verifier 验证。
	if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
		struct vlan_hdr *vh = nh;
		if ((void *)(vh + 1) > data_end)
			goto pass;
		h_proto = bpf_ntohs(vh->h_vlan_encapsulated_proto);
		nh = (void *)(vh + 1);

		if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
			struct vlan_hdr *vh2 = nh;
			if ((void *)(vh2 + 1) > data_end)
				goto pass;
			h_proto = bpf_ntohs(vh2->h_vlan_encapsulated_proto);
			nh = (void *)(vh2 + 1);
		}
	}

	if (h_proto == ETH_P_IP) {
		struct iphdr *iph = nh;
		if ((void *)(iph + 1) > data_end)
			goto pass;
		if (iph->version != 4 || iph->ihl < 5)
			goto pass;

		struct lpm_key_v4 key = {};
		key.prefixlen = 32;
		__builtin_memcpy(key.data, &iph->saddr, 4);

		if (bpf_map_lookup_elem(&blocked_v4, &key)) {
			stat_inc(STAT_IDX_DROPPED_V4);
			return XDP_DROP;
		}
		goto pass;
	}

	if (h_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6h = nh;
		if ((void *)(ip6h + 1) > data_end)
			goto pass;
		if (ip6h->version != 6)
			goto pass;

		struct lpm_key_v6 key = {};
		key.prefixlen = 128;
		__builtin_memcpy(key.data, &ip6h->saddr, 16);

		if (bpf_map_lookup_elem(&blocked_v6, &key)) {
			stat_inc(STAT_IDX_DROPPED_V6);
			return XDP_DROP;
		}
		goto pass;
	}

pass:
	stat_inc(STAT_IDX_PASSED);
	return XDP_PASS;
}

char __license[] SEC("license") = "MIT";
