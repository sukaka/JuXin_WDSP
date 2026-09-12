//go:build ignore

// 九章 WDSP Agent eBPF/TC 旁路抓包程序（Phase 2）。
//
// 设计要点（docs/agents/WDSP_DISTRIBUTED_AGENT_DESIGN.md §6 第二阶段、§20/§72）：
//   - 挂点：TC ingress + egress（用户态经 cilium/ebpf TCX link 逐网卡挂载；
//     TCX 需内核 ≥ 6.6，旧内核由用户态 Fail-Open 回退 AF_PACKET）；
//   - 绝对旁路：程序只返回 TC_ACT_OK，永不丢包/改包（红线：不影响业务流量）；
//   - 内核初筛：非 TCP 不上送；端口集合用 BPF hash map（key=u16 主机序端口），
//     用户态热更新；方向过滤保留在用户态（与 AF_PACKET 路径同一 filter 语义源）；
//   - 上送：BPF ring buffer，事件 = 定长头 + 变长帧字节（cap_len ≤ snaplen ≤ 4096）；
//   - 丢包统计：ringbuf 满导致 output 失败时累加 dropped 计数 map（kernel_drops 来源）。
//
// 生成：见 generate.go（bpf2go，容器内 clang + bpftool dump vmlinux.h，CO-RE）。

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP     0x0800
#define ETH_P_IPV6   0x86DD
#define ETH_P_8021Q  0x8100
#define ETH_P_8021AD 0x88A8

#define IPPROTO_TCP_V 6

// TC 动作（<linux/pkt_cls.h> 为 UAPI 头，与 vmlinux.h 混用易冲突，直接定义）。
// 程序只用 TC_ACT_OK：绝对旁路，任何路径都不丢包/改包（红线）。
#define TC_ACT_OK 0

// MAX_SNAPLEN 单事件截取硬上限（与用户态钳制一致）。
// 取 4096 的理由：典型 MTU 1500 下完整帧 1514B，2048 默认即可覆盖；
// HTTP 嗅探需要的 16KB 是流重组后的累计窗口（httpparse 跨包累积），
// 单包截取无需求 16KB；ringbuf 吞吐 ≈ 事件数 × 事件字节数，
// snaplen 越大高 pps 下 ringbuf 越容易满（丢事件），故上限收敛在 4096。
#define MAX_SNAPLEN 4096

// 事件定长头（变长帧数据紧随其后，总长 = sizeof(hdr) + cap_len）。
// 内存布局即上送格式：字段均为定宽小端（BPF 目标默认小端；bpfeb 仅为编译
// 完整性生成，部署目标 amd64/arm64 均为小端）。
struct event_hdr {
	__u64 ts_ns;    // bpf_ktime_get_ns（CLOCK_MONOTONIC，用户态换算墙钟）
	__u32 ifindex;  // 挂载网卡 ifindex
	__u32 orig_len; // 线上原始帧长（skb->len，TC 层含 L2）
	__u32 cap_len;  // 实际上送字节数
	__u8 dir;       // TC 挂点方向：0=ingress(RX) 1=egress(TX)
	__u8 pad[3];
};

struct scratch {
	struct event_hdr hdr;
	__u8 data[MAX_SNAPLEN];
};

// 采集端口集合（key=主机序 u16 端口；value 占位）。用户态两阶段热更新。
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u16);
	__type(value, __u8);
} capture_ports SEC(".maps");

// 运行配置（idx 0 = snaplen；0 值由用户态加载前写入默认值）。
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} capture_cfg SEC(".maps");

// 上送 ring buffer（max_entries 可在用户态加载前按 2 的幂调整）。
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 默认 4MB
} events SEC(".maps");

// per-CPU 暂存（组事件 + ringbuf_output 拷贝；避免 BPF 栈 512B 限制）。
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct scratch);
} event_scratch SEC(".maps");

// 内核侧统计（idx 0=submitted 上送成功，idx 1=dropped ringbuf 满丢弃）。
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} capture_stats SEC(".maps");

static __always_inline void stat_inc(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&capture_stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

// capture 共享逻辑。返回值恒为 TC_ACT_OK（绝对旁路，永不影响业务流量）。
static __always_inline int capture(struct __sk_buff *skb, __u8 dir)
{
	__u32 l2 = 14; // Ethernet 头长
	__u16 proto = 0;
	__u16 sport = 0, dport = 0;

	if (bpf_skb_load_bytes(skb, 12, &proto, sizeof(proto)) < 0)
		return TC_ACT_OK;
	proto = bpf_ntohs(proto);
	if (proto == ETH_P_8021Q || proto == ETH_P_8021AD) {
		// 单层 VLAN tag（多层 QinQ 不展开，按非 TCP 丢弃处理）
		if (bpf_skb_load_bytes(skb, 16, &proto, sizeof(proto)) < 0)
			return TC_ACT_OK;
		proto = bpf_ntohs(proto);
		l2 = 18;
	}

	if (proto == ETH_P_IP) {
		__u8 ip_proto = 0, vihl = 0;
		if (bpf_skb_load_bytes(skb, l2 + 9, &ip_proto, 1) < 0)
			return TC_ACT_OK;
		if (ip_proto != IPPROTO_TCP_V)
			return TC_ACT_OK; // 非 TCP 不上送
		if (bpf_skb_load_bytes(skb, l2, &vihl, 1) < 0)
			return TC_ACT_OK;
		__u32 ihl = (vihl & 0x0f) * 4;
		if (ihl < 20)
			return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, l2 + ihl, &sport, 2) < 0)
			return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, l2 + ihl + 2, &dport, 2) < 0)
			return TC_ACT_OK;
	} else if (proto == ETH_P_IPV6) {
		__u8 nexthdr = 0;
		if (bpf_skb_load_bytes(skb, l2 + 6, &nexthdr, 1) < 0)
			return TC_ACT_OK;
		if (nexthdr != IPPROTO_TCP_V)
			return TC_ACT_OK; // 扩展头不遍历（限制见 README）
		if (bpf_skb_load_bytes(skb, l2 + 40, &sport, 2) < 0)
			return TC_ACT_OK;
		if (bpf_skb_load_bytes(skb, l2 + 40 + 2, &dport, 2) < 0)
			return TC_ACT_OK;
	} else {
		return TC_ACT_OK;
	}

	sport = bpf_ntohs(sport);
	dport = bpf_ntohs(dport);
	// 端口集合命中（dst 或 src 任一）；方向语义由用户态 filter 判定
	if (!bpf_map_lookup_elem(&capture_ports, &dport) &&
	    !bpf_map_lookup_elem(&capture_ports, &sport))
		return TC_ACT_OK;

	__u32 zero = 0;
	__u32 *snap = bpf_map_lookup_elem(&capture_cfg, &zero);
	// 用 __u64 做比较/钳制：避免 clang 对 u32 零扩展副本做边界检查，
	// 导致 verifier 无法把上界关联回实际使用的寄存器（6.x verifier 实测）
	__u64 snaplen = snap ? *snap : 2048;
	__u64 cap_len = skb->len;
	if (cap_len > snaplen)
		cap_len = snaplen;
	if (cap_len > MAX_SNAPLEN)
		cap_len = MAX_SNAPLEN;

	struct scratch *s = bpf_map_lookup_elem(&event_scratch, &zero);
	if (!s || cap_len == 0)
		return TC_ACT_OK;
	// 先拷帧再填头：cap_len 保持为寄存器局部量，
	// 避免 clang 从 map value 重载导致 verifier 丢失边界
	if (bpf_skb_load_bytes(skb, 0, s->data, cap_len) < 0)
		return TC_ACT_OK;
	s->hdr.ts_ns = bpf_ktime_get_ns();
	s->hdr.ifindex = skb->ifindex;
	s->hdr.orig_len = skb->len;
	s->hdr.cap_len = cap_len;
	s->hdr.dir = dir;
	s->hdr.pad[0] = s->hdr.pad[1] = s->hdr.pad[2] = 0;

	if (bpf_ringbuf_output(&events, s, sizeof(struct event_hdr) + cap_len, 0) == 0)
		stat_inc(0);
	else
		stat_inc(1); // ringbuf 满：内核侧丢事件计数（用户态上报 kernel_drops）
	return TC_ACT_OK;
}

SEC("tc")
int capture_ingress(struct __sk_buff *skb)
{
	return capture(skb, 0);
}

SEC("tc")
int capture_egress(struct __sk_buff *skb)
{
	return capture(skb, 1);
}

char __license[] SEC("license") = "Dual MIT/GPL";
