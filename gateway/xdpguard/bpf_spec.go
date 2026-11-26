package xdpguard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	// ProgramName is the XDP program name in both built-in asm spec and external ELF objects.
	ProgramName = "xdp_jiuzhang_drop"

	// MapBlockedV4 is the IPv4 LPM Trie map name.
	MapBlockedV4 = "blocked_v4"
	// MapBlockedV6 is the IPv6 LPM Trie map name.
	MapBlockedV6 = "blocked_v6"
	// MapDropStats is the PerCPUArray telemetry counter map name.
	MapDropStats = "drop_stats"

	// MaxBlockedV4Entries is the maximum IPv4 CIDR entries stored in blocked_v4.
	MaxBlockedV4Entries = 131072
	// MaxBlockedV6Entries is the maximum IPv6 CIDR entries stored in blocked_v6.
	MaxBlockedV6Entries = 131072

	// BPFFNoPrealloc matches Linux UAPI BPF_F_NO_PREALLOC (required by BPF_MAP_TYPE_LPM_TRIE).
	BPFFNoPrealloc uint32 = 1

	// StatIdxDroppedV4 counts IPv4 packets dropped by XDP.
	StatIdxDroppedV4 uint32 = 0
	// StatIdxDroppedV6 counts IPv6 packets dropped by XDP.
	StatIdxDroppedV6 uint32 = 1
	// StatIdxPassed counts packets allowed to pass up the kernel stack.
	StatIdxPassed uint32 = 2
	// StatMapEntries is the fixed entry count of drop_stats.
	StatMapEntries uint32 = 3

	// XDP action constants matching Linux UAPI enum xdp_action.
	XDPDrop = 1
	XDPPass = 2

	// EtherType constants in numeric big-endian representation.
	ethPIP     = 0x0800
	ethPIPv6   = 0x86DD
	ethP8021Q  = 0x8100
	ethP8021AD = 0x88A8
)

// LPMKeyV4 matches Linux struct bpf_lpm_trie_key for IPv4 (8 bytes, zero padding):
// PrefixLen is in host byte order; Data is in network byte order (big-endian).
type LPMKeyV4 struct {
	PrefixLen uint32
	Data      [4]byte
}

// LPMKeyV6 matches Linux struct bpf_lpm_trie_key for IPv6 (20 bytes, zero padding):
// PrefixLen is in host byte order; Data is in network byte order (big-endian).
type LPMKeyV6 struct {
	PrefixLen uint32
	Data      [16]byte
}

// EncodeLPMKeyV4 encodes a canonical IPv4 netip.Prefix into an 8-byte LPM Trie key.
func EncodeLPMKeyV4(p netip.Prefix) (LPMKeyV4, error) {
	if !p.IsValid() {
		return LPMKeyV4{}, errors.New("invalid IPv4 prefix")
	}
	addr := p.Addr()
	if addr.Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(addr.Unmap(), p.Bits()-96)
		addr = p.Addr()
	}
	if !addr.Is4() {
		return LPMKeyV4{}, fmt.Errorf("prefix %s is not IPv4", p)
	}
	masked := p.Masked()
	return LPMKeyV4{
		PrefixLen: uint32(masked.Bits()),
		Data:      masked.Addr().As4(),
	}, nil
}

// DecodeLPMKeyV4 decodes an LPMKeyV4 back into a canonical netip.Prefix.
func DecodeLPMKeyV4(k LPMKeyV4) (netip.Prefix, error) {
	if k.PrefixLen > 32 {
		return netip.Prefix{}, fmt.Errorf("invalid IPv4 LPM prefixlen %d", k.PrefixLen)
	}
	return netip.PrefixFrom(netip.AddrFrom4(k.Data), int(k.PrefixLen)).Masked(), nil
}

// MarshalBytes serializes LPMKeyV4 using the specified byte order for PrefixLen
// while preserving Data in network byte order.
func (k LPMKeyV4) MarshalBytes(bo binary.ByteOrder) [8]byte {
	var out [8]byte
	bo.PutUint32(out[0:4], k.PrefixLen)
	copy(out[4:8], k.Data[:])
	return out
}

// EncodeLPMKeyV6 encodes a canonical IPv6 netip.Prefix into a 20-byte LPM Trie key.
func EncodeLPMKeyV6(p netip.Prefix) (LPMKeyV6, error) {
	if !p.IsValid() {
		return LPMKeyV6{}, errors.New("invalid IPv6 prefix")
	}
	addr := p.Addr()
	if !addr.Is6() || addr.Is4In6() {
		return LPMKeyV6{}, fmt.Errorf("prefix %s is not native IPv6", p)
	}
	masked := p.Masked()
	return LPMKeyV6{
		PrefixLen: uint32(masked.Bits()),
		Data:      masked.Addr().As16(),
	}, nil
}

// DecodeLPMKeyV6 decodes an LPMKeyV6 back into a canonical netip.Prefix.
func DecodeLPMKeyV6(k LPMKeyV6) (netip.Prefix, error) {
	if k.PrefixLen > 128 {
		return netip.Prefix{}, fmt.Errorf("invalid IPv6 LPM prefixlen %d", k.PrefixLen)
	}
	return netip.PrefixFrom(netip.AddrFrom16(k.Data), int(k.PrefixLen)).Masked(), nil
}

// MarshalBytes serializes LPMKeyV6 using the specified byte order for PrefixLen
// while preserving Data in network byte order.
func (k LPMKeyV6) MarshalBytes(bo binary.ByteOrder) [20]byte {
	var out [20]byte
	bo.PutUint32(out[0:4], k.PrefixLen)
	copy(out[4:20], k.Data[:])
	return out
}

// BuildCollectionSpec constructs a pure-Go, verifier-clean eBPF XDP CollectionSpec
// requiring zero clang or CGO at build time.
func BuildCollectionSpec() *ebpf.CollectionSpec {
	return &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			MapBlockedV4: {
				Name:       MapBlockedV4,
				Type:       ebpf.LPMTrie,
				KeySize:    8,
				ValueSize:  4,
				MaxEntries: MaxBlockedV4Entries,
				Flags:      BPFFNoPrealloc,
			},
			MapBlockedV6: {
				Name:       MapBlockedV6,
				Type:       ebpf.LPMTrie,
				KeySize:    20,
				ValueSize:  4,
				MaxEntries: MaxBlockedV6Entries,
				Flags:      BPFFNoPrealloc,
			},
			MapDropStats: {
				Name:       MapDropStats,
				Type:       ebpf.PerCPUArray,
				KeySize:    4,
				ValueSize:  8,
				MaxEntries: StatMapEntries,
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			ProgramName: {
				Name:         ProgramName,
				Type:         ebpf.XDP,
				SectionName:  "xdp",
				License:      "MIT",
				Instructions: buildXDPDropInstructions(),
			},
		},
	}
}

// LoadCollectionSpec returns the built-in pure-Go CollectionSpec when bpfObjPath is empty,
// or loads and validates a pre-compiled ELF object when bpfObjPath is provided.
func LoadCollectionSpec(bpfObjPath string) (*ebpf.CollectionSpec, error) {
	path := strings.TrimSpace(bpfObjPath)
	if path == "" {
		return BuildCollectionSpec(), nil
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("stat bpf object %q: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink bpf object path %q", path)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("bpf object path %q is not a regular file", path)
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load bpf object %q: %w", path, err)
	}
	if err := ValidateCollectionSpec(spec); err != nil {
		return nil, fmt.Errorf("validate bpf object %q: %w", path, err)
	}
	return spec, nil
}

// ValidateCollectionSpec verifies that a CollectionSpec provides the expected XDP program
// and map contracts (blocked_v4, blocked_v6, drop_stats).
func ValidateCollectionSpec(spec *ebpf.CollectionSpec) error {
	if spec == nil {
		return errors.New("collection spec is nil")
	}
	prog, ok := spec.Programs[ProgramName]
	if !ok || prog == nil {
		return fmt.Errorf("missing required program %q", ProgramName)
	}
	if prog.Type != ebpf.XDP {
		return fmt.Errorf("program %q has type %s, expected XDP", ProgramName, prog.Type)
	}
	if len(prog.Instructions) == 0 {
		return fmt.Errorf("program %q has empty instructions", ProgramName)
	}

	checkMap := func(name string, typ ebpf.MapType, keySize, valSize, minEntries uint32) error {
		m, exists := spec.Maps[name]
		if !exists || m == nil {
			return fmt.Errorf("missing required map %q", name)
		}
		if m.Type != typ {
			return fmt.Errorf("map %q has type %s, expected %s", name, m.Type, typ)
		}
		if m.KeySize != keySize {
			return fmt.Errorf("map %q key size=%d, expected %d", name, m.KeySize, keySize)
		}
		if m.ValueSize != valSize {
			return fmt.Errorf("map %q value size=%d, expected %d", name, m.ValueSize, valSize)
		}
		if m.MaxEntries < minEntries {
			return fmt.Errorf("map %q max entries=%d, expected >= %d", name, m.MaxEntries, minEntries)
		}
		return nil
	}

	if err := checkMap(MapBlockedV4, ebpf.LPMTrie, 8, 4, 1); err != nil {
		return err
	}
	if err := checkMap(MapBlockedV6, ebpf.LPMTrie, 20, 4, 1); err != nil {
		return err
	}
	if err := checkMap(MapDropStats, ebpf.PerCPUArray, 4, 8, StatMapEntries); err != nil {
		return err
	}
	return nil
}

// buildXDPDropInstructions constructs the bounds-checked, loop-free eBPF XDP bytecode:
//
// Stack layout (all 4-byte aligned, fully initialized before helper calls):
//
//	[fp - 8  .. fp - 1 ] : LPMKeyV4 (prefixlen=32, 4-byte IPv4 src in network byte order)
//	[fp - 24 .. fp - 5 ] : LPMKeyV6 (prefixlen=128, 16-byte IPv6 src in network byte order)
//	[fp - 32 .. fp - 29] : uint32 stat index (0=dropped_v4, 1=dropped_v6, 2=passed)
func buildXDPDropInstructions() asm.Instructions {
	return asm.Instructions{
		// Prologue: R1 = ctx (struct xdp_md *)
		// R2 = ctx->data, R3 = ctx->data_end (32-bit loads required by XDP verifier)
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word).WithSymbol(ProgramName),
		asm.LoadMem(asm.R3, asm.R1, 4, asm.Word),

		// Bounds check Ethernet header (14 bytes): if data + 14 > data_end -> pass
		asm.Mov.Reg(asm.R4, asm.R2),
		asm.Add.Imm(asm.R4, 14),
		asm.JGT.Reg(asm.R4, asm.R3, "pass"),

		// Load eth->h_proto at data + 12 and normalize wire big-endian to numeric value
		asm.LoadMem(asm.R5, asm.R2, 12, asm.Half),
		asm.HostTo(asm.BE, asm.R5, asm.Half),

		// Optional 802.1Q / 802.1AD VLAN tag #1
		asm.JEq.Imm(asm.R5, ethP8021Q, "vlan1"),
		asm.JEq.Imm(asm.R5, ethP8021AD, "vlan1"),
		asm.Ja.Label("check_ip"),

		// vlan1: R4 points to VLAN header (+14); advance 4 bytes with bounds check
		asm.Mov.Reg(asm.R2, asm.R4).WithSymbol("vlan1"),
		asm.Add.Imm(asm.R4, 4),
		asm.JGT.Reg(asm.R4, asm.R3, "pass"),
		asm.LoadMem(asm.R5, asm.R2, 2, asm.Half),
		asm.HostTo(asm.BE, asm.R5, asm.Half),

		// Optional 802.1Q / 802.1AD VLAN tag #2 (QinQ)
		asm.JEq.Imm(asm.R5, ethP8021Q, "vlan2"),
		asm.JEq.Imm(asm.R5, ethP8021AD, "vlan2"),
		asm.Ja.Label("check_ip"),

		// vlan2: R4 points to inner VLAN header (+18); advance 4 bytes with bounds check
		asm.Mov.Reg(asm.R2, asm.R4).WithSymbol("vlan2"),
		asm.Add.Imm(asm.R4, 4),
		asm.JGT.Reg(asm.R4, asm.R3, "pass"),
		asm.LoadMem(asm.R5, asm.R2, 2, asm.Half),
		asm.HostTo(asm.BE, asm.R5, asm.Half),

		// Dispatch L3 protocol (R4 = L3 header pointer, R3 = data_end)
		asm.JEq.Imm(asm.R5, ethPIP, "parse_v4").WithSymbol("check_ip"),
		asm.JEq.Imm(asm.R5, ethPIPv6, "parse_v6"),
		asm.Ja.Label("pass"),

		// parse_v4: bounds-check minimum 20-byte IPv4 header
		asm.Mov.Reg(asm.R2, asm.R4).WithSymbol("parse_v4"),
		asm.Add.Imm(asm.R2, 20),
		asm.JGT.Reg(asm.R2, asm.R3, "pass"),

		// Validate IPv4 version == 4 and IHL >= 5
		asm.LoadMem(asm.R2, asm.R4, 0, asm.Byte),
		asm.Mov.Reg(asm.R1, asm.R2),
		asm.RSh.Imm(asm.R1, 4),
		asm.JNE.Imm(asm.R1, 4, "pass"),
		asm.And.Imm(asm.R2, 0x0f),
		asm.JLT.Imm(asm.R2, 5, "pass"),

		// Construct LPMKeyV4 at [fp - 8 .. fp - 1]
		asm.StoreImm(asm.R10, -8, 32, asm.Word),
		asm.LoadMem(asm.R2, asm.R4, 12, asm.Word),
		asm.StoreMem(asm.R10, -4, asm.R2, asm.Word),

		// bpf_map_lookup_elem(&blocked_v4, fp - 8)
		asm.LoadMapPtr(asm.R1, 0).WithReference(MapBlockedV4),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),

		// Increment drop_stats[StatIdxDroppedV4] (per-CPU array: exclusive CPU access)
		asm.StoreImm(asm.R10, -32, int64(StatIdxDroppedV4), asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference(MapDropStats),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -32),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ret_drop"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),
		asm.Ja.Label("ret_drop"),

		// parse_v6: bounds-check 40-byte IPv6 header
		asm.Mov.Reg(asm.R2, asm.R4).WithSymbol("parse_v6"),
		asm.Add.Imm(asm.R2, 40),
		asm.JGT.Reg(asm.R2, asm.R3, "pass"),

		// Validate IPv6 version == 6
		asm.LoadMem(asm.R2, asm.R4, 0, asm.Byte),
		asm.RSh.Imm(asm.R2, 4),
		asm.JNE.Imm(asm.R2, 6, "pass"),

		// Construct LPMKeyV6 at [fp - 24 .. fp - 5] (src IP at IPv6 header offsets 8..23)
		asm.StoreImm(asm.R10, -24, 128, asm.Word),
		asm.LoadMem(asm.R2, asm.R4, 8, asm.Word),
		asm.StoreMem(asm.R10, -20, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R4, 12, asm.Word),
		asm.StoreMem(asm.R10, -16, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R4, 16, asm.Word),
		asm.StoreMem(asm.R10, -12, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R4, 20, asm.Word),
		asm.StoreMem(asm.R10, -8, asm.R2, asm.Word),

		// bpf_map_lookup_elem(&blocked_v6, fp - 24)
		asm.LoadMapPtr(asm.R1, 0).WithReference(MapBlockedV6),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -24),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "pass"),

		// Increment drop_stats[StatIdxDroppedV6]
		asm.StoreImm(asm.R10, -32, int64(StatIdxDroppedV6), asm.Word),
		asm.LoadMapPtr(asm.R1, 0).WithReference(MapDropStats),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -32),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ret_drop"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),

		// ret_drop: return XDP_DROP (1)
		asm.Mov.Imm(asm.R0, XDPDrop).WithSymbol("ret_drop"),
		asm.Return(),

		// pass: increment drop_stats[StatIdxPassed] and return XDP_PASS (2)
		asm.StoreImm(asm.R10, -32, int64(StatIdxPassed), asm.Word).WithSymbol("pass"),
		asm.LoadMapPtr(asm.R1, 0).WithReference(MapDropStats),
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -32),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ret_pass"),
		asm.LoadMem(asm.R1, asm.R0, 0, asm.DWord),
		asm.Add.Imm(asm.R1, 1),
		asm.StoreMem(asm.R0, 0, asm.R1, asm.DWord),

		// ret_pass: return XDP_PASS (2)
		asm.Mov.Imm(asm.R0, XDPPass).WithSymbol("ret_pass"),
		asm.Return(),
	}
}
