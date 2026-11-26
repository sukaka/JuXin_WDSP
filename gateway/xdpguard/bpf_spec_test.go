package xdpguard

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestBuildCollectionSpecAndInstructions(t *testing.T) {
	spec := BuildCollectionSpec()
	if err := ValidateCollectionSpec(spec); err != nil {
		t.Fatalf("ValidateCollectionSpec failed: %v", err)
	}

	// Verify exact map specifications.
	v4 := spec.Maps[MapBlockedV4]
	if v4.Type != ebpf.LPMTrie || v4.KeySize != 8 || v4.ValueSize != 4 || v4.MaxEntries != MaxBlockedV4Entries || v4.Flags != BPFFNoPrealloc {
		t.Fatalf("unexpected blocked_v4 spec: %+v", v4)
	}
	v6 := spec.Maps[MapBlockedV6]
	if v6.Type != ebpf.LPMTrie || v6.KeySize != 20 || v6.ValueSize != 4 || v6.MaxEntries != MaxBlockedV6Entries || v6.Flags != BPFFNoPrealloc {
		t.Fatalf("unexpected blocked_v6 spec: %+v", v6)
	}
	stats := spec.Maps[MapDropStats]
	if stats.Type != ebpf.PerCPUArray || stats.KeySize != 4 || stats.ValueSize != 8 || stats.MaxEntries != StatMapEntries {
		t.Fatalf("unexpected drop_stats spec: %+v", stats)
	}

	// Verify program metadata.
	prog := spec.Programs[ProgramName]
	if prog.Type != ebpf.XDP || prog.License != "MIT" || prog.SectionName != "xdp" {
		t.Fatalf("unexpected program spec: type=%v license=%q section=%q", prog.Type, prog.License, prog.SectionName)
	}

	insns := prog.Instructions
	symbols, err := insns.SymbolOffsets()
	if err != nil {
		t.Fatalf("SymbolOffsets failed (duplicate symbols?): %v", err)
	}
	for _, requiredSym := range []string{ProgramName, "vlan1", "vlan2", "check_ip", "parse_v4", "parse_v6", "ret_drop", "pass", "ret_pass"} {
		if _, ok := symbols[requiredSym]; !ok {
			t.Fatalf("missing expected symbol %q in instructions", requiredSym)
		}
	}

	mapRefs := make(map[string]int)
	lookupCalls := 0
	exits := 0
	boundsChecks := 0
	for i, ins := range insns {
		if ins.OpCode == asm.InvalidOpCode {
			t.Fatalf("instruction %d has InvalidOpCode: %v", i, ins)
		}
		if ins.IsLoadFromMap() {
			ref := ins.Reference()
			if _, ok := spec.Maps[ref]; !ok {
				t.Fatalf("instruction %d references unknown map %q", i, ref)
			}
			mapRefs[ref]++
			continue
		}
		if ref := ins.Reference(); ref != "" {
			targetIdx, ok := symbols[ref]
			if !ok {
				t.Fatalf("instruction %d jumps to undefined label %q", i, ref)
			}
			if targetIdx <= i {
				t.Fatalf("instruction %d jumps backwards to %q (%d <= %d); XDP program must be loop-free DAG", i, ref, targetIdx, i)
			}
		}
		if ins.IsBuiltinCall() && asm.BuiltinFunc(ins.Constant) == asm.FnMapLookupElem {
			lookupCalls++
		}
		if ins.OpCode.JumpOp() == asm.Exit {
			exits++
		}
		// Bounds check pattern: JGT reg against R3 (data_end).
		if ins.OpCode.Class() == asm.JumpClass && ins.OpCode.JumpOp() == asm.JGT && ins.Src == asm.R3 {
			boundsChecks++
		}
	}

	for _, m := range []string{MapBlockedV4, MapBlockedV6, MapDropStats} {
		if mapRefs[m] == 0 {
			t.Fatalf("map %q is never referenced by XDP instructions", m)
		}
	}
	if lookupCalls != 5 {
		t.Fatalf("expected 5 bpf_map_lookup_elem calls (v4, v6, 3x drop_stats), got %d", lookupCalls)
	}
	if exits != 2 {
		t.Fatalf("expected 2 exit instructions (XDP_DROP, XDP_PASS), got %d", exits)
	}
	// Ethernet (+14), VLAN1 (+4), VLAN2 (+4), IPv4 (+20), IPv6 (+40) = 5 packet bounds checks.
	if boundsChecks != 5 {
		t.Fatalf("expected 5 packet bounds checks against R3 (data_end), got %d", boundsChecks)
	}
}

func TestLPMKeyV4Serialization(t *testing.T) {
	if sz := binary.Size(LPMKeyV4{}); sz != 8 {
		t.Fatalf("LPMKeyV4 binary size = %d, want 8", sz)
	}

	// Host bits must be masked off; network byte order preserved.
	k, err := EncodeLPMKeyV4(netip.MustParsePrefix("203.0.113.77/24"))
	if err != nil {
		t.Fatalf("EncodeLPMKeyV4 error: %v", err)
	}
	if k.PrefixLen != 24 || k.Data != [4]byte{203, 0, 113, 0} {
		t.Fatalf("unexpected LPMKeyV4: %+v", k)
	}

	leBytes := k.MarshalBytes(binary.LittleEndian)
	wantLE := [8]byte{24, 0, 0, 0, 203, 0, 113, 0}
	if leBytes != wantLE {
		t.Fatalf("MarshalBytes(LE) = %v, want %v", leBytes, wantLE)
	}
	beBytes := k.MarshalBytes(binary.BigEndian)
	wantBE := [8]byte{0, 0, 0, 24, 203, 0, 113, 0}
	if beBytes != wantBE {
		t.Fatalf("MarshalBytes(BE) = %v, want %v", beBytes, wantBE)
	}

	decoded, err := DecodeLPMKeyV4(k)
	if err != nil {
		t.Fatalf("DecodeLPMKeyV4 error: %v", err)
	}
	if decoded != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("DecodeLPMKeyV4 = %s, want 203.0.113.0/24", decoded)
	}

	// IPv4-in-IPv6 prefix unmaps cleanly.
	kMapped, err := EncodeLPMKeyV4(netip.MustParsePrefix("::ffff:198.51.100.9/120"))
	if err != nil {
		t.Fatalf("EncodeLPMKeyV4 mapped error: %v", err)
	}
	if kMapped.PrefixLen != 24 || kMapped.Data != [4]byte{198, 51, 100, 0} {
		t.Fatalf("unexpected unmapped LPMKeyV4: %+v", kMapped)
	}

	if _, err := EncodeLPMKeyV4(netip.MustParsePrefix("2001:db8::/32")); err == nil {
		t.Fatal("expected error encoding IPv6 prefix as LPMKeyV4")
	}
	if _, err := DecodeLPMKeyV4(LPMKeyV4{PrefixLen: 33}); err == nil {
		t.Fatal("expected error decoding invalid prefixlen 33")
	}
}

func TestLPMKeyV6Serialization(t *testing.T) {
	if sz := binary.Size(LPMKeyV6{}); sz != 20 {
		t.Fatalf("LPMKeyV6 binary size = %d, want 20", sz)
	}

	k, err := EncodeLPMKeyV6(netip.MustParsePrefix("2001:db8:abcd::1234/48"))
	if err != nil {
		t.Fatalf("EncodeLPMKeyV6 error: %v", err)
	}
	wantData := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd}
	if k.PrefixLen != 48 || k.Data != wantData {
		t.Fatalf("unexpected LPMKeyV6: %+v", k)
	}

	leBytes := k.MarshalBytes(binary.LittleEndian)
	if leBytes[0] != 48 || leBytes[1] != 0 || leBytes[4] != 0x20 || leBytes[5] != 0x01 || leBytes[8] != 0xab || leBytes[9] != 0xcd {
		t.Fatalf("unexpected MarshalBytes(LE): %x", leBytes)
	}

	decoded, err := DecodeLPMKeyV6(k)
	if err != nil {
		t.Fatalf("DecodeLPMKeyV6 error: %v", err)
	}
	if decoded != netip.MustParsePrefix("2001:db8:abcd::/48") {
		t.Fatalf("DecodeLPMKeyV6 = %s, want 2001:db8:abcd::/48", decoded)
	}

	if _, err := EncodeLPMKeyV6(netip.MustParsePrefix("203.0.113.1/32")); err == nil {
		t.Fatal("expected error encoding IPv4 prefix as LPMKeyV6")
	}
	if _, err := DecodeLPMKeyV6(LPMKeyV6{PrefixLen: 129}); err == nil {
		t.Fatal("expected error decoding invalid prefixlen 129")
	}
}

func TestLoadCollectionSpecPaths(t *testing.T) {
	spec, err := LoadCollectionSpec("")
	if err != nil || spec == nil {
		t.Fatalf("LoadCollectionSpec empty path failed: %v", err)
	}

	tmpDir := t.TempDir()
	// Directory rejected.
	if _, err := LoadCollectionSpec(tmpDir); err == nil {
		t.Fatal("expected directory bpf-obj path to fail")
	}
	// Missing file rejected.
	if _, err := LoadCollectionSpec(filepath.Join(tmpDir, "missing.o")); err == nil {
		t.Fatal("expected missing bpf-obj path to fail")
	}
	// Non-ELF file rejected.
	badFile := filepath.Join(tmpDir, "bad.o")
	if err := os.WriteFile(badFile, []byte("not an elf"), 0o600); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	if _, err := LoadCollectionSpec(badFile); err == nil {
		t.Fatal("expected invalid ELF bpf-obj to fail")
	}
	// Symlink rejected.
	linkPath := filepath.Join(tmpDir, "link.o")
	if err := os.Symlink(badFile, linkPath); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := LoadCollectionSpec(linkPath); err == nil {
		t.Fatal("expected symlink bpf-obj path to fail")
	}
}
