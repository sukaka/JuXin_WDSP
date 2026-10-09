package capability

import (
	"strings"
	"testing"
)

func nodeManifest() Manifest {
	return Manifest{
		ContractVersion: ContractVersion,
		NodeID:          "gw-1",
		ProductVersion:  "1.2.1",
		BuildDigest:     "sha256:abc",
		Protocols:       map[string]string{"graphql": "cost_v1", "grpc": "unary_g1", "mcp": "observe"},
		Detectors:       []DetectorCap{{Name: "authzdecide", Version: "az/1"}, {Name: "graphql.cost", Version: "cost/2"}},
		Actions:         []string{"block", "observe", "grpc_error"},
		Limits:          map[string]int64{"max_grpc_frame_bytes": 4194304},
		GeneratedAt:     "2026-10-03T00:00:00Z",
	}
}

func missingKeys(ms []Missing) string {
	var keys []string
	for _, m := range ms {
		keys = append(keys, m.Key)
	}
	return strings.Join(keys, ",")
}

func TestValidateOk(t *testing.T) {
	if msg := nodeManifest().Validate(); msg != "" {
		t.Fatalf("合法清单被误判: %s", msg)
	}
}

func TestValidateVersionMismatch(t *testing.T) {
	m := nodeManifest()
	m.ContractVersion = "ngc/9.9"
	if msg := m.Validate(); !strings.Contains(msg, "contract_version") {
		t.Fatalf("版本不一致未拒绝: %q", msg)
	}
}

func TestValidateBadLevel(t *testing.T) {
	m := nodeManifest()
	m.Protocols["graphql"] = "quantum"
	if msg := m.Validate(); !strings.Contains(msg, "protocols.graphql") {
		t.Fatalf("非法层级未拒绝: %q", msg)
	}
	// 未知协议键忽略（向前兼容）
	m.Protocols = map[string]string{"future-proto": "x"}
	if msg := m.Validate(); msg != "" {
		t.Fatalf("未知协议键应忽略: %s", msg)
	}
}

func TestCheckAllSatisfied(t *testing.T) {
	req := Manifest{
		ContractVersion: ContractVersion,
		Protocols:       map[string]string{"graphql": "parse", "grpc": "frame"},
		Detectors:       []DetectorCap{{Name: "authzdecide", Version: "az/1"}},
		Actions:         []string{"block"},
		Limits:          map[string]int64{"max_grpc_frame_bytes": 1048576},
	}
	if ms := CheckRequirements(req, nodeManifest()); len(ms) != 0 {
		t.Fatalf("全部满足仍报缺口: %v", missingKeys(ms))
	}
}

func TestCheckProtocolLevelTooLow(t *testing.T) {
	req := Manifest{
		ContractVersion: ContractVersion,
		Protocols:       map[string]string{"grpc": "stream_g2"},
	}
	ms := CheckRequirements(req, nodeManifest())
	if missingKeys(ms) != "protocols.grpc" {
		t.Fatalf("keys=%s want protocols.grpc", missingKeys(ms))
	}
	if ms[0].Actual != "unary_g1" {
		t.Fatalf("actual=%s want unary_g1", ms[0].Actual)
	}
}

func TestCheckDetectorMissingAndVersion(t *testing.T) {
	req := Manifest{
		ContractVersion: ContractVersion,
		Detectors: []DetectorCap{
			{Name: "authzdecide", Version: "az/2"}, // 节点 az/1 < 需求 az/2
			{Name: "nope", Version: "x/1"},         // 不存在
		},
	}
	ms := CheckRequirements(req, nodeManifest())
	got := missingKeys(ms)
	if !strings.Contains(got, "detectors.authzdecide") || !strings.Contains(got, "detectors.nope") {
		t.Fatalf("keys=%s", got)
	}
	// az/1 满足 az/1、cost/2 满足 cost/1
	req2 := Manifest{
		ContractVersion: ContractVersion,
		Detectors:       []DetectorCap{{Name: "authzdecide", Version: "az/1"}, {Name: "graphql.cost", Version: "cost/1"}},
	}
	if ms := CheckRequirements(req2, nodeManifest()); len(ms) != 0 {
		t.Fatalf("同版本应满足: %v", missingKeys(ms))
	}
}

func TestCheckActionMissing(t *testing.T) {
	req := Manifest{ContractVersion: ContractVersion, Actions: []string{"mcp_error"}}
	ms := CheckRequirements(req, nodeManifest())
	if missingKeys(ms) != "actions.mcp_error" {
		t.Fatalf("keys=%s want actions.mcp_error", missingKeys(ms))
	}
}

func TestCheckLimits(t *testing.T) {
	req := Manifest{
		ContractVersion: ContractVersion,
		Limits:          map[string]int64{"max_grpc_frame_bytes": 8388608, "max_ast_nodes": 0},
	}
	ms := CheckRequirements(req, nodeManifest())
	if len(ms) != 1 || ms[0].Key != "limits.max_grpc_frame_bytes" {
		t.Fatalf("ms=%v（应仅 limits 一项；需求 0 无约束）", ms)
	}
}

func TestCheckVersionMismatchListed(t *testing.T) {
	req := Manifest{ContractVersion: "ngc/9.9"}
	ms := CheckRequirements(req, nodeManifest())
	if len(ms) == 0 || ms[0].Key != "contract_version" {
		t.Fatalf("ms=%v want contract_version 缺口", ms)
	}
}
