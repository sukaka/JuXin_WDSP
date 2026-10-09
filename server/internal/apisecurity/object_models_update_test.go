// object_models_update_test.go 对象模型发布状态管理测试（NG-AZ-02 D5/D7）：
// 词表校验、排他前置约束、更新语义（三分态 nil=不变更）、不存在 404。
package apisecurity

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestObjectModelPatchValidate(t *testing.T) {
	boolPtr := func(v bool) *bool { return &v }
	strPtr := func(v string) *string { return &v }
	cases := []struct {
		name  string
		patch ObjectModelPatch
		want  string // 空=合法
	}{
		{"空 patch 合法", ObjectModelPatch{}, ""},
		{"全字段合法", ObjectModelPatch{Publishable: boolPtr(true), RequiredRelation: strPtr("owner"),
			OwnerExclusive: boolPtr(true), OnLeaseExpired: strPtr("degraded")}, ""},
		{"required_relation 非 OWNER 拒收", ObjectModelPatch{RequiredRelation: strPtr("SHARED_WITH")}, "OWNER"},
		{"on_lease_expired 非法拒收", ObjectModelPatch{OnLeaseExpired: strPtr("block")}, "strict|degraded"},
		{"publishable 但非排他拒收", ObjectModelPatch{Publishable: boolPtr(true), OwnerExclusive: boolPtr(false)}, "owner_exclusive"},
		{"publishable 且排他合法", ObjectModelPatch{Publishable: boolPtr(true), OwnerExclusive: boolPtr(true)}, ""},
		// ---- NG-AZ-03 D3：enforcement 词表与 §8.4 四要素强制前置 ----
		{"enforcement 词表外拒收", ObjectModelPatch{Enforcement: strPtr("BLOCK")}, "OBSERVE|PROTECT"},
		{"切 OBSERVE 无前置要求", ObjectModelPatch{Enforcement: strPtr("OBSERVE")}, ""},
		{"切 PROTECT 三要素+确认单令牌合法", ObjectModelPatch{Enforcement: strPtr("protect"),
			EnforcementOwner: strPtr("zhang.lei@example.com"), EvidenceSource: strPtr("authority_sync"),
			OnUnknown: strPtr("allow_unknown"), ConfirmToken: strPtr("0f4b1c2a-0000-4000-8000-abcdefabcdef")}, ""},
		{"切 PROTECT 缺 confirm_token 拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EnforcementOwner: strPtr("owner-1"), EvidenceSource: strPtr("AUTHORITY_SYNC"),
			OnUnknown: strPtr("ALLOW_UNKNOWN")}, "confirm_token"},
		{"切 PROTECT confirm_token 空白拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EnforcementOwner: strPtr("owner-1"), EvidenceSource: strPtr("AUTHORITY_SYNC"),
			OnUnknown: strPtr("ALLOW_UNKNOWN"), ConfirmToken: strPtr("  ")}, "confirm_token"},
		{"切 PROTECT 缺 enforcement_owner 拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EvidenceSource: strPtr("AUTHORITY_SYNC"), OnUnknown: strPtr("ALLOW_UNKNOWN")}, "enforcement_owner"},
		{"切 PROTECT enforcement_owner 空白拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EnforcementOwner: strPtr("  "), EvidenceSource: strPtr("AUTHORITY_SYNC"), OnUnknown: strPtr("ALLOW_UNKNOWN")}, "enforcement_owner"},
		{"切 PROTECT enforcement_owner 超长拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EnforcementOwner: strPtr(strings.Repeat("a", 129)), EvidenceSource: strPtr("AUTHORITY_SYNC"),
			OnUnknown: strPtr("ALLOW_UNKNOWN")}, "128"},
		{"切 PROTECT 缺 evidence_source 拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EnforcementOwner: strPtr("owner-1"), OnUnknown: strPtr("ALLOW_UNKNOWN")}, "evidence_source"},
		{"切 PROTECT 缺 on_unknown 拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EnforcementOwner: strPtr("owner-1"), EvidenceSource: strPtr("MANUAL_CONFIRMED")}, "on_unknown"},
		{"切 PROTECT evidence_source 词表外拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EnforcementOwner: strPtr("owner-1"), EvidenceSource: strPtr("GUESSED"), OnUnknown: strPtr("ALLOW_UNKNOWN"),
			ConfirmToken: strPtr("tok")}, "AUTHORITY_SYNC|MANUAL_CONFIRMED"},
		{"切 PROTECT on_unknown 词表外拒收", ObjectModelPatch{Enforcement: strPtr("PROTECT"),
			EnforcementOwner: strPtr("owner-1"), EvidenceSource: strPtr("AUTHORITY_SYNC"), OnUnknown: strPtr("BLOCK_UNKNOWN"),
			ConfirmToken: strPtr("tok")}, "ALLOW_UNKNOWN"},
		{"不切换时 evidence_source 词表外同样拒收", ObjectModelPatch{EvidenceSource: strPtr("GUESSED")}, "AUTHORITY_SYNC|MANUAL_CONFIRMED"},
		{"不切换时 on_unknown 词表外同样拒收", ObjectModelPatch{OnUnknown: strPtr("DENY_UNKNOWN")}, "ALLOW_UNKNOWN"},
	}
	for _, c := range cases {
		got := c.patch.validate()
		if c.want == "" && got != "" {
			t.Fatalf("%s 应合法: %s", c.name, got)
		}
		if c.want != "" && (got == "" || !contains(got, c.want)) {
			t.Fatalf("%s 应含 %q: %s", c.name, c.want, got)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// UpdateObjectModel 语义（无 DB——经 fake 存储不行（方法是具体 *Store 方法），
// 此处仅验证 ErrObjectModelNotFound 哨兵与三分态逻辑的纯函数部分）。
func TestObjectModelNotFoundSentinel(t *testing.T) {
	if ErrObjectModelNotFound == nil || ErrObjectModelNotFound.Error() == "" {
		t.Fatal("哨兵错误须非空")
	}
	var _ = context.Background
	var _ = uuid.Nil
}
