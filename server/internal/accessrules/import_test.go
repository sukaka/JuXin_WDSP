package accessrules

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeResolver 测试用应用编码解析器。
func fakeResolver(apps map[string]uuid.UUID) AppCodeResolver {
	return func(_ context.Context, code string) (uuid.UUID, error) {
		if id, ok := apps[code]; ok {
			return id, nil
		}
		return uuid.Nil, ErrAppNotFound
	}
}

func TestBuildImportInputs_TextMode(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	recs, err := parseTextLines("1.2.3.4\n10.0.0.0/8\nbad-address\n::ffff:192.168.1.1\n")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	def := ImportDefaults{RuleType: "deny", ScopeType: "global"}
	valid, errs := buildImportInputs(ctx, recs, def, fakeResolver(nil), nil, now)
	if len(valid) != 3 {
		t.Fatalf("应 3 行有效, 得到 %d: %+v", len(valid), valid)
	}
	if len(errs) != 1 {
		t.Fatalf("应 1 行错误, 得到 %d: %+v", len(errs), errs)
	}
	// 错误行定位
	if errs[0].Line != 3 || errs[0].Content != "bad-address" || errs[0].Code != ImportErrInvalid {
		t.Fatalf("错误行定位错误: %+v", errs[0])
	}
	// 默认值生效 + 地址规范化
	if valid[0].Input.RuleType != RuleTypeDeny || valid[0].Input.ScopeType != ScopeGlobal {
		t.Fatalf("默认参数未生效: %+v", valid[0].Input)
	}
	if valid[2].Input.Address != "192.168.1.1" {
		t.Fatalf("映射地址应归一为 v4: %+v", valid[2].Input)
	}
	if valid[0].Input.SourceType != SourceImport {
		t.Fatalf("导入来源应为 IMPORT: %+v", valid[0].Input)
	}
	if valid[0].Input.ValidityType != ValidityPermanent {
		t.Fatalf("无失效时间应为永久规则: %+v", valid[0].Input)
	}
}

func TestBuildImportInputs_RuleTypeRequired(t *testing.T) {
	ctx := context.Background()
	recs, _ := parseTextLines("1.2.3.4\n")
	valid, errs := buildImportInputs(ctx, recs, ImportDefaults{}, fakeResolver(nil), nil, time.Now())
	if len(valid) != 0 || len(errs) != 1 {
		t.Fatalf("缺少规则类型应为错误行: valid=%d errs=%+v", len(valid), errs)
	}
	if errs[0].Code != ImportErrInvalid {
		t.Fatalf("错误码应为 INVALID: %+v", errs[0])
	}
}

func TestBuildImportInputs_CSVWithAppCode(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	appID := uuid.New()
	content := "address,rule_type,scope_type,application_code,effective_until,reason\n" +
		"1.2.3.4,ALLOW,APPLICATION,myapp,,白名单\n" +
		"5.6.7.8,DENY,APPLICATION,noapp,,应用不存在\n" +
		"9.9.9.9,ALLOW,GLOBAL,myapp,,全局不应带应用\n"
	recs, err := parseCSVContent(content)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	valid, errs := buildImportInputs(ctx, recs, ImportDefaults{}, fakeResolver(map[string]uuid.UUID{"myapp": appID}), nil, now)
	if len(valid) != 1 {
		t.Fatalf("应 1 行有效: %+v", valid)
	}
	if valid[0].Input.ApplicationID == nil || *valid[0].Input.ApplicationID != appID {
		t.Fatalf("应用编码应解析为 ID: %+v", valid[0].Input)
	}
	if len(errs) != 2 {
		t.Fatalf("应 2 行错误: %+v", errs)
	}
	if errs[0].Code != ImportErrAppNotFound || errs[0].Line != 3 {
		t.Fatalf("应用不存在应为 APP_NOT_FOUND: %+v", errs[0])
	}
	if errs[1].Code != ImportErrInvalid || errs[1].Line != 4 {
		t.Fatalf("全局带应用应为 INVALID: %+v", errs[1])
	}
}

func TestBuildImportInputs_EffectiveUntil(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	future := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	content := "address,rule_type,effective_until\n" +
		"1.2.3.4,DENY," + future + "\n" +
		"5.6.7.8,DENY,2020-01-01\n" +
		"9.9.9.9,DENY,not-a-time\n"
	recs, _ := parseCSVContent(content)
	valid, errs := buildImportInputs(ctx, recs, ImportDefaults{}, fakeResolver(nil), nil, now)
	if len(valid) != 1 {
		t.Fatalf("应 1 行有效: valid=%+v errs=%+v", valid, errs)
	}
	if valid[0].Input.ValidityType != ValidityTemporary || valid[0].Input.EffectiveUntil == nil {
		t.Fatalf("有失效时间应为临时规则: %+v", valid[0].Input)
	}
	if len(errs) != 2 {
		t.Fatalf("过去时间与非法时间应为错误行: %+v", errs)
	}
}

func TestBuildImportInputs_DefaultUntilFromBody(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	until := now.Add(time.Hour)
	recs, _ := parseTextLines("1.2.3.4\n")
	def := ImportDefaults{RuleType: "DENY", EffectiveUntil: &until, Reason: "CC封禁"}
	valid, errs := buildImportInputs(ctx, recs, def, fakeResolver(nil), nil, now)
	if len(errs) != 0 || len(valid) != 1 {
		t.Fatalf("应全部有效: %+v", errs)
	}
	in := valid[0].Input
	if in.ValidityType != ValidityTemporary || in.EffectiveUntil == nil || !in.EffectiveUntil.Equal(until) {
		t.Fatalf("body 默认失效时间未生效: %+v", in)
	}
	if in.Reason != "CC封禁" {
		t.Fatalf("默认原因未生效: %+v", in)
	}
}

func TestBuildImportInputs_ChineseExportRoundTrip(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	future := now.Add(48 * time.Hour)
	appID := uuid.New()

	exported := RenderExportCSV([]Rule{
		{
			ID: uuid.New(), Name: "应用临时黑名单", RuleType: RuleTypeDeny,
			ScopeType: ScopeApplication, ApplicationID: &appID, Address: "198.51.100.0/24",
			IPVersion: IPVersion4, Priority: 100, Status: StatusActive,
			ValidityType: ValidityTemporary, EffectiveUntil: &future,
			Reason: "导出回灌测试,含逗号", SourceType: SourceManual, CreatedAt: now,
		},
		{
			ID: uuid.New(), Name: "全局永久白名单", RuleType: RuleTypeAllow,
			ScopeType: ScopeGlobal, Address: "2001:db8::1",
			IPVersion: IPVersion6, Priority: 50, Status: StatusActive,
			ValidityType: ValidityPermanent, Reason: "运维白名单",
			SourceType: SourceImport, CreatedAt: now,
		},
	}, map[uuid.UUID]string{appID: "shop"})

	recs, err := parseCSVContent(exported)
	if err != nil {
		t.Fatalf("导出的中文 CSV 应可直接回灌解析: %v", err)
	}
	valid, rowErrs := buildImportInputs(ctx, recs, ImportDefaults{}, fakeResolver(map[string]uuid.UUID{"shop": appID}), nil, now)
	if len(rowErrs) != 0 {
		t.Fatalf("回灌不应出现行错误: %+v", rowErrs)
	}
	if len(valid) != 2 {
		t.Fatalf("应回灌 2 条有效规则, 得到 %d", len(valid))
	}

	r0 := valid[0].Input
	if r0.RuleType != RuleTypeDeny || r0.ScopeType != ScopeApplication || r0.ApplicationID == nil || *r0.ApplicationID != appID ||
		r0.Address != "198.51.100.0/24" || r0.ValidityType != ValidityTemporary ||
		r0.EffectiveUntil == nil || !r0.EffectiveUntil.Equal(future) || r0.Reason != "导出回灌测试,含逗号" {
		t.Fatalf("第1条回灌结果失真: %+v", r0)
	}

	r1 := valid[1].Input
	if r1.RuleType != RuleTypeAllow || r1.ScopeType != ScopeGlobal || r1.ApplicationID != nil ||
		r1.Address != "2001:db8::1" || r1.ValidityType != ValidityPermanent || r1.EffectiveUntil != nil || r1.Reason != "运维白名单" {
		t.Fatalf("第2条回灌结果失真: %+v", r1)
	}
}

func TestBuildImportInputs_ChineseAndInvalidValues(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	appID := uuid.New()
	content := "\ufeff地址,规则类型,生效范围,应用编码,原因\n" +
		"1.2.3.4,白名单,指定应用,myapp,中文行\n" +
		"5.6.7.8,未知类型,全局,,非法规则类型\n" +
		"9.9.9.9,黑名单,非法范围,,非法范围\n"
	recs, err := parseCSVContent(content)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	valid, errs := buildImportInputs(ctx, recs, ImportDefaults{}, fakeResolver(map[string]uuid.UUID{"myapp": appID}), nil, now)
	if len(valid) != 1 || valid[0].Input.RuleType != RuleTypeAllow || valid[0].Input.ScopeType != ScopeApplication {
		t.Fatalf("中文枚举导入解析错误: valid=%+v", valid)
	}
	if len(errs) != 2 || errs[0].Code != ImportErrInvalid || errs[1].Code != ImportErrInvalid {
		t.Fatalf("非法中文枚举应产生 2 条 INVALID 错误: errs=%+v", errs)
	}
}

func TestBuildImportInputs_Protected(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	checker := &fakeChecker{protected: map[string]string{"1.2.3.4": "出口网关"}}
	recs, _ := parseTextLines("1.2.3.4\n5.6.7.8\n")

	t.Run("deny_blocked", func(t *testing.T) {
		def := ImportDefaults{RuleType: "DENY"}
		valid, errs := buildImportInputs(ctx, recs, def, fakeResolver(nil), checker, now)
		if len(valid) != 1 {
			t.Fatalf("保护地址应被拦截: valid=%+v", valid)
		}
		if len(errs) != 1 || errs[0].Code != ImportErrProtected || !strings.Contains(errs[0].Error, "出口网关") {
			t.Fatalf("应为 PROTECTED 错误且含保护地址名: %+v", errs)
		}
	})
	t.Run("allow_passes", func(t *testing.T) {
		def := ImportDefaults{RuleType: "ALLOW"}
		valid, errs := buildImportInputs(ctx, recs, def, fakeResolver(nil), checker, now)
		if len(valid) != 2 || len(errs) != 0 {
			t.Fatalf("ALLOW 不受保护地址限制: valid=%d errs=%+v", len(valid), errs)
		}
	})
}

func TestBuildImportInputs_DryRunPreviewShape(t *testing.T) {
	// 模拟预览模式的输入构造：全部校验通过，不产生错误
	ctx := context.Background()
	recs, _ := parseTextLines("1.2.3.4\n5.6.7.8\n")
	def := ImportDefaults{RuleType: "DENY"}
	valid, errs := buildImportInputs(ctx, recs, def, fakeResolver(nil), nil, time.Now())
	if len(errs) != 0 || len(valid) != 2 {
		t.Fatalf("预览输入应全部有效: %+v", errs)
	}
	for i, row := range valid {
		if row.Line != i+1 {
			t.Fatalf("行号不连续: %+v", row)
		}
		if row.Input.Name != row.Input.Address {
			t.Fatalf("导入规则名应取规范地址: %+v", row.Input)
		}
	}
}

func TestHasProtectedErr(t *testing.T) {
	if hasProtectedErr(nil) {
		t.Fatalf("空错误列表不应判为保护错误")
	}
	errs := []ImportRowError{{Code: ImportErrInvalid}, {Code: ImportErrProtected}}
	if !hasProtectedErr(errs) {
		t.Fatalf("应识别保护地址错误")
	}
}
