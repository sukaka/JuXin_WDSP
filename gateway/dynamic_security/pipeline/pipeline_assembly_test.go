// pipeline_assembly_test.go 第六波能力 pipeline 装配测试：凭据异常三检测器挂接、
// 配额/对象/分页/批量检测器挂接（配置未到=不启用）、§7 ctx 标识字段可读、耗时埋点。
package pipeline

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/metrics"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// asmBearerReq 构造携带强凭据（避免弱凭据噪音）与 JSON Accept 的 API 分类请求。
func asmBearerReq(t *testing.T, method, target, token, ua string) *http.Request {
	t.Helper()
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader(`{"a":1}`)
	} else {
		body = strings.NewReader("")
	}
	r, err := http.NewRequest(method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
	}
	r.Header.Set("Accept", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if ua != "" {
		r.Header.Set("User-Agent", ua)
	}
	return r
}

func asmProcess(t *testing.T, r *http.Request, cfg Config) *Result {
	t.Helper()
	res, err := Process(r, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Skipped {
		t.Fatal("expected pipeline to run")
	}
	return res
}

// ---------- 凭据异常三检测器挂接 ----------

// URL 明文凭据位置：无配置门槛，管线内直接产出 auth.credential_in_url。
func TestProcessCredentialLocationAnomalyMounted(t *testing.T) {
	r := asmBearerReq(t, http.MethodGet,
		"http://h/v1/asm-loc?next=Bearer%20secret-token-asm-loc-1", "", "")
	res := asmProcess(t, r, Config{Enabled: true, Mode: "OBSERVE"})
	if !hasRule(res, "auth.credential_in_url") {
		t.Fatalf("expected auth.credential_in_url, got %+v", res.Context.CopyMatches())
	}
}

// Token 跨应用：同一凭据先后在两个 ApplicationID 下出现（默认阈值 2）→ 第二次命中；
// 未供给 ApplicationID 时（应用未识别）永不命中——不凭空捏造归属。
func TestProcessCredentialCrossAppMounted(t *testing.T) {
	const token = "asm-crossapp-token-0123456789abcdef"
	cfg := Config{Enabled: true, Mode: "OBSERVE", ApplicationID: "app-asm-alpha"}
	res1 := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/asm-crossapp", token, ""), cfg)
	if hasRule(res1, "auth.credential_cross_app") {
		t.Fatal("first app below threshold must not match")
	}
	cfg.ApplicationID = "app-asm-beta"
	res2 := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/asm-crossapp", token, ""), cfg)
	if !hasRule(res2, "auth.credential_cross_app") {
		t.Fatalf("second distinct app must match, got %+v", res2.Context.CopyMatches())
	}

	// 负例：未供给 ApplicationID（零值）→ 跳过不判
	const token2 = "asm-crossapp-token-fedcba9876543210"
	noApp := Config{Enabled: true, Mode: "OBSERVE"}
	for i := 0; i < 3; i++ {
		res := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/asm-crossapp-na", token2, ""), noApp)
		if hasRule(res, "auth.credential_cross_app") {
			t.Fatal("empty ApplicationID must skip cross-app detection")
		}
	}
}

// 多设备窗口计数：同凭据滑窗内 3 个 UA 族（默认阈值）→ 第三次命中；
// 同请求叠加跨应用信号时 auth.env_anomaly_stack 计数包含新信号（验证挂接顺序在 stack 之前）。
func TestProcessCredentialDeviceSpreadMounted(t *testing.T) {
	const token = "asm-device-token-0123456789abcdef"
	cfg := Config{Enabled: true, Mode: "OBSERVE", ApplicationID: "app-asm-dev"}
	uas := []string{"Mozilla/5.0 Chrome/120.0", "python-requests/2.31", "Googlebot/2.1"}
	for i, ua := range uas {
		if i == 2 {
			cfg.ApplicationID = "app-asm-dev-2" // 第三请求同时制造跨应用信号
		}
		res := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/asm-device", token, ua), cfg)
		matched := hasRule(res, "auth.credential_device_spread")
		if i < 2 && matched {
			t.Fatalf("distinct %d below threshold must not match", i+1)
		}
		if i == 2 {
			if !matched {
				t.Fatalf("distinct 3 at threshold must match, got %+v", res.Context.CopyMatches())
			}
			if !hasRule(res, "auth.credential_cross_app") {
				t.Fatalf("third request changed app, expected cross_app, got %+v", res.Context.CopyMatches())
			}
			if !hasRule(res, "auth.env_anomaly_stack") {
				t.Fatalf("cross_app + device_spread in same request must stack, got %+v", res.Context.CopyMatches())
			}
		}
	}
}

// ---------- 配额/对象/分页/批量挂接（配置未到 = 不启用） ----------

// 小时/日配额：>0 阈值启用，超限产 ratelimit.api_hourly_quota / ratelimit.api_daily_quota。
func TestProcessAPIQuotaMounted(t *testing.T) {
	const token = "asm-quota-token-0123456789abcdef"
	cfg := Config{Enabled: true, Mode: "OBSERVE", APIQuotaPerHour: 2, APIQuotaPerDay: 2}
	for i := 1; i <= 3; i++ {
		res := asmProcess(t, asmBearerReq(t, http.MethodPost, "http://h/v1/asm-quota", token, ""), cfg)
		h, d := hasRule(res, "ratelimit.api_hourly_quota"), hasRule(res, "ratelimit.api_daily_quota")
		if i <= 2 && (h || d) {
			t.Fatalf("hit %d at/below limit must not match", i)
		}
		if i == 3 && (!h || !d) {
			t.Fatalf("hit 3 over limit must match hourly and daily, got %+v", res.Context.CopyMatches())
		}
	}
}

// 对象维度限速：同身份反复访问同对象超限命中；对象标识来自 §7 ctx 字段
// （res.Context.ObjectIdentifiers 非空证明管线内已落 ctx）。
func TestProcessObjectRateMounted(t *testing.T) {
	const token = "asm-object-token-0123456789abcdef"
	cfg := Config{Enabled: true, Mode: "OBSERVE", ObjectRatePerMinute: 2}
	for i := 1; i <= 3; i++ {
		res := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/asm-obj/42", token, ""), cfg)
		matched := hasRule(res, "ratelimit.object_rate")
		if i <= 2 && matched {
			t.Fatalf("hit %d at/below limit must not match", i)
		}
		if i == 3 && !matched {
			t.Fatalf("hit 3 over limit must match, got %+v", res.Context.CopyMatches())
		}
		ids := res.Context.CopyObjectIdentifiers()
		if len(ids) == 0 {
			t.Fatal("pipeline must populate ctx object_identifiers (§7)")
		}
		if ids[0].Source != "path" || ids[0].Param != "id" || ids[0].ValueHash == "" {
			t.Fatalf("bad object identifier: %+v", ids[0])
		}
	}
}

// 分页/批量上限：>0 阈值启用并命中；未配置（≤0）时即使超引擎默认值也不启用
// （limit=5000 超引擎默认 200、ids 200 个超默认 100，均不得命中——配置未到不启用，
// 不走默认值冒充已配置）。
func TestProcessPageBatchMountedAndDisabledByDefault(t *testing.T) {
	const token = "asm-page-token-0123456789abcdef"
	cfg := Config{Enabled: true, Mode: "OBSERVE", MaxPageSize: 5, MaxBatchSize: 2}
	res := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/asm-page?limit=10&ids=1,2,3", token, ""), cfg)
	if !hasRule(res, "ratelimit.page_size_exceeded") {
		t.Fatalf("limit=10 over MaxPageSize=5 must match, got %+v", res.Context.CopyMatches())
	}
	if !hasRule(res, "ratelimit.batch_size_exceeded") {
		t.Fatalf("ids 3 items over MaxBatchSize=2 must match, got %+v", res.Context.CopyMatches())
	}

	// 区分性负例：零配置下 ?limit=5000（超引擎默认 200）与 200 元素批量（超默认 100）均零行为
	var sb strings.Builder
	for i := 1; i <= 200; i++ {
		if i > 1 {
			sb.WriteByte(',')
		}
		sb.WriteString("1")
	}
	off := Config{Enabled: true, Mode: "OBSERVE"}
	res2 := asmProcess(t, asmBearerReq(t, http.MethodGet,
		"http://h/v1/asm-page-off?limit=5000&ids="+sb.String(), token, ""), off)
	for _, rule := range []string{
		"ratelimit.page_size_exceeded", "ratelimit.batch_size_exceeded",
		"ratelimit.api_hourly_quota", "ratelimit.api_daily_quota", "ratelimit.object_rate",
	} {
		if hasRule(res2, rule) {
			t.Fatalf("unconfigured quota %s must stay disabled (no engine default fallback)", rule)
		}
	}
}

// ---------- §7 ctx 标识字段可读 ----------

// device_fingerprint 在管线内落 ctx：与 parser.DeriveDeviceFingerprint 同口径同盐，
// 检测段前写入（供检测器读取），空 UA 不产出。
func TestProcessContextIdentifiersPopulated(t *testing.T) {
	r := asmBearerReq(t, http.MethodGet, "http://h/v1/asm-ctx/7", "", "Mozilla/5.0 Chrome/120.0")
	cfg := Config{Enabled: true, Mode: "OBSERVE", IdentitySalt: "asm-salt"}
	res := asmProcess(t, r, cfg)
	want := parser.DeriveDeviceFingerprint("asm-salt", r.Header)
	if want == "" {
		t.Fatal("fixture UA must derive a fingerprint")
	}
	if res.Context.DeviceFingerprint != want {
		t.Fatalf("ctx device_fingerprint = %q, want %q", res.Context.DeviceFingerprint, want)
	}
	if len(res.Context.CopyObjectIdentifiers()) == 0 {
		t.Fatal("path object param must populate ctx object_identifiers")
	}

	// 空 UA → 不产出指纹（与 DeriveDeviceFingerprint 口径一致）
	res2 := asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/asm-ctx/8", "", ""), cfg)
	if res2.Context.DeviceFingerprint != "" {
		t.Fatalf("empty UA must not derive fingerprint, got %q", res2.Context.DeviceFingerprint)
	}
}

// ---------- 耗时埋点 ----------

// 检测耗时：Process 执行后 api_detect_duration 计数 +1；响应解析耗时：JSON 响应
// ProcessResponse 后 +1，非 JSON 响应不计入。
func TestProcessDurationMetricsMounted(t *testing.T) {
	before := metrics.ReadSnapshot().Durations[metrics.DetectDuration].Count
	asmProcess(t, asmBearerReq(t, http.MethodGet, "http://h/v1/asm-metrics", "", ""),
		Config{Enabled: true, Mode: "OBSERVE"})
	if got := metrics.ReadSnapshot().Durations[metrics.DetectDuration].Count; got != before+1 {
		t.Fatalf("detect duration count = %d, want %d", got, before+1)
	}

	ctx := dsctx.New("asm-resp-metrics", dsctx.DefaultParseLimits())
	respCfg := ResponseConfig{Mode: decision.ModeObserve}
	before = metrics.ReadSnapshot().Durations[metrics.ResponseParseDuration].Count
	if _, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/json", Body: []byte(`{"a":1}`),
	}, respCfg); err != nil {
		t.Fatal(err)
	}
	if got := metrics.ReadSnapshot().Durations[metrics.ResponseParseDuration].Count; got != before+1 {
		t.Fatalf("response parse duration count = %d, want %d", got, before+1)
	}

	// 非 JSON 响应不解析、不计入
	if _, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "text/plain", Body: []byte("hello"),
	}, respCfg); err != nil {
		t.Fatal(err)
	}
	if got := metrics.ReadSnapshot().Durations[metrics.ResponseParseDuration].Count; got != before+1 {
		t.Fatalf("non-JSON response must not be timed, count = %d, want %d", got, before+1)
	}
}
