package identitybehavior

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"go.uber.org/zap"
)

func TestIdentifierKeyIsStableAndHashed(t *testing.T) {
	query := url.Values{"Account_ID": {"alice"}, "object_id": {"42"}}
	got := identifierKey(query, []string{"account_id"})
	if got == "" || got == "alice" || got != identifierKey(query, []string{"ACCOUNT_ID"}) {
		t.Fatalf("identifier key is not normalized/hashed: %q", got)
	}
	if identifierKey(url.Values{"account_id": {""}}, []string{"account_id"}) != "" {
		t.Fatal("empty identifier must be ignored")
	}
}

func TestEnumerationExcludedBatchPath(t *testing.T) {
	if !enumerationExcludedPath("/v1/users/batch") {
		t.Fatal("batch endpoints must be excluded")
	}
	if !enumerationExcludedPath("/v1/Export") {
		t.Fatal("export endpoints must be excluded (case-insensitive)")
	}
	if enumerationExcludedPath("/v1/users") {
		t.Fatal("ordinary paths must remain eligible")
	}
}

// MED-1 回归：query 携带分页字段不再整请求跳过标识提取（「&page=1 即免疫枚举检测」
// 一键绕过），降级为剔除分页字段后照常提取账号/对象标识。
func TestPaginationFieldsNoLongerBypassExtraction(t *testing.T) {
	q := identifierQuery(url.Values{"account": {"alice"}, "page": {"1"}, "Limit": {"50"}})
	if _, ok := q["page"]; ok {
		t.Fatal("pagination fields must be stripped from identifier query")
	}
	if _, ok := q["Limit"]; ok {
		t.Fatal("pagination field match must be case-insensitive")
	}
	got := identifierKey(q, []string{"account"})
	if got == "" || got == "alice" {
		t.Fatalf("account identifier must still be extracted (hashed): %q", got)
	}
	if identifierKey(q, []string{"page"}) != "" {
		t.Fatal("pagination field itself must not be counted as an identifier")
	}
	// 仅分页字段、无标识字段：不产生账号/对象键（翻页本身不计入枚举统计）
	only := identifierQuery(url.Values{"cursor": {"abc"}, "offset": {"20"}})
	if identifierKey(only, []string{"account"}) != "" {
		t.Fatal("pure pagination traffic must not produce identifier keys")
	}
}

// 引擎级回归：Begin 对带分页参数的请求仍产出 accountKey（不再被 enumerationExcluded 整请求跳过）。
func TestBeginPaginatedRequestStillTracksAccount(t *testing.T) {
	threshold := int64(2)
	cfg, err := Compile(&Params{Enabled: true, AccountIdentifierFields: []string{"account"},
		AccountEnumThreshold: &threshold}, nil)
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v %v", cfg, err)
	}
	e := NewEngine(cfg, NewMemoryStore(0, zap.NewNop()), nil, Options{Logger: zap.NewNop()})
	r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/v1/users?account=alice&page=1", nil)
	r.RemoteAddr = "203.0.113.10:1"
	w, obs := e.Begin(httptest.NewRecorder(), r, clientip.Result{ClientIP: mustIP(t, "203.0.113.10")})
	if obs == nil {
		t.Fatal("observation expected")
	}
	if obs.accountKey == "" {
		t.Fatal("paginated request must still extract account identifier (MED-1 bypass)")
	}
	_ = w
	// 批量路径仍整请求跳过
	r2 := httptest.NewRequest(http.MethodGet, "http://waf-test.local/v1/users/sync?account=alice", nil)
	r2.RemoteAddr = "203.0.113.10:1"
	_, obs2 := e.Begin(httptest.NewRecorder(), r2, clientip.Result{ClientIP: mustIP(t, "203.0.113.10")})
	if obs2 == nil || obs2.accountKey != "" {
		t.Fatalf("batch path must remain excluded: %+v", obs2)
	}
}

func TestEnumerationSignalRequiresIdentityConfidence(t *testing.T) {
	threshold := int64(2)
	cfg, err := Compile(&Params{Enabled: true, AccountEnumThreshold: &threshold}, nil)
	if err != nil {
		t.Fatal(err)
	}
	snap := &Snapshot{}
	snap.Windows[Window5m].AccountEnumCount = 2
	if got := EvaluateRecon(cfg, snap, ""); len(got) != 0 {
		t.Fatalf("anonymous identity emitted enumeration signal: %#v", got)
	}
	snap.IdentityConfidence = 40
	snap.Windows[Window5m].RequestCount = 3
	snap.Windows[Window5m].Status401Count = 1
	got := EvaluateRecon(cfg, snap, "")
	if len(got) != 1 || got[0].Signal != SignalAccountEnumeration {
		t.Fatalf("expected account enumeration signal, got %#v", got)
	}
	if got[0].Metadata["request_count"] != int64(3) || got[0].Metadata["status_401_count"] != int64(1) {
		t.Fatalf("enumeration evidence missing response context: %#v", got[0].Metadata)
	}
	if fields, ok := got[0].Metadata["identifier_fields"].([]string); !ok || len(fields) == 0 {
		t.Fatalf("enumeration evidence missing identifier fields: %#v", got[0].Metadata)
	}
}
