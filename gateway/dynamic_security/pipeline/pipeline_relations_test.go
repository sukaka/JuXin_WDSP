// pipeline_relations_test.go 参数条件关系经统一管线生效（W11-REL）：
// REQUIRES 缺失伴随参数在 PROTECT 定案 BLOCK、OBSERVE 降级不阻断；MUTEX 同现升级；
// CO_OCCURS 仅 INFO 观察永不阻断；证据不落值。
package pipeline

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// REQUIRES（QUERY page → page_size）：page 在、page_size 缺 → 违例。
func TestProcessParamRelationsRequires(t *testing.T) {
	rels := []detectors.ParamRelation{{
		EndpointKey:  "GET /v1/orders",
		RelationType: "REQUIRES",
		ParamA:       detectors.ParamRelationRef{Location: "QUERY", Name: "page"},
		ParamB:       detectors.ParamRelationRef{Location: "QUERY", Name: "page_size"},
	}}
	newReq := func() *http.Request {
		r, _ := http.NewRequest(http.MethodGet, "http://h/v1/orders?page=1", nil)
		return r
	}

	// PROTECT：BLOCK 类命中 → 定案 BLOCK
	res, err := Process(newReq(), Config{Enabled: true, Mode: "PROTECT", ParamRelations: rels}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "schema.relation_requires") {
		t.Fatalf("expected relation_requires, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("final=%s, want BLOCK", res.FinalAction)
	}
	// 证据不含观测值
	for _, m := range res.Context.CopyMatches() {
		for _, v := range m.Evidence {
			if v == "1" {
				t.Fatalf("raw value leaked into evidence: %+v", m.Evidence)
			}
		}
	}

	// OBSERVE：命中照常，动作降级不阻断
	res2, err := Process(newReq(), Config{Enabled: true, Mode: "OBSERVE", ParamRelations: rels}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res2, "schema.relation_requires") {
		t.Fatalf("expected relation_requires in OBSERVE, got %+v", res2.Context.CopyMatches())
	}
	if res2.FinalAction == dsctx.ActionBlock {
		t.Fatalf("OBSERVE must not block, final=%s", res2.FinalAction)
	}

	// 反例：page 与 page_size 同在 → 无违例、不阻断
	okReq, _ := http.NewRequest(http.MethodGet, "http://h/v1/orders?page=1&page_size=20", nil)
	res3, err := Process(okReq, Config{Enabled: true, Mode: "PROTECT", ParamRelations: rels}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res3, "schema.relation_requires") || res3.FinalAction == dsctx.ActionBlock {
		t.Fatalf("both present must pass, final=%s matches=%+v", res3.FinalAction, res3.Context.CopyMatches())
	}
}

// MUTEX（BODY buyer.phone × buyer.email）：同现 → 违例；CO_OCCURS：单侧出现仅 INFO。
func TestProcessParamRelationsMutexAndCoOccurs(t *testing.T) {
	mutexRel := detectors.ParamRelation{
		EndpointKey:  "POST /v1/orders",
		RelationType: "MUTEX",
		ParamA:       detectors.ParamRelationRef{Location: "BODY", Name: "phone", Path: "buyer.phone"},
		ParamB:       detectors.ParamRelationRef{Location: "BODY", Name: "email", Path: "buyer.email"},
	}
	newReq := func(body string) *http.Request {
		r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return r
	}

	// 同现：PROTECT 定案 BLOCK
	res, err := Process(newReq(`{"buyer":{"phone":"13800001111","email":"a@b.c"}}`),
		Config{Enabled: true, Mode: "PROTECT", ParamRelations: []detectors.ParamRelation{mutexRel}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "schema.relation_mutex") {
		t.Fatalf("expected relation_mutex, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction != dsctx.ActionBlock {
		t.Fatalf("final=%s, want BLOCK", res.FinalAction)
	}
	for _, m := range res.Context.CopyMatches() {
		for _, v := range m.Evidence {
			if strings.Contains(v, "13800001111") || strings.Contains(v, "a@b.c") {
				t.Fatalf("raw value leaked into evidence: %+v", m.Evidence)
			}
		}
	}

	// 单侧出现：MUTEX 通过
	res2, err := Process(newReq(`{"buyer":{"phone":"13800001111"}}`),
		Config{Enabled: true, Mode: "PROTECT", ParamRelations: []detectors.ParamRelation{mutexRel}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res2, "schema.relation_mutex") || res2.FinalAction == dsctx.ActionBlock {
		t.Fatalf("single side must pass MUTEX, final=%s", res2.FinalAction)
	}

	// CO_OCCURS 单侧出现：PROTECT 下也绝不阻断（INFO 明细不参与决策）
	coRel := detectors.ParamRelation{
		EndpointKey:  "POST /v1/orders",
		RelationType: "CO_OCCURS",
		ParamA:       detectors.ParamRelationRef{Location: "BODY", Name: "phone", Path: "buyer.phone"},
		ParamB:       detectors.ParamRelationRef{Location: "BODY", Name: "email", Path: "buyer.email"},
	}
	res3, err := Process(newReq(`{"buyer":{"phone":"13800001111"}}`),
		Config{Enabled: true, Mode: "PROTECT", ParamRelations: []detectors.ParamRelation{coRel}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res3, "schema.relation_cooccurs") {
		t.Fatalf("expected relation_cooccurs, got %+v", res3.Context.CopyMatches())
	}
	if res3.FinalAction == dsctx.ActionBlock {
		t.Fatalf("CO_OCCURS must never block, final=%s", res3.FinalAction)
	}
}
