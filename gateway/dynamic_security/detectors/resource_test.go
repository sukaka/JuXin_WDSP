package detectors

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func resetObjectTrackerForTest() {
	defaultObjectTracker = &objectTracker{entries: newLRU(objectTrackerMaxKeys)}
}

func TestResource_UnauthenticatedObjectAccess(t *testing.T) {
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/users/123",
		NormalizedPath: "/v1/users/{id}",
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx, p, "ip:192.0.2.1", "", nil)
	m := findMatch(ctx, "resource.unauthenticated_object_access")
	if m == nil {
		t.Fatalf("expected UNAUTHENTICATED_OBJECT_ACCESS, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["object_type"] != "numeric" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	if got := ctx.Extensions["api.object_id_type"]; got != "numeric" {
		t.Fatalf("extension api.object_id_type=%v", got)
	}
}

func TestResource_WithCredentialNoMatchButExtension(t *testing.T) {
	// 负例：携带凭据的对象访问不报（仍记录对象类型扩展供学习/关联）
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/users/550e8400-e29b-41d4-a716-446655440000",
		NormalizedPath: "/v1/users/{uuid}",
		Headers:        map[string]string{"authorization": "[redacted]"},
	}
	CheckResourceAccess(ctx, p, "auth:abc", "", nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("authenticated object access must not match, got %+v", ctx.CopyMatches())
	}
	if got := ctx.Extensions["api.object_id_type"]; got != "uuid" {
		t.Fatalf("extension api.object_id_type=%v", got)
	}
}

func TestResource_SequentialNumericIDWriteEscalates(t *testing.T) {
	resetObjectTrackerForTest()
	mk := func(idPath string) (*dsctx.RequestContext, *parser.Parsed) {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		p := &parser.Parsed{
			Method:         "PUT",
			RawPath:        "/v1/users/" + idPath,
			NormalizedPath: "/v1/users/{id}",
			Headers:        map[string]string{},
		}
		return ctx, p
	}
	// 第一次：无凭据写对象，仅 OBSERVE
	ctx1, p1 := mk("100")
	CheckResourceAccess(ctx1, p1, "ip:192.0.2.1", "", nil)
	m1 := findMatch(ctx1, "resource.unauthenticated_object_access")
	if m1 == nil || m1.Category != "OBSERVE" {
		t.Fatalf("first access should be OBSERVE, got %+v", ctx1.CopyMatches())
	}
	// 第二次：连续数字 ID + 写方法 + 无凭据 → 升 BLOCK 类 HIGH
	ctx2, p2 := mk("101")
	CheckResourceAccess(ctx2, p2, "ip:192.0.2.1", "", nil)
	m2 := findMatch(ctx2, "resource.unauthenticated_object_access")
	if m2 == nil {
		t.Fatalf("expected escalated match, got %+v", ctx2.CopyMatches())
	}
	if m2.Category != "BLOCK" || m2.Severity != "HIGH" || m2.ScoreDelta != 30 {
		t.Fatalf("bad escalated attrs: %+v", m2)
	}
	if m2.Evidence["pattern"] != "sequential_numeric_id" {
		t.Fatalf("bad escalated evidence: %+v", m2.Evidence)
	}
}

func TestResource_NonSequentialIDStaysObserve(t *testing.T) {
	// 负例：非连续数字 ID 不升级
	resetObjectTrackerForTest()
	mk := func(idPath string) (*dsctx.RequestContext, *parser.Parsed) {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		return ctx, &parser.Parsed{
			Method:         "POST",
			RawPath:        "/v1/users/" + idPath,
			NormalizedPath: "/v1/users/{id}",
			Headers:        map[string]string{},
		}
	}
	ctx1, p1 := mk("100")
	CheckResourceAccess(ctx1, p1, "ip:192.0.2.1", "", nil)
	ctx2, p2 := mk("500")
	CheckResourceAccess(ctx2, p2, "ip:192.0.2.1", "", nil)
	m2 := findMatch(ctx2, "resource.unauthenticated_object_access")
	if m2 == nil || m2.Category != "OBSERVE" {
		t.Fatalf("non-sequential id must stay OBSERVE, got %+v", ctx2.CopyMatches())
	}
}

func TestResource_NoObjectSegmentNoMatch(t *testing.T) {
	// 负例：无对象段
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/users/list",
		NormalizedPath: "/v1/users/list",
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx, p, "ip:192.0.2.1", "", nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("no object segment must not match, got %+v", ctx.CopyMatches())
	}
	if _, ok := ctx.Extensions["api.object_id_type"]; ok {
		t.Fatal("extension must not be set without object segment")
	}
}

// findAllMatches 返回指定 RuleID 的全部 match（多段/多参数逐段评估会产生多条）。
func findAllMatches(ctx *dsctx.RequestContext, ruleID string) []dsctx.DetectorMatch {
	var out []dsctx.DetectorMatch
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			out = append(out, m)
		}
	}
	return out
}

// 多对象段路径：/orgs/{id}/users/{id} 逐段评估，每段各产一条 OBSERVE match，
// 证据注明段位置；扩展 api.object_id_type 取首路径段，api.object_id_types 记录全部。
func TestResource_MultiSegmentPath(t *testing.T) {
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/orgs/5/users/123",
		NormalizedPath: "/orgs/{id}/users/{id}",
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx, p, "ip:192.0.2.1", "", nil)
	ms := findAllMatches(ctx, "resource.unauthenticated_object_access")
	if len(ms) != 2 {
		t.Fatalf("want 2 per-segment matches, got %+v", ctx.CopyMatches())
	}
	if ms[0].Evidence["segment"] != "1" || ms[1].Evidence["segment"] != "3" {
		t.Fatalf("bad segment evidence: %+v / %+v", ms[0].Evidence, ms[1].Evidence)
	}
	for _, m := range ms {
		if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
			t.Fatalf("bad attrs: %+v", m)
		}
		if m.Evidence["source"] != "path" || m.Evidence["object_type"] != "numeric" {
			t.Fatalf("bad evidence: %+v", m.Evidence)
		}
		// 对象 ID 原始值不得入证据
		for _, v := range m.Evidence {
			if v == "5" || v == "123" {
				t.Fatalf("raw object id leaked into evidence: %+v", m.Evidence)
			}
		}
	}
	if got := ctx.Extensions["api.object_id_type"]; got != "numeric" {
		t.Fatalf("extension api.object_id_type=%v", got)
	}
	types, ok := ctx.Extensions["api.object_id_types"].([]string)
	if !ok || len(types) != 2 || types[0] != "path:1:numeric" || types[1] != "path:3:numeric" {
		t.Fatalf("extension api.object_id_types=%v", ctx.Extensions["api.object_id_types"])
	}
}

// 多段升档游标按「同 identity+endpoint+段位置」隔离：orgs 段连续 +1（100→101）升 BLOCK，
// users 段（200→250 非连续）保持 OBSERVE。
func TestResource_MultiSegmentCursorPerPosition(t *testing.T) {
	resetObjectTrackerForTest()
	mk := func(orgID, userID string) (*dsctx.RequestContext, *parser.Parsed) {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		return ctx, &parser.Parsed{
			Method:         "PUT",
			RawPath:        "/orgs/" + orgID + "/users/" + userID,
			NormalizedPath: "/orgs/{id}/users/{id}",
			Headers:        map[string]string{},
		}
	}
	ctx1, p1 := mk("100", "200")
	CheckResourceAccess(ctx1, p1, "ip:192.0.2.1", "", nil)
	for _, m := range findAllMatches(ctx1, "resource.unauthenticated_object_access") {
		if m.Category != "OBSERVE" {
			t.Fatalf("first access must be OBSERVE, got %+v", m)
		}
	}
	ctx2, p2 := mk("101", "250")
	CheckResourceAccess(ctx2, p2, "ip:192.0.2.1", "", nil)
	ms := findAllMatches(ctx2, "resource.unauthenticated_object_access")
	if len(ms) != 2 {
		t.Fatalf("want 2 matches, got %+v", ctx2.CopyMatches())
	}
	seg1, seg3 := ms[0], ms[1]
	if seg1.Evidence["segment"] != "1" || seg3.Evidence["segment"] != "3" {
		t.Fatalf("bad segment order: %+v / %+v", seg1.Evidence, seg3.Evidence)
	}
	// 段 1（orgs：100→101 连续）升 BLOCK；段 3（users：200→250 非连续）不升
	if seg1.Category != "BLOCK" || seg1.Severity != "HIGH" || seg1.ScoreDelta != 30 {
		t.Fatalf("segment 1 should escalate: %+v", seg1)
	}
	if seg1.Evidence["pattern"] != "sequential_numeric_id" {
		t.Fatalf("segment 1 bad escalated evidence: %+v", seg1.Evidence)
	}
	if seg3.Category != "OBSERVE" {
		t.Fatalf("segment 3 non-sequential must stay OBSERVE: %+v", seg3)
	}
}

// Query 参数对象标识：纯数字参数值 + 无凭据 → 同一规则命中，证据注明 source=query 与参数名；
// 参数值绝不入证据；只认形态不认语义（参数名不含 id 语义也照判）。
func TestResource_QueryObjectParam(t *testing.T) {
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/orders",
		NormalizedPath: "/v1/orders",
		Query:          map[string]string{"filter": "987654"},
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx, p, "ip:192.0.2.1", "", nil)
	m := findMatch(ctx, "resource.unauthenticated_object_access")
	if m == nil {
		t.Fatalf("expected query object match, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.ScoreDelta != 15 {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["source"] != "query" || m.Evidence["param"] != "filter" || m.Evidence["object_type"] != "numeric" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	for _, v := range m.Evidence {
		if v == "987654" {
			t.Fatalf("query value leaked into evidence: %+v", m.Evidence)
		}
	}
	// 无路径对象段：api.object_id_type 不设置；api.object_id_types 含 query 条目
	if _, ok := ctx.Extensions["api.object_id_type"]; ok {
		t.Fatal("api.object_id_type must not be set without path object segment")
	}
	types, ok := ctx.Extensions["api.object_id_types"].([]string)
	if !ok || len(types) != 1 || types[0] != "query:filter:numeric" {
		t.Fatalf("extension api.object_id_types=%v", ctx.Extensions["api.object_id_types"])
	}
}

// Query 参数 UUID/长 hex 形态同样命中；有凭据时不报但对象类型事实写入扩展。
func TestResource_QueryObjectParamShapesAndCredential(t *testing.T) {
	resetObjectTrackerForTest()
	// UUID 形态 + 有凭据：不报，扩展照写
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/orders",
		NormalizedPath: "/v1/orders",
		Query:          map[string]string{"order": "550e8400-e29b-41d4-a716-446655440000"},
		Headers:        map[string]string{"authorization": "[redacted]"},
	}
	CheckResourceAccess(ctx, p, "auth:abc", "", nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("authenticated query object access must not match, got %+v", ctx.CopyMatches())
	}
	types, ok := ctx.Extensions["api.object_id_types"].([]string)
	if !ok || len(types) != 1 || types[0] != "query:order:uuid" {
		t.Fatalf("extension api.object_id_types=%v", ctx.Extensions["api.object_id_types"])
	}
	// 长 hex 形态 + 无凭据：命中
	ctx2 := dsctx.New("t", dsctx.DefaultParseLimits())
	p2 := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/files",
		NormalizedPath: "/v1/files",
		Query:          map[string]string{"digest": "0123456789abcdef"},
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx2, p2, "ip:192.0.2.1", "", nil)
	m := findMatch(ctx2, "resource.unauthenticated_object_access")
	if m == nil || m.Evidence["object_type"] != "hex" || m.Evidence["param"] != "digest" {
		t.Fatalf("expected hex query object match, got %+v", ctx2.CopyMatches())
	}
}

// Query 参数连续数字枚举升档：游标键含参数名，与路径段游标互不污染。
func TestResource_QuerySequentialEscalates(t *testing.T) {
	resetObjectTrackerForTest()
	mk := func(id string) (*dsctx.RequestContext, *parser.Parsed) {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		return ctx, &parser.Parsed{
			Method:         "PUT",
			RawPath:        "/v1/orders",
			NormalizedPath: "/v1/orders",
			Query:          map[string]string{"user": id},
			Headers:        map[string]string{},
		}
	}
	ctx1, p1 := mk("100")
	CheckResourceAccess(ctx1, p1, "ip:192.0.2.1", "", nil)
	m1 := findMatch(ctx1, "resource.unauthenticated_object_access")
	if m1 == nil || m1.Category != "OBSERVE" {
		t.Fatalf("first access should be OBSERVE, got %+v", ctx1.CopyMatches())
	}
	ctx2, p2 := mk("101")
	CheckResourceAccess(ctx2, p2, "ip:192.0.2.1", "", nil)
	m2 := findMatch(ctx2, "resource.unauthenticated_object_access")
	if m2 == nil {
		t.Fatalf("expected escalated match, got %+v", ctx2.CopyMatches())
	}
	if m2.Category != "BLOCK" || m2.Severity != "HIGH" || m2.ScoreDelta != 30 {
		t.Fatalf("bad escalated attrs: %+v", m2)
	}
	if m2.Evidence["source"] != "query" || m2.Evidence["param"] != "user" || m2.Evidence["pattern"] != "sequential_numeric_id" {
		t.Fatalf("bad escalated evidence: %+v", m2.Evidence)
	}
}

// 负例：Query 参数值不命中对象形态（非纯数字/UUID/长 hex）不报；
// 只认形态不认语义——参数名带 id 但值无对象形态同样不报。
func TestResource_QueryNonShapeNoMatch(t *testing.T) {
	resetObjectTrackerForTest()
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	p := &parser.Parsed{
		Method:         "GET",
		RawPath:        "/v1/orders",
		NormalizedPath: "/v1/orders",
		Query:          map[string]string{"user_id": "abc-def", "q": "hello world"},
		Headers:        map[string]string{},
	}
	CheckResourceAccess(ctx, p, "ip:192.0.2.1", "", nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("non-shape query values must not match, got %+v", ctx.CopyMatches())
	}
	if _, ok := ctx.Extensions["api.object_id_types"]; ok {
		t.Fatal("extension must not be set without object identifier")
	}
}

// 显式端点键：游标键使用调用方传入的管线统一口径（gRPC EndpointKeyPreserve 场景），
// 不再内部按归一化路径重算——两个归一化后不同的路径在同一显式端点键下游标连续即升档。
func TestResource_ExplicitEndpointKeyDrivesCursor(t *testing.T) {
	resetObjectTrackerForTest()
	const ek = "POST /pkg.OrderService/Update" // gRPC 管线 EndpointKeyPreserve 口径
	mk := func(rawPath, normPath, id string) (*dsctx.RequestContext, *parser.Parsed) {
		ctx := dsctx.New("t", dsctx.DefaultParseLimits())
		return ctx, &parser.Parsed{
			Method:         "POST",
			RawPath:        rawPath + id,
			NormalizedPath: normPath,
			Headers:        map[string]string{},
		}
	}
	// 第一次：/grpc/a/100（归一化 /grpc/a/{id}）
	ctx1, p1 := mk("/grpc/a/", "/grpc/a/{id}", "100")
	CheckResourceAccess(ctx1, p1, "ip:192.0.2.1", ek, nil)
	// 第二次：/grpc/b/101（归一化 /grpc/b/{id}，与第一次归一化键不同；
	// 若内部重算 EndpointKey 则两键互不相同不升档；显式 ek 相同 → 连续升 BLOCK）
	ctx2, p2 := mk("/grpc/b/", "/grpc/b/{id}", "101")
	CheckResourceAccess(ctx2, p2, "ip:192.0.2.1", ek, nil)
	m2 := findMatch(ctx2, "resource.unauthenticated_object_access")
	if m2 == nil {
		t.Fatalf("expected match, got %+v", ctx2.CopyMatches())
	}
	if m2.Category != "BLOCK" || m2.Evidence["pattern"] != "sequential_numeric_id" {
		t.Fatalf("explicit endpoint key must drive shared cursor, got %+v", m2)
	}
}
