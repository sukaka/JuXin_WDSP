// stage8_api_grpc_descriptors_test.go gRPC 描述符集管理面 + 发布侧端到端贯通测试
// （W14-DESC / P2-05 深化分片）。
//
// 链路：管理面 HTTP API 上传 protoset（POST /api/v1/api-security/grpc-descriptors，
//
//	multipart，权限 api_spec.manage）→ services 摘要落库 → 发布通道组装
//	（guardconfig.Provider.BuildGuardConfig，与 app.go 同一接线：
//	  SetGRPCDescriptorLister(NewGRPCDescriptorStore(db))）
//	→ 生成器产出 Caddy JSON：jiuzhang_guard 处理器内 api_grpc_descriptors 段
//	  （键名与网关 grpcDescriptorJSON 契约对应：name/content_base64）
//	→ 访问控制版本快照落库/回读保留描述符集（回滚路径不丢配置）
//	→ 删除驱动发布内容回落与 api_policy_version 确定性回归基线（P0-21 锚点）。
//
// 覆盖边界（如实声明）：本测试覆盖「配置 → 下发内容」的 server 侧全链与 CRUD 权限；
// 网关侧描述符编译/动态解码由模块级测试覆盖
// （gateway/modules/jiuzhang_guard/apigrpc_desc_test.go），两侧经同一下发契约键名衔接。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8APIGRPCDescriptorsE2E -count=1
package tests

import (
	"bytes"
	"context"
	"encoding/base64"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

// ---------- 测试用 FileDescriptorSet 线字节编码（server 无 protobuf 库，手工编码） ----------

func s8EncVarint(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func s8EncLen(fieldNum int, payload []byte) []byte {
	out := s8EncVarint(uint64(fieldNum<<3 | 2))
	out = append(out, s8EncVarint(uint64(len(payload)))...)
	return append(out, payload...)
}

func s8EncString(fieldNum int, s string) []byte { return s8EncLen(fieldNum, []byte(s)) }

// s8TestDescriptorSet 最小合法 FileDescriptorSet：
// 文件 echo.proto（包 pkg.echo.v1），服务 Echo，方法 Ping(.pkg.echo.v1.PingReq → .pkg.echo.v1.PingResp)。
func s8TestDescriptorSet() []byte {
	method := s8EncString(1, "Ping")
	method = append(method, s8EncString(2, ".pkg.echo.v1.PingReq")...)
	method = append(method, s8EncString(3, ".pkg.echo.v1.PingResp")...)
	svc := append(s8EncString(1, "Echo"), s8EncLen(2, method)...)
	file := s8EncString(1, "echo.proto")
	file = append(file, s8EncString(2, "pkg.echo.v1")...)
	file = append(file, s8EncLen(6, svc)...)
	return s8EncLen(1, file)
}

// s8GRPCDescProvider 按 app.go 同一接线构造发布组装器（WDSP 形态 + 描述符集读取）。
func s8GRPCDescProvider(env *testEnv) *guardconfig.Provider {
	p := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{
			APIDynamicProtection: true, APIProtectionMode: "PROTECT",
			APIEventsLog: "/var/log/caddy/api-runtime-events.log",
			GatewayNode:  "gw-test",
		})
	p.SetAPIModels(apimodels.NewStore(env.db))
	p.SetAPIAssets(apiassets.NewStore(env.db))
	p.SetGRPCDescriptorLister(guardconfig.NewGRPCDescriptorStore(env.db))
	return p
}

// s8UploadDescriptor multipart 上传描述符集（env 助手仅支持 JSON，multipart 自行构造）。
func s8UploadDescriptor(t *testing.T, env *testEnv, cookies []*http.Cookie, csrf, name, filename string, content []byte) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if name != "" {
		if err := mw.WriteField("name", name); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, env.server.URL+"/api/v1/api-security/grpc-descriptors", &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", csrf)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload descriptor: %v", err)
	}
	return resp
}

func TestStage8APIGRPCDescriptorsE2E(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	cookies, csrf := env.s5Login(t, "s8gd", "SECURITY_ADMIN")
	setBytes := s8TestDescriptorSet()

	// ---------- 1. 基线：无描述符集 → 不下发 api_grpc_descriptors 段 ----------
	cfg0, err := s8GRPCDescProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (baseline): %v", err)
	}
	if len(cfg0.APIGRPCDescriptors) != 0 {
		t.Fatalf("baseline descriptors = %+v, want empty", cfg0.APIGRPCDescriptors)
	}
	if j := s8GenerateGuardJSON(t, cfg0); strings.Contains(j, "api_grpc_descriptors") {
		t.Fatal("baseline caddy json must not contain api_grpc_descriptors")
	}

	// ---------- 2. 管理面 HTTP API 上传 protoset（201 + services 摘要） ----------
	resp := s8UploadDescriptor(t, env, cookies, csrf, "echo-desc", "echo.pb", setBytes)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload status = %d, want 201, body: %s", resp.StatusCode, readBodyString(t, resp))
	}
	var created apiResp
	readJSON(t, resp, &created)
	descID, _ := created.Data["id"].(string)
	if descID == "" {
		t.Fatalf("created descriptor id missing: %+v", created.Data)
	}
	// services 摘要：pkg.echo.v1.Echo / Ping（上传时线格式解析落库）
	svcRaw, _ := created.Data["services"].([]interface{})
	if len(svcRaw) != 1 {
		t.Fatalf("services summary = %+v", created.Data["services"])
	}
	svc0, _ := svcRaw[0].(map[string]interface{})
	if svc0["service"] != "pkg.echo.v1.Echo" {
		t.Fatalf("service summary = %+v", svc0)
	}

	// ---------- 3. 列表（摘要随列表返回，不携带 content 字节） ----------
	listResp := env.get(t, "/api/v1/api-security/grpc-descriptors", cookies)
	listed := s5OK(t, listResp, "list grpc descriptors")
	items, _ := listed.Data["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("list items = %+v", listed.Data)
	}
	item0, _ := items[0].(map[string]interface{})
	if item0["name"] != "echo-desc" || item0["status"] != "ENABLED" {
		t.Fatalf("list item = %+v", item0)
	}

	// ---------- 4. 发布通道组装：描述符集进入 GuardConfig（base64 契约） ----------
	cfg1, err := s8GRPCDescProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if len(cfg1.APIGRPCDescriptors) != 1 {
		t.Fatalf("descriptors = %+v, want 1", cfg1.APIGRPCDescriptors)
	}
	d := cfg1.APIGRPCDescriptors[0]
	if d.Name != "echo-desc" || d.ContentBase64 != base64.StdEncoding.EncodeToString(setBytes) {
		t.Fatalf("descriptor payload mismatch: name=%q base64 match=%v",
			d.Name, d.ContentBase64 == base64.StdEncoding.EncodeToString(setBytes))
	}
	// 策略版本戳随描述符内容确定性变化（P0-21 生效校验锚点）
	if cfg1.APIPolicyVersion == cfg0.APIPolicyVersion {
		t.Fatal("api_policy_version must change when grpc descriptors change")
	}

	// ---------- 5. 生成器：Caddy JSON 的 jiuzhang_guard 处理器含 api_grpc_descriptors ----------
	j := s8GenerateGuardJSON(t, cfg1)
	for _, want := range []string{
		`"handler":"jiuzhang_guard"`,
		`"api_grpc_descriptors":[{"name":"echo-desc","content_base64":"` + d.ContentBase64 + `"}]`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("caddy json missing %q", want)
		}
	}

	// ---------- 6. 版本快照落库/回读：描述符集随快照保留（回滚路径不丢配置） ----------
	versionID, err := s8GRPCDescProvider(env).SaveVersionSnapshot(ctx, cfg1, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save version snapshot: %v", err)
	}
	back, err := s8GRPCDescProvider(env).GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("get version config: %v", err)
	}
	if len(back.APIGRPCDescriptors) != 1 || back.APIGRPCDescriptors[0].Name != "echo-desc" {
		t.Fatalf("snapshot round-trip lost descriptors: %+v", back.APIGRPCDescriptors)
	}

	// ---------- 7. 同名上传 409；删除 → 发布内容回落（版本戳回归基线） ----------
	dup := s8UploadDescriptor(t, env, cookies, csrf, "echo-desc", "echo.pb", setBytes)
	s5Expect(t, dup, http.StatusConflict, "duplicate descriptor name")
	delResp := env.do(t, "DELETE", "/api/v1/api-security/grpc-descriptors/"+descID, "", cookies, csrf)
	s5OK(t, delResp, "delete grpc descriptor")
	cfg2, err := s8GRPCDescProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (deleted): %v", err)
	}
	if len(cfg2.APIGRPCDescriptors) != 0 {
		t.Fatalf("deleted descriptor must leave publish payload: %+v", cfg2.APIGRPCDescriptors)
	}
	if cfg2.APIPolicyVersion != cfg0.APIPolicyVersion {
		t.Fatal("api_policy_version must return to baseline when descriptor deleted（同内容恒同版）")
	}
	if j := s8GenerateGuardJSON(t, cfg2); strings.Contains(j, "api_grpc_descriptors") {
		t.Fatal("deleted descriptor must not appear in caddy json")
	}

	// 权限底线：未登录访问 401（与既有集成测试同一口径）
	unauth := env.do(t, "GET", "/api/v1/api-security/grpc-descriptors", "", nil, "")
	s5Expect(t, unauth, 401, "unauthenticated grpc descriptors list")
}
