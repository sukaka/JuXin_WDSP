// apigrpc_desc_test.go gRPC 描述符驱动字段级解析端到端（W14-DESC / P2-05 深化）：
// 配置 JSON → 注册表装配 → 请求解码 → 事件观测（decoded/descriptor 不落值）、
// 敏感字段命中证据纪律、无描述符零变化、失败集 Warn 跳过降级、Validate 结构校验。
package jiuzhang_guard

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// grpcDescE2ESetBase64 动态构造订单服务描述符集并 base64（与发布通道契约同形态）。
func grpcDescE2ESetBase64(t *testing.T) string {
	t.Helper()
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	field := func(name string, num int32) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{
			Name: proto.String(name), Number: proto.Int32(num),
			Type: str.Enum(), Label: optional.Enum(),
		}
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("orders.proto"),
		Package: proto.String("pkg.orders.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("CreateOrderReq"), Field: []*descriptorpb.FieldDescriptorProto{field("order_id", 1), field("buyer_phone", 2)}},
			{Name: proto.String("CreateOrderResp"), Field: []*descriptorpb.FieldDescriptorProto{field("id", 1)}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("OrderService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name: proto.String("CreateOrder"), InputType: proto.String(".pkg.orders.v1.CreateOrderReq"), OutputType: proto.String(".pkg.orders.v1.CreateOrderResp"),
			}},
		}},
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	if err != nil {
		t.Fatalf("marshal fds: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// grpcDescE2EGuard 构造注入描述符集与值级敏感规则的测试 Guard（走配置→装配路径）。
func grpcDescE2EGuard(t *testing.T, mode string) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, mode, nil)
	g.APIGRPCDescriptors = []grpcDescriptorJSON{{Name: "orders", ContentBase64: grpcDescE2ESetBase64(t)}}
	g.apiGRPCRegistry = g.buildAPIGRPCRegistry()
	if g.apiGRPCRegistry == nil {
		t.Fatal("registry must build from valid descriptor config")
	}
	g.APISensitiveValueRules = []detectors.SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json"}, Level: "SENSITIVE"},
	}
	return g, logPath
}

// grpcDescE2EMessage 编码 CreateOrder 请求消息帧（buyer_phone 为手机号形态）。
func grpcDescE2EMessage(t *testing.T) []byte {
	t.Helper()
	g, _ := grpcDescE2EGuard(t, "OBSERVE")
	md, _, ok := g.apiGRPCRegistry.Lookup("pkg.orders.v1.OrderService", "CreateOrder")
	if !ok {
		t.Fatal("lookup failed")
	}
	m := dynamicpb.NewMessage(md.Input())
	m.Set(m.Descriptor().Fields().ByName("order_id"), protoreflect.ValueOfString("o-1"))
	m.Set(m.Descriptor().Fields().ByName("buyer_phone"), protoreflect.ValueOfString("13800001111"))
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	f := make([]byte, 5+len(raw))
	binary.BigEndian.PutUint32(f[1:5], uint32(len(raw)))
	copy(f[5:], raw)
	return f
}

// 敏感字段端到端：PROTECT 放行（OBSERVE 级不定案）、体完整交付下游、事件
// grpc.observed 带 decoded=true/descriptor=orders、grpc.sensitive_field 证据
// 只含字段路径+规则名不落值。
func TestServeNext_GRPCDescriptorSensitiveE2E(t *testing.T) {
	g, logPath := grpcDescE2EGuard(t, "PROTECT")
	body := grpcDescE2EMessage(t)
	var gotBody []byte
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotBody = make([]byte, len(body))
		n, _ := r.Body.Read(gotBody)
		gotBody = gotBody[:n]
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := g.serveNext(httptest.NewRecorder(), grpcE2ERequest("req-grpc-desc-e2e-1", body), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if len(gotBody) != len(body) {
		t.Fatalf("downstream body corrupted: %d != %d", len(gotBody), len(body))
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	var observed, sensitive bool
	for _, d := range recs[0].Details {
		switch d.RuleID {
		case "grpc.observed":
			observed = true
			if d.Evidence["decoded"] != "true" || d.Evidence["descriptor"] != "orders" {
				t.Fatalf("observed evidence = %+v", d.Evidence)
			}
		case "grpc.sensitive_field":
			sensitive = true
			if d.Evidence["field"] != "buyer_phone" || d.Evidence["data_type"] != "phone" ||
				d.Evidence["location"] != "grpc" || d.Evidence["descriptor"] != "orders" {
				t.Fatalf("sensitive evidence = %+v", d.Evidence)
			}
			for k, v := range d.Evidence {
				if strings.Contains(v, "13800001111") {
					t.Fatalf("evidence must not carry value: %s in %+v", k, d.Evidence)
				}
			}
		}
	}
	if !observed || !sensitive {
		t.Fatalf("details observed/sensitive = %v/%v: %+v", observed, sensitive, recs[0].Details)
	}
	if recs[0].FinalAction != "OBSERVE" {
		t.Fatalf("observe-level sensitive hit must not block (OBSERVE expected), got %s", recs[0].FinalAction)
	}
}

// 无描述符下发：观测证据与 v1 逐键一致（无 decoded/descriptor 键）。
func TestServeNext_GRPCDescriptorAbsentZeroChange(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.APIGRPCAllowCompression = boolPtr(true)

	body := grpcE2EFrame(false, []byte{0x0a, 0x01})
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	if err := g.serveNext(httptest.NewRecorder(), grpcE2ERequest("req-grpc-desc-e2e-2", body), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	for _, d := range recs[0].Details {
		if d.RuleID != "grpc.observed" {
			continue
		}
		if _, ok := d.Evidence["decoded"]; ok {
			t.Fatalf("no registry must not add decoded key: %+v", d.Evidence)
		}
		if len(d.Evidence) != 2 {
			t.Fatalf("v1 evidence shape broken: %+v", d.Evidence)
		}
		return
	}
	t.Fatalf("grpc.observed missing: %+v", recs[0].Details)
}

// 失败集 Warn 跳过：坏集（非法 base64/非法 protoset）降级、好集正常登记；
// 全部失败注册表为 nil（与无描述符一致）。
func TestGuardBuildAPIGRPCRegistryWarnSkip(t *testing.T) {
	good := grpcDescE2ESetBase64(t)
	g := &Guard{logger: zap.NewNop()}
	g.APIGRPCDescriptors = []grpcDescriptorJSON{
		{Name: "bad-base64", ContentBase64: "!!!"},
		{Name: "bad-protoset", ContentBase64: base64.StdEncoding.EncodeToString([]byte{0x80})},
		{Name: "orders", ContentBase64: good},
	}
	reg := g.buildAPIGRPCRegistry()
	if reg == nil || reg.Sets() != 1 || reg.Methods() != 1 {
		t.Fatalf("registry = %+v", reg)
	}
	if _, setName, ok := reg.Lookup("pkg.orders.v1.OrderService", "CreateOrder"); !ok || setName != "orders" {
		t.Fatalf("good set must register, got %v/%q", ok, setName)
	}
	// 全部失败：nil（gRPC 处理与 v1 一致）
	g2 := &Guard{logger: zap.NewNop()}
	g2.APIGRPCDescriptors = []grpcDescriptorJSON{{Name: "bad", ContentBase64: "!!!"}}
	if reg := g2.buildAPIGRPCRegistry(); reg != nil {
		t.Fatalf("all-bad sets must yield nil registry: %+v", reg)
	}
	// 无配置：nil
	g3 := &Guard{logger: zap.NewNop()}
	if reg := g3.buildAPIGRPCRegistry(); reg != nil {
		t.Fatalf("no config must yield nil registry: %+v", reg)
	}
}

// 描述符集 Validate 结构校验：空名/超长名/非法 base64/超 1MiB 拒绝；合法通过。
func TestGuardValidateGRPCDescriptors(t *testing.T) {
	good := grpcDescE2ESetBase64(t)
	mk := func(sets ...grpcDescriptorJSON) *Guard {
		return &Guard{APIDynamicProtection: true, EventsLog: "/tmp/x.log", APIGRPCDescriptors: sets}
	}
	if err := mk(grpcDescriptorJSON{Name: "", ContentBase64: good}).Validate(); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if err := mk(grpcDescriptorJSON{Name: strings.Repeat("a", 129), ContentBase64: good}).Validate(); err == nil {
		t.Fatal("oversized name must be rejected")
	}
	if err := mk(grpcDescriptorJSON{Name: "x", ContentBase64: "!!!"}).Validate(); err == nil {
		t.Fatal("bad base64 must be rejected")
	}
	if err := mk(grpcDescriptorJSON{Name: "x", ContentBase64: base64.StdEncoding.EncodeToString(make([]byte, 2<<20))}).Validate(); err == nil {
		t.Fatal("oversized content must be rejected")
	}
	if err := mk(grpcDescriptorJSON{Name: "orders", ContentBase64: good}).Validate(); err != nil {
		t.Fatalf("valid descriptor set must pass: %v", err)
	}
}
