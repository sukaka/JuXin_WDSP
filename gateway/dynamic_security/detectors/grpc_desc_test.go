// grpc_desc_test.go gRPC 描述符驱动字段级解析测试（W14-DESC / P2-05 深化）：
// 动态解码正确性（描述符+消息以 protobuf 库动态构造）、敏感字段命中与证据不落值、
// decoded/descriptor 观测扩展、无描述符零变化、解码失败降级（grpc.decode_error
// 与 malformed_frame 区分）、压缩/无首帧降级、重复字段只统计不求值。
package detectors

import (
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// grpcDescTestSet 动态构造订单服务描述符集（与 grpcdesc 测试同构：
// CreateOrderReq{order_id, buyer_phone, buyer{name,id_card}, repeated tags}，
// 另加 WideReq{f01..f30 string} 供命中预算用例）。
func grpcDescTestSet(t *testing.T) []byte {
	t.Helper()
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	msgT := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	field := func(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string, label descriptorpb.FieldDescriptorProto_Label) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name:   proto.String(name),
			Number: proto.Int32(num),
			Type:   typ.Enum(),
			Label:  label.Enum(),
		}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	req := &descriptorpb.DescriptorProto{
		Name: proto.String("CreateOrderReq"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("order_id", 1, str, "", optional),
			field("buyer_phone", 2, str, "", optional),
			field("buyer", 3, msgT, ".pkg.orders.v1.Buyer", optional),
			field("tags", 4, str, "", repeated),
		},
	}
	buyer := &descriptorpb.DescriptorProto{
		Name: proto.String("Buyer"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("name", 1, str, "", optional),
			field("id_card", 2, str, "", optional),
		},
	}
	resp := &descriptorpb.DescriptorProto{
		Name:  proto.String("CreateOrderResp"),
		Field: []*descriptorpb.FieldDescriptorProto{field("id", 1, str, "", optional)},
	}
	wide := &descriptorpb.DescriptorProto{Name: proto.String("WideReq")}
	for i := 1; i <= 30; i++ {
		name := "f" + strings.Repeat("0", 2-len(itoa(i))) + itoa(i)
		wide.Field = append(wide.Field, field(name, int32(i), str, "", optional))
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:        proto.String("orders.proto"),
		Package:     proto.String("pkg.orders.v1"),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{req, buyer, resp, wide},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("OrderService"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{Name: proto.String("CreateOrder"), InputType: proto.String(".pkg.orders.v1.CreateOrderReq"), OutputType: proto.String(".pkg.orders.v1.CreateOrderResp")},
				{Name: proto.String("Wide"), InputType: proto.String(".pkg.orders.v1.WideReq"), OutputType: proto.String(".pkg.orders.v1.CreateOrderResp")},
			},
		}},
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	if err != nil {
		t.Fatalf("marshal fds: %v", err)
	}
	return raw
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// grpcDescTestRegistry 装配测试注册表。
func grpcDescTestRegistry(t *testing.T) *grpcdesc.Registry {
	t.Helper()
	r := grpcdesc.NewRegistry()
	if err := r.AddSet("orders", base64.StdEncoding.EncodeToString(grpcDescTestSet(t))); err != nil {
		t.Fatalf("AddSet: %v", err)
	}
	return r
}

// grpcDescTestMessage 构造 CreateOrder 请求消息字节（buyer_phone/id_card 为敏感形态）。
func grpcDescTestMessage(t *testing.T, r *grpcdesc.Registry) []byte {
	t.Helper()
	md, _, ok := r.Lookup("pkg.orders.v1.OrderService", "CreateOrder")
	if !ok {
		t.Fatal("lookup failed")
	}
	m := dynamicpb.NewMessage(md.Input())
	fields := m.Descriptor().Fields()
	m.Set(fields.ByName("order_id"), protoreflect.ValueOfString("o-1"))
	m.Set(fields.ByName("buyer_phone"), protoreflect.ValueOfString("13800001111"))
	buyer := dynamicpb.NewMessage(fields.ByName("buyer").Message())
	buyer.Set(buyer.Descriptor().Fields().ByName("name"), protoreflect.ValueOfString("zhang"))
	buyer.Set(buyer.Descriptor().Fields().ByName("id_card"), protoreflect.ValueOfString("110101199001011234"))
	m.Set(fields.ByName("buyer"), protoreflect.ValueOfMessage(buyer))
	tags := m.NewField(fields.ByName("tags")).List()
	tags.Append(protoreflect.ValueOfString("13800001111")) // 重复字段内敏感值：只统计不求值
	m.Set(fields.ByName("tags"), protoreflect.ValueOfList(tags))
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	return raw
}

// grpcDescValueRules 测试值级规则（手机号/身份证，json 位置——gRPC 与 JSON 体同规则）。
func grpcDescValueRules(t *testing.T) []CompiledSensitiveValueRule {
	t.Helper()
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json"}, Level: "SENSITIVE"},
		{DataType: "id_card", Regex: `^\d{17}[\dXx]$`, Locations: []string{"json"}, Level: "IMPORTANT"},
	})
	if err != nil {
		t.Fatalf("compile value rules: %v", err)
	}
	return rules
}

func grpcDescScan(r *grpcdesc.Registry, method string, rules []CompiledSensitiveValueRule) *GRPCDescriptorScan {
	return &GRPCDescriptorScan{
		Registry:   r,
		Service:    "pkg.orders.v1.OrderService",
		Method:     method,
		ValueRules: rules,
	}
}

// 敏感命中：decoded=true + descriptor 集名 + repeated_fields 计数；
// grpc.sensitive_field 证据只含字段路径+规则名+集名，绝不落值；OBSERVE 不定案。
func TestCheckGRPCDescriptorSensitive(t *testing.T) {
	reg := grpcDescTestRegistry(t)
	ctx := dsctx.New("req-grpc-desc-1", dsctx.DefaultParseLimits())
	p := &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 1, FirstMessage: grpcDescTestMessage(t, reg)}}
	CheckGRPC(ctx, p, true, grpcDescScan(reg, "CreateOrder", grpcDescValueRules(t)))

	obs := findGRPCMatch(ctx.CopyMatches(), "grpc.observed")
	if obs == nil {
		t.Fatalf("grpc.observed missing: %+v", ctx.CopyMatches())
	}
	if obs.Evidence["decoded"] != "true" || obs.Evidence["descriptor"] != "orders" ||
		obs.Evidence["repeated_fields"] != "1" {
		t.Fatalf("observed evidence = %+v", obs.Evidence)
	}
	// 敏感命中：buyer_phone（顶层）与 buyer.id_card（嵌套点路径）；重复字段 tags 内敏感值不求值
	var hits []string
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != "grpc.sensitive_field" {
			continue
		}
		if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
			t.Fatalf("sensitive discipline = %s/%s", m.Category, m.Severity)
		}
		if m.Evidence["location"] != "grpc" || m.Evidence["descriptor"] != "orders" {
			t.Fatalf("sensitive evidence = %+v", m.Evidence)
		}
		for k, v := range m.Evidence {
			if strings.Contains(v, "13800001111") || strings.Contains(v, "110101199001011234") {
				t.Fatalf("evidence must not carry field value: %s=%s in %+v", k, v, m.Evidence)
			}
		}
		hits = append(hits, m.Evidence["field"]+"="+m.Evidence["data_type"])
	}
	if len(hits) != 2 {
		t.Fatalf("sensitive hits = %v (repeated field must not be evaluated)", hits)
	}
	joined := strings.Join(hits, ",")
	if !strings.Contains(joined, "buyer_phone=phone") || !strings.Contains(joined, "buyer.id_card=id_card") {
		t.Fatalf("sensitive hits = %v", hits)
	}
	// OBSERVE 明细：PROTECT 模式不定案阻断
	if act := decision.Decide(ctx, decision.Input{Mode: decision.ModeProtect}); act != dsctx.ActionObserve &&
		act != dsctx.ActionAllow {
		t.Fatalf("observe-level grpc details must not block, got %s", act)
	}
}

// 无值级规则：解码观测照产（decoded=true），无敏感明细——解码与敏感判定解耦。
func TestCheckGRPCDescriptorDecodeOnly(t *testing.T) {
	reg := grpcDescTestRegistry(t)
	ctx := dsctx.New("req-grpc-desc-2", dsctx.DefaultParseLimits())
	p := &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 1, FirstMessage: grpcDescTestMessage(t, reg)}}
	CheckGRPC(ctx, p, true, grpcDescScan(reg, "CreateOrder", nil))
	obs := findGRPCMatch(ctx.CopyMatches(), "grpc.observed")
	if obs == nil || obs.Evidence["decoded"] != "true" || obs.Evidence["descriptor"] != "orders" {
		t.Fatalf("observed = %+v", obs)
	}
	if m := findGRPCMatch(ctx.CopyMatches(), "grpc.sensitive_field"); m != nil {
		t.Fatalf("no value rules must not flag: %+v", m)
	}
}

// 方法未登记：decoded=false 且不指名 descriptor（零新增明细，仅观测键）。
func TestCheckGRPCDescriptorMethodMiss(t *testing.T) {
	reg := grpcDescTestRegistry(t)
	ctx := dsctx.New("req-grpc-desc-3", dsctx.DefaultParseLimits())
	p := &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 1, FirstMessage: grpcDescTestMessage(t, reg)}}
	CheckGRPC(ctx, p, true, grpcDescScan(reg, "DeleteOrder", grpcDescValueRules(t)))
	obs := findGRPCMatch(ctx.CopyMatches(), "grpc.observed")
	if obs == nil || obs.Evidence["decoded"] != "false" {
		t.Fatalf("observed = %+v", obs)
	}
	if _, ok := obs.Evidence["descriptor"]; ok {
		t.Fatalf("unmatched method must not name descriptor: %+v", obs.Evidence)
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != "grpc.observed" {
			t.Fatalf("method miss must not add details: %+v", m)
		}
	}
}

// 无完整首帧（FirstMessage nil：首帧压缩/截断样本/无体）：方法命中仍指名 descriptor，
// decoded=false，不产错误明细——压缩帧不解码，降级为 v1 观测。
func TestCheckGRPCDescriptorNoFirstMessage(t *testing.T) {
	reg := grpcDescTestRegistry(t)
	ctx := dsctx.New("req-grpc-desc-4", dsctx.DefaultParseLimits())
	p := &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 1, CompressedSeen: true}}
	CheckGRPC(ctx, p, true, grpcDescScan(reg, "CreateOrder", grpcDescValueRules(t)))
	obs := findGRPCMatch(ctx.CopyMatches(), "grpc.observed")
	if obs == nil || obs.Evidence["decoded"] != "false" || obs.Evidence["descriptor"] != "orders" {
		t.Fatalf("observed = %+v", obs)
	}
	if m := findGRPCMatch(ctx.CopyMatches(), "grpc.decode_error"); m != nil {
		t.Fatalf("compressed/absent first frame must not be decode_error: %+v", m)
	}
}

// 线格式损坏：帧结构合法但消息体非合法 protobuf → grpc.decode_error（OBSERVE/LOW，
// 证据含 descriptor）；与 malformed_frame 严格区分（后者由帧结构校验产出，本用例不产）。
func TestCheckGRPCDescriptorDecodeError(t *testing.T) {
	reg := grpcDescTestRegistry(t)
	ctx := dsctx.New("req-grpc-desc-5", dsctx.DefaultParseLimits())
	p := &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 1, FirstMessage: []byte{0x0a, 0x7f}}} // 长度声明越界
	CheckGRPC(ctx, p, true, grpcDescScan(reg, "CreateOrder", grpcDescValueRules(t)))
	de := findGRPCMatch(ctx.CopyMatches(), "grpc.decode_error")
	if de == nil {
		t.Fatalf("grpc.decode_error missing: %+v", ctx.CopyMatches())
	}
	if de.Category != "OBSERVE" || de.Severity != "LOW" || de.Evidence["descriptor"] != "orders" {
		t.Fatalf("decode_error = %+v", de)
	}
	obs := findGRPCMatch(ctx.CopyMatches(), "grpc.observed")
	if obs == nil || obs.Evidence["decoded"] != "false" || obs.Evidence["descriptor"] != "orders" {
		t.Fatalf("observed = %+v", obs)
	}
	if m := findGRPCMatch(ctx.CopyMatches(), "grpc.malformed_frame"); m != nil {
		t.Fatalf("wire-corrupt message is not malformed_frame: %+v", m)
	}
	// decode_error 为 OBSERVE 级：PROTECT 模式不阻断
	if act := decision.Decide(ctx, decision.Input{Mode: decision.ModeProtect}); act == dsctx.ActionBlock {
		t.Fatal("decode_error must not block")
	}
}

// 命中预算：30 个 string 字段全部命中同一规则，明细条数封顶 maxGRPCSensitiveHits。
func TestCheckGRPCDescriptorHitBudget(t *testing.T) {
	reg := grpcDescTestRegistry(t)
	md, _, _ := reg.Lookup("pkg.orders.v1.OrderService", "Wide")
	m := dynamicpb.NewMessage(md.Input())
	fds := m.Descriptor().Fields()
	for i := 0; i < fds.Len(); i++ {
		m.Set(fds.Get(i), protoreflect.ValueOfString("13800001111"))
	}
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dsctx.New("req-grpc-desc-6", dsctx.DefaultParseLimits())
	p := &parser.Parsed{GRPC: &parser.GRPCInfo{MessageCount: 1, FirstMessage: raw}}
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{
		{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	CheckGRPC(ctx, p, true, grpcDescScan(reg, "Wide", rules))
	hits := 0
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "grpc.sensitive_field" {
			hits++
		}
	}
	if hits != maxGRPCSensitiveHits {
		t.Fatalf("hits = %d, want capped at %d", hits, maxGRPCSensitiveHits)
	}
}
