// pipeline_grpc_desc_test.go gRPC 描述符驱动字段级解析管线集成测试（W14-DESC / P2-05 深化）：
// 注册表下发时 decoded/descriptor 观测扩展与敏感字段命中（证据不落值）、
// 无注册表与 v1 完全一致（观测证据无 decoded 键）、解码失败降级 grpc.decode_error。
package pipeline

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
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
)

// grpcDescPipeRegistry 动态构造订单服务描述符注册表（CreateOrderReq{order_id,buyer_phone}）。
func grpcDescPipeRegistry(t *testing.T) *grpcdesc.Registry {
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
	r := grpcdesc.NewRegistry()
	if err := r.AddSet("orders", base64.StdEncoding.EncodeToString(raw)); err != nil {
		t.Fatalf("AddSet: %v", err)
	}
	return r
}

// grpcDescPipeMessage 编码 CreateOrder 请求消息（buyer_phone 为手机号形态）。
func grpcDescPipeMessage(t *testing.T, r *grpcdesc.Registry, phone string) []byte {
	t.Helper()
	md, _, ok := r.Lookup("pkg.orders.v1.OrderService", "CreateOrder")
	if !ok {
		t.Fatal("lookup failed")
	}
	m := dynamicpb.NewMessage(md.Input())
	m.Set(m.Descriptor().Fields().ByName("order_id"), protoreflect.ValueOfString("o-1"))
	m.Set(m.Descriptor().Fields().ByName("buyer_phone"), protoreflect.ValueOfString(phone))
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	return raw
}

func findPipeMatch(res *Result, ruleID string) *dsctx.DetectorMatch {
	for i, m := range res.Context.CopyMatches() {
		if m.RuleID == ruleID {
			ms := res.Context.CopyMatches()
			return &ms[i]
		}
	}
	return nil
}

// 注册表 + 值级规则：decoded=true/descriptor=orders 观测扩展；手机号命中
// grpc.sensitive_field（证据只含字段路径+规则名不落值）；OBSERVE 级不阻断。
func TestProcessGRPCDescriptorSensitive(t *testing.T) {
	reg := grpcDescPipeRegistry(t)
	body := grpcPipeFrame(false, grpcDescPipeMessage(t, reg, "13800001111"))
	res, err := Process(grpcPipeRequest(body), Config{
		Enabled: true, Mode: decision.ModeProtect,
		GRPCDescriptors: reg,
		SensitiveValueRules: []detectors.SensitiveValueRule{
			{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"json"}, Level: "SENSITIVE"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obs := findPipeMatch(res, "grpc.observed")
	if obs == nil || obs.Evidence["decoded"] != "true" || obs.Evidence["descriptor"] != "orders" {
		t.Fatalf("observed = %+v", obs)
	}
	hit := findPipeMatch(res, "grpc.sensitive_field")
	if hit == nil {
		t.Fatalf("grpc.sensitive_field missing: %+v", res.Context.CopyMatches())
	}
	if hit.Evidence["field"] != "buyer_phone" || hit.Evidence["data_type"] != "phone" ||
		hit.Evidence["location"] != "grpc" {
		t.Fatalf("sensitive evidence = %+v", hit.Evidence)
	}
	for k, v := range hit.Evidence {
		if strings.Contains(v, "13800001111") {
			t.Fatalf("evidence must not carry value: %s in %+v", k, hit.Evidence)
		}
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatal("observe-level sensitive hit must not block")
	}
}

// 无注册表（nil）：观测证据无 decoded/descriptor 键，与 v1 逐键一致（零变化纪律）。
func TestProcessGRPCDescriptorAbsent(t *testing.T) {
	body := grpcPipeFrame(false, []byte{0x0a, 0x01})
	res, err := Process(grpcPipeRequest(body), Config{Enabled: true, Mode: decision.ModeProtect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	obs := findPipeMatch(res, "grpc.observed")
	if obs == nil {
		t.Fatalf("grpc.observed missing: %+v", res.Context.CopyMatches())
	}
	if _, ok := obs.Evidence["decoded"]; ok {
		t.Fatalf("nil registry must not add decoded key: %+v", obs.Evidence)
	}
	if len(obs.Evidence) != 2 {
		t.Fatalf("nil registry must keep v1 evidence shape: %+v", obs.Evidence)
	}
}

// 解码失败降级：线格式损坏首帧 → grpc.decode_error（OBSERVE/LOW）+ decoded=false，
// 不报错不阻断（请求照常走完管线）。
func TestProcessGRPCDescriptorDecodeErrorDegrades(t *testing.T) {
	reg := grpcDescPipeRegistry(t)
	body := grpcPipeFrame(false, []byte{0x0a, 0x7f}) // 帧结构合法，消息体线格式损坏
	res, err := Process(grpcPipeRequest(body), Config{
		Enabled: true, Mode: decision.ModeProtect, GRPCDescriptors: reg,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatal("decode error must degrade, not block")
	}
	de := findPipeMatch(res, "grpc.decode_error")
	if de == nil || de.Severity != "LOW" {
		t.Fatalf("decode_error = %+v", de)
	}
	obs := findPipeMatch(res, "grpc.observed")
	if obs == nil || obs.Evidence["decoded"] != "false" || obs.Evidence["descriptor"] != "orders" {
		t.Fatalf("observed = %+v", obs)
	}
}
