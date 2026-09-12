// grpcdesc_test.go 描述符注册表单测（protoc 不可用，按任务书以 protobuf 库自身
// 在测试中动态构造 descriptor + dynamicpb 消息编码）：
// 编译/查找/解码/字段遍历正确性（嵌套点路径、重复字段只统计）、
// 装配护栏（名/体量/条数/依赖自闭合）、解码失败如实报错、跨集重名后者生效。
package grpcdesc

import (
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// testFileDescriptorSet 动态构造订单服务描述符集：
// pkg.orders.v1.OrderService.CreateOrder(CreateOrderReq) returns (CreateOrderResp)；
// CreateOrderReq{order_id, buyer_phone, buyer(Buyer{name,id_card}), repeated tags}。
func testFileDescriptorSet(t *testing.T) []byte {
	t.Helper()
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	field := func(name string, num int32, typ descriptorpb.FieldDescriptorProto_Type, typeName string, label descriptorpb.FieldDescriptorProto_Label) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{
			Name:     proto.String(name),
			Number:   proto.Int32(num),
			Type:     typ.Enum(),
			Label:    label.Enum(),
			JsonName: proto.String(name),
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
			field("buyer", 3, msg, ".pkg.orders.v1.Buyer", optional),
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
		Name: proto.String("CreateOrderResp"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("id", 1, str, "", optional),
		},
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:        proto.String("orders.proto"),
		Package:     proto.String("pkg.orders.v1"),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{req, buyer, resp},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: proto.String("OrderService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       proto.String("CreateOrder"),
						InputType:  proto.String(".pkg.orders.v1.CreateOrderReq"),
						OutputType: proto.String(".pkg.orders.v1.CreateOrderResp"),
					},
				},
			},
		},
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	if err != nil {
		t.Fatalf("marshal fds: %v", err)
	}
	return raw
}

// testRegistry 装配测试注册表。
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r := NewRegistry()
	if err := r.AddSet("orders", base64.StdEncoding.EncodeToString(testFileDescriptorSet(t))); err != nil {
		t.Fatalf("AddSet: %v", err)
	}
	return r
}

// testOrderMessage 构造动态请求消息并编码（buyer_phone 命中敏感词表形态）。
func testOrderMessage(t *testing.T, r *Registry) []byte {
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
	tags.Append(protoreflect.ValueOfString("vip"))
	m.Set(fields.ByName("tags"), protoreflect.ValueOfList(tags))
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal message: %v", err)
	}
	return raw
}

func TestRegistryLookupDecodeWalk(t *testing.T) {
	r := testRegistry(t)
	if r.Sets() != 1 || r.Methods() != 1 {
		t.Fatalf("sets/methods = %d/%d", r.Sets(), r.Methods())
	}
	md, setName, ok := r.Lookup("pkg.orders.v1.OrderService", "CreateOrder")
	if !ok || setName != "orders" {
		t.Fatalf("lookup = %v/%q", ok, setName)
	}
	if string(md.Input().FullName()) != "pkg.orders.v1.CreateOrderReq" {
		t.Fatalf("input = %s", md.Input().FullName())
	}
	// 未登记方法：miss
	if _, _, ok := r.Lookup("pkg.orders.v1.OrderService", "DeleteOrder"); ok {
		t.Fatal("unknown method must miss")
	}
	if _, _, ok := r.Lookup("other.Service", "CreateOrder"); ok {
		t.Fatal("unknown service must miss")
	}

	msg, err := DecodeRequest(md, testOrderMessage(t, r))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	fields, repeated := WalkStringFields(msg, 8, 256)
	if repeated != 1 { // tags 重复字段只统计
		t.Fatalf("repeated = %d, want 1", repeated)
	}
	got := map[string]string{}
	for _, f := range fields {
		got[f.Path] = f.Value
	}
	want := map[string]string{
		"order_id":      "o-1",
		"buyer_phone":   "13800001111",
		"buyer.name":    "zhang",
		"buyer.id_card": "110101199001011234",
	}
	if len(got) != len(want) {
		t.Fatalf("fields = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("field %q = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
}

func TestAddSetGuards(t *testing.T) {
	good := base64.StdEncoding.EncodeToString(testFileDescriptorSet(t))
	// 空名/超长名
	if err := NewRegistry().AddSet("", good); err == nil {
		t.Fatal("empty name must be rejected")
	}
	if err := NewRegistry().AddSet(strings.Repeat("a", maxNameLen+1), good); err == nil {
		t.Fatal("oversized name must be rejected")
	}
	// 非法 base64
	if err := NewRegistry().AddSet("x", "!!!not-base64!!!"); err == nil {
		t.Fatal("bad base64 must be rejected")
	}
	// 空内容
	if err := NewRegistry().AddSet("x", base64.StdEncoding.EncodeToString(nil)); err == nil {
		t.Fatal("empty content must be rejected")
	}
	// 超 1MiB
	if err := NewRegistry().AddSet("x", base64.StdEncoding.EncodeToString(make([]byte, MaxSetBytes+1))); err == nil {
		t.Fatal("oversized content must be rejected")
	}
	// 线格式损坏（合法 base64 但非 FileDescriptorSet）
	if err := NewRegistry().AddSet("x", base64.StdEncoding.EncodeToString([]byte{0x80})); err == nil {
		t.Fatal("corrupt wire must be rejected")
	}
	// 依赖不自闭合（import 缺失的引用类型）：protodesc 编译失败
	dangling := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{{
		Name:    proto.String("dangling.proto"),
		Package: proto.String("d"),
		Syntax:  proto.String("proto3"),
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("S"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String("M"),
				InputType:  proto.String(".missing.Req"),
				OutputType: proto.String(".missing.Resp"),
			}},
		}},
	}}}
	raw, err := proto.Marshal(dangling)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewRegistry().AddSet("dangling", base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("non-self-contained set must be rejected")
	}
	// 条数上限
	r := NewRegistry()
	for i := 0; i < MaxSets; i++ {
		if err := r.AddSet(strings.Repeat("s", 1)+strings.Repeat("0", i%10)+base64Name(i), good); err != nil {
			t.Fatalf("set %d: %v", i, err)
		}
	}
	if err := r.AddSet("overflow", good); err == nil {
		t.Fatal("too many sets must be rejected")
	}
}

func base64Name(i int) string {
	// 生成互不相同的短名（避免构造唯一索引冲突干扰条数测试）
	return strings.Repeat("n", i+1)
}

func TestAddSetDuplicateMethodLaterWins(t *testing.T) {
	raw := testFileDescriptorSet(t)
	r := NewRegistry()
	if err := r.AddSet("first", base64.StdEncoding.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
	if err := r.AddSet("second", base64.StdEncoding.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
	_, setName, ok := r.Lookup("pkg.orders.v1.OrderService", "CreateOrder")
	if !ok || setName != "second" {
		t.Fatalf("later set must win, got %q", setName)
	}
	if r.Sets() != 2 || r.Methods() != 1 {
		t.Fatalf("sets/methods = %d/%d", r.Sets(), r.Methods())
	}
}

func TestDecodeRequestCorruptWire(t *testing.T) {
	r := testRegistry(t)
	md, _, _ := r.Lookup("pkg.orders.v1.OrderService", "CreateOrder")
	// 截断的 varint
	if _, err := DecodeRequest(md, []byte{0x80}); err == nil {
		t.Fatal("corrupt wire must error")
	}
	// 长度声明越界
	if _, err := DecodeRequest(md, []byte{0x0a, 0x7f}); err == nil {
		t.Fatal("length overflow must error")
	}
	// 空消息合法（零字段）
	m, err := DecodeRequest(md, nil)
	if err != nil {
		t.Fatalf("empty message must decode: %v", err)
	}
	fields, repeated := WalkStringFields(m, 8, 256)
	if len(fields) != 0 || repeated != 0 {
		t.Fatalf("empty message walk = %v/%d", fields, repeated)
	}
}

func TestWalkStringFieldsBudgets(t *testing.T) {
	r := testRegistry(t)
	md, _, _ := r.Lookup("pkg.orders.v1.OrderService", "CreateOrder")
	msg, err := DecodeRequest(md, testOrderMessage(t, r))
	if err != nil {
		t.Fatal(err)
	}
	// 深度 1：嵌套 buyer 不递归，仅顶层 string
	fields, _ := WalkStringFields(msg, 1, 256)
	if len(fields) != 2 {
		t.Fatalf("depth=1 fields = %v", fields)
	}
	// 字段数上限 2：截断产出
	fields, _ = WalkStringFields(msg, 8, 2)
	if len(fields) != 2 {
		t.Fatalf("maxFields=2 fields = %v", fields)
	}
	// 零/负预算：零产出
	fields, repeated := WalkStringFields(msg, 0, 0)
	if len(fields) != 0 || repeated != 0 {
		t.Fatalf("zero budget walk = %v/%d", fields, repeated)
	}
}
