// helpers_test.go grpcguard 测试共享构造：echo 描述符集/动态消息/帧体/配置。
package grpcguard

import (
	"compress/gzip"
	"encoding/base64"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// testEchoFDS 动态构造 echo 描述符集（proto3）：
//   - enum Status{UNKNOWN=0, OK=1, BAD=2}
//   - message Inner{note:1 string, deep:2 Inner}（自递归——深度测试载体）
//   - message EchoReq{name:1 string, tags:2 repeated string, count:3 int32,
//     inner:4 Inner, status:5 Status, blob:6 bytes, attrs:7 map<string,string>}
//   - service EchoService{Echo(EchoReq) returns (EchoReq)}
func testEchoFDS(t *testing.T) []byte {
	t.Helper()
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING
	int32T := descriptorpb.FieldDescriptorProto_TYPE_INT32
	msgT := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE
	enumT := descriptorpb.FieldDescriptorProto_TYPE_ENUM
	bytesT := descriptorpb.FieldDescriptorProto_TYPE_BYTES
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
	inner := &descriptorpb.DescriptorProto{
		Name: proto.String("Inner"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("note", 1, str, "", optional),
			field("deep", 2, msgT, ".echo.Inner", optional),
		},
	}
	attrsEntry := &descriptorpb.DescriptorProto{
		Name: proto.String("AttrsEntry"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("key", 1, str, "", optional),
			field("value", 2, str, "", optional),
		},
		Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
	}
	req := &descriptorpb.DescriptorProto{
		Name: proto.String("EchoReq"),
		Field: []*descriptorpb.FieldDescriptorProto{
			field("name", 1, str, "", optional),
			field("tags", 2, str, "", repeated),
			field("count", 3, int32T, "", optional),
			field("inner", 4, msgT, ".echo.Inner", optional),
			field("status", 5, enumT, ".echo.Status", optional),
			field("blob", 6, bytesT, "", optional),
			field("attrs", 7, msgT, ".echo.EchoReq.AttrsEntry", repeated),
		},
		NestedType: []*descriptorpb.DescriptorProto{attrsEntry},
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("echo.proto"),
		Package: proto.String("echo"),
		Syntax:  proto.String("proto3"),
		EnumType: []*descriptorpb.EnumDescriptorProto{{
			Name: proto.String("Status"),
			Value: []*descriptorpb.EnumValueDescriptorProto{
				{Name: proto.String("UNKNOWN"), Number: proto.Int32(0)},
				{Name: proto.String("OK"), Number: proto.Int32(1)},
				{Name: proto.String("BAD"), Number: proto.Int32(2)},
			},
		}},
		MessageType: []*descriptorpb.DescriptorProto{inner, req},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("EchoService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String("Echo"),
				InputType:  proto.String(".echo.EchoReq"),
				OutputType: proto.String(".echo.EchoReq"),
			}},
		}},
	}
	raw, err := proto.Marshal(&descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{file}})
	if err != nil {
		t.Fatalf("marshal fds: %v", err)
	}
	return raw
}

// testEchoRegistry 装配 echo 注册表。
func testEchoRegistry(t *testing.T) *grpcdesc.Registry {
	t.Helper()
	r := grpcdesc.NewRegistry()
	if err := r.AddSet("echo-set", base64.StdEncoding.EncodeToString(testEchoFDS(t))); err != nil {
		t.Fatalf("AddSet: %v", err)
	}
	return r
}

// testEchoMessage 构造动态 EchoReq 消息并编码；mutate 为字段定制钩子。
func testEchoMessage(t *testing.T, r *grpcdesc.Registry, mutate func(m protoreflect.Message)) []byte {
	t.Helper()
	md, _, ok := r.Lookup("echo.EchoService", "Echo")
	if !ok {
		t.Fatal("lookup failed")
	}
	m := dynamicpb.NewMessage(md.Input())
	fields := m.Descriptor().Fields()
	m.Set(fields.ByName("name"), protoreflect.ValueOfString("alice"))
	m.Set(fields.ByName("count"), protoreflect.ValueOfInt32(1))
	m.Set(fields.ByName("status"), protoreflect.ValueOfEnum(1))
	if mutate != nil {
		mutate(m)
	}
	raw, err := proto.Marshal(m)
	if err != nil {
		t.Fatalf("marshal msg: %v", err)
	}
	return raw
}

// testSetTags 设置 repeated tags（n 个元素）。
func testSetTags(n int) func(m protoreflect.Message) {
	return func(m protoreflect.Message) {
		fd := m.Descriptor().Fields().ByName("tags")
		l := m.NewField(fd).List()
		for i := 0; i < n; i++ {
			l.Append(protoreflect.ValueOfString("t"))
		}
		m.Set(fd, protoreflect.ValueOfList(l))
	}
}

// testSetAttrs 设置 map attrs（n 个条目）。
func testSetAttrs(n int) func(m protoreflect.Message) {
	return func(m protoreflect.Message) {
		fd := m.Descriptor().Fields().ByName("attrs")
		mp := m.NewField(fd).Map()
		kd, vd := fd.MapKey(), fd.MapValue()
		for i := 0; i < n; i++ {
			mp.Set(protoreflect.ValueOfString("k"+string(rune('a'+i%26))+string(rune('0'+i/26%10))).MapKey(), protoreflect.ValueOfString("v"))
		}
		_ = kd
		_ = vd
		m.Set(fd, protoreflect.ValueOfMap(mp))
	}
}

// testSetInner 设置嵌套 Inner（depth 层自递归）。
func testSetInner(depth int) func(m protoreflect.Message) {
	return func(m protoreflect.Message) {
		fd := m.Descriptor().Fields().ByName("inner")
		cur := m
		for i := 0; i < depth; i++ {
			im := dynamicpb.NewMessage(fd.Message())
			im.Set(im.Descriptor().Fields().ByName("note"), protoreflect.ValueOfString("n"))
			cur.Set(fd, protoreflect.ValueOfMessage(im))
			cur = im
			fd = im.Descriptor().Fields().ByName("deep")
		}
	}
}

// testSetStatusEnum 设置枚举值（num 可为域外值——dynamicpb 容许任意整数）。
func testSetStatusEnum(num protoreflect.EnumNumber) func(m protoreflect.Message) {
	return func(m protoreflect.Message) {
		m.Set(m.Descriptor().Fields().ByName("status"), protoreflect.ValueOfEnum(num))
	}
}

// testSetStringLen 设置 name 为指定长度。
func testSetStringLen(n int) func(m protoreflect.Message) {
	return func(m protoreflect.Message) {
		m.Set(m.Descriptor().Fields().ByName("name"), protoreflect.ValueOfString(string(make([]byte, n))))
	}
}

// testSetBlobLen 设置 blob 为指定长度。
func testSetBlobLen(n int) func(m protoreflect.Message) {
	return func(m protoreflect.Message) {
		m.Set(m.Descriptor().Fields().ByName("blob"), protoreflect.ValueOfBytes(make([]byte, n)))
	}
}

// testFrame gRPC 帧构造（与批次 A 同形）。
func testFrame(compressed bool, body []byte) []byte {
	out := make([]byte, 5, 5+len(body))
	if compressed {
		out[0] = 1
	}
	out[1] = byte(len(body) >> 24)
	out[2] = byte(len(body) >> 16)
	out[3] = byte(len(body) >> 8)
	out[4] = byte(len(body))
	return append(out, body...)
}

// testAppendUnknownWire 消息尾部追加未知字段 wire（field 99 varint——
// dynamicpb 解码保留为未知字段，计数测试载体）。
func testAppendUnknownWire(msg []byte) []byte {
	out := protowire.AppendTag(msg, 99, protowire.VarintType)
	return protowire.AppendVarint(out, 1)
}

// testConfig 装配测试 Config（bindings 为 application→service→Binding）。
func testConfig(t *testing.T, global bool, bindings map[string]map[string]Binding) *Config {
	t.Helper()
	reg := testEchoRegistry(t)
	cfg := &Config{
		SetRegistries: map[string]*grpcdesc.Registry{"echo-set": reg},
		SetHashes:     map[string]string{"echo-set": "deadbeef"},
		Bindings:      bindings,
	}
	if global {
		cfg.GlobalRegistry = reg
	}
	return cfg
}

// appendWriter 把 *[]byte 适配成 io.Writer（gzip 测试构造用）。
type appendWriter struct{ b *[]byte }

func (w appendWriter) Write(p []byte) (int, error) {
	*w.b = append(*w.b, p...)
	return len(p), nil
}

// gzipNewWriterForTest 写入目标的 gzip.Writer（buf 为输出累积切片）。
func gzipNewWriterForTest(buf *[]byte) *gzip.Writer {
	return gzip.NewWriter(appendWriter{buf})
}

// gzipCompressForTest 一次性压缩并返回完整 gzip 字节流。
func gzipCompressForTest(data []byte) []byte {
	var buf []byte
	w := gzipNewWriterForTest(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf
}
