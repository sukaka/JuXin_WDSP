// protoset_test.go FileDescriptorSet 线格式摘要解析单测（server module 无 protobuf 库，
// 测试以手工线字节编码构造描述符集；编码辅助与线上解析严格对偶）。
package apigrpcdesc

import (
	"errors"
	"strings"
	"testing"
)

// ---------- 线字节编码辅助（测试侧编码器，与解析器对偶） ----------

func encVarint(v uint64) []byte {
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

func encTag(fieldNum, wireType int) []byte { return encVarint(uint64(fieldNum<<3 | wireType)) }

func encLen(fieldNum int, payload []byte) []byte {
	out := encTag(fieldNum, 2)
	out = append(out, encVarint(uint64(len(payload)))...)
	return append(out, payload...)
}

func encString(fieldNum int, s string) []byte { return encLen(fieldNum, []byte(s)) }

func encBool(fieldNum int, v bool) []byte {
	out := encTag(fieldNum, 0)
	if v {
		return append(out, 1)
	}
	return append(out, 0)
}

// methodProto 编码 MethodDescriptorProto。
func methodProto(name, in, out string, clientStreaming, serverStreaming bool) []byte {
	b := encString(1, name)
	b = append(b, encString(2, in)...)
	b = append(b, encString(3, out)...)
	if clientStreaming {
		b = append(b, encBool(5, true)...)
	}
	if serverStreaming {
		b = append(b, encBool(6, true)...)
	}
	return b
}

// serviceProto 编码 ServiceDescriptorProto。
func serviceProto(name string, methods ...[]byte) []byte {
	b := encString(1, name)
	for _, m := range methods {
		b = append(b, encLen(2, m)...)
	}
	return b
}

// fileProto 编码 FileDescriptorProto（package + 若干 service）。
func fileProto(pkg string, services ...[]byte) []byte {
	b := encString(1, "test.proto")
	if pkg != "" {
		b = append(b, encString(2, pkg)...)
	}
	for _, s := range services {
		b = append(b, encLen(6, s)...)
	}
	return b
}

// fileDescriptorSet 编码 FileDescriptorSet。
func fileDescriptorSet(files ...[]byte) []byte {
	var b []byte
	for _, f := range files {
		b = append(b, encLen(1, f)...)
	}
	return b
}

// ---------- 用例 ----------

func TestParseFileDescriptorSetSummary(t *testing.T) {
	set := fileDescriptorSet(fileProto("pkg.orders.v1",
		serviceProto("OrderService",
			methodProto("CreateOrder", ".pkg.orders.v1.CreateOrderReq", ".pkg.orders.v1.CreateOrderResp", false, false),
			methodProto("WatchOrders", ".pkg.orders.v1.WatchReq", ".pkg.orders.v1.OrderEvent", false, true),
		),
	))
	services, err := ParseFileDescriptorSet(set)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(services) != 1 {
		t.Fatalf("services = %d, want 1", len(services))
	}
	svc := services[0]
	if svc.Service != "pkg.orders.v1.OrderService" {
		t.Fatalf("service = %q", svc.Service)
	}
	if len(svc.Methods) != 2 {
		t.Fatalf("methods = %d, want 2", len(svc.Methods))
	}
	m0 := svc.Methods[0]
	if m0.Name != "CreateOrder" || m0.InputType != ".pkg.orders.v1.CreateOrderReq" ||
		m0.OutputType != ".pkg.orders.v1.CreateOrderResp" || m0.ClientStreaming || m0.ServerStreaming {
		t.Fatalf("method[0] = %+v", m0)
	}
	if !svc.Methods[1].ServerStreaming {
		t.Fatalf("method[1] server_streaming must be true: %+v", svc.Methods[1])
	}
}

func TestParseFileDescriptorSetMultiFileAndUnknownFields(t *testing.T) {
	// 第二个文件：无包名服务 + 未知字段（FileOptions 形态：varint/fixed64/LEN/fixed32 混合跳过）
	file2 := encString(1, "legacy.proto")
	file2 = append(file2, encTag(8, 2)...) // options (LEN, 内容跳过)
	opts := append(encVarint(7<<3|0), 1)   // options 内一个 varint 字段
	opts = append(opts, encTag(9, 1)...)
	opts = append(opts, 0, 0, 0, 0, 0, 0, 0, 0) // fixed64
	opts = append(opts, encTag(10, 5)...)
	opts = append(opts, 0, 0, 0, 0) // fixed32
	file2 = append(file2, encVarint(uint64(len(opts)))...)
	file2 = append(file2, opts...)
	file2 = append(file2, encLen(6, serviceProto("Echo", methodProto("Ping", ".PingReq", ".PingResp", true, true)))...)

	set := fileDescriptorSet(
		fileProto("a.b", serviceProto("S1", methodProto("M", ".a.b.Req", ".a.b.Resp", false, false))),
		file2,
	)
	services, err := ParseFileDescriptorSet(set)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(services) != 2 {
		t.Fatalf("services = %d, want 2", len(services))
	}
	if services[0].Service != "a.b.S1" {
		t.Fatalf("services[0] = %q", services[0].Service)
	}
	if services[1].Service != "Echo" { // 无包名：裸服务名
		t.Fatalf("services[1] = %q", services[1].Service)
	}
	if !services[1].Methods[0].ClientStreaming || !services[1].Methods[0].ServerStreaming {
		t.Fatalf("streaming flags lost: %+v", services[1].Methods[0])
	}
}

func TestParseFileDescriptorSetBadWire(t *testing.T) {
	good := fileDescriptorSet(fileProto("p", serviceProto("S", methodProto("M", ".R", ".S", false, false))))
	cases := map[string][]byte{
		"空内容":   {},
		"无文件条目": encString(9, "x"),          // 只有未知顶层字段
		"截断tag": {0x80},                     // varint 未终结
		"长度越界":  append(encTag(1, 2), 0x7f), // 声明 127 无载荷
		"组线型":   append(encTag(1, 3), 0x00), // SGROUP 不支持
		"零字段号":  {0x00},                     // field number 0
		"服务无名": fileDescriptorSet(fileProto("p",
			encLen(2, methodProto("M", ".A", ".B", false, false)))), // service 只有 method(2) 无 name(1)
		"方法无名": fileDescriptorSet(fileProto("p",
			encLen(6, methodProto("", ".A", ".B", false, false)))),
		"名称非UTF8": fileDescriptorSet(fileProto("p",
			encLen(6, append(encTag(1, 2), 0x01, 0xff)))),
		"整体截断": good[:len(good)-3],
	}
	for name, blob := range cases {
		if _, err := ParseFileDescriptorSet(blob); err == nil {
			t.Fatalf("%s must be rejected", name)
		} else if !errors.Is(err, ErrBadDescriptorSet) {
			t.Fatalf("%s error must wrap ErrBadDescriptorSet, got %v", name, err)
		}
	}
}

func TestParseFileDescriptorSetNameTooLong(t *testing.T) {
	longName := strings.Repeat("a", maxSummaryNameLen+1)
	set := fileDescriptorSet(fileProto("p",
		serviceProto(longName, methodProto("M", ".A", ".B", false, false))))
	if _, err := ParseFileDescriptorSet(set); err == nil {
		t.Fatal("oversized name must be rejected")
	}
	// 恰为上限：接受
	okName := strings.Repeat("a", maxSummaryNameLen)
	set = fileDescriptorSet(fileProto("p",
		serviceProto(okName, methodProto("M", ".A", ".B", false, false))))
	services, err := ParseFileDescriptorSet(set)
	if err != nil {
		t.Fatalf("boundary name must pass: %v", err)
	}
	if services[0].Service != "p."+okName {
		t.Fatalf("service = %q", services[0].Service)
	}
}

// TestDefaultNameFromFile 缺省名称推导（去常见 protoset 后缀与目录段）。
func TestDefaultNameFromFile(t *testing.T) {
	cases := map[string]string{
		"orders.pb":              "orders",
		"order service.protoset": "order service",
		`/tmp/x/echo.bin`:        "echo",
		`C:\desc\pay.fds`:        "pay",
		"noext":                  "noext",
	}
	for in, want := range cases {
		if got := defaultNameFromFile(in); got != want {
			t.Fatalf("defaultNameFromFile(%q) = %q, want %q", in, got, want)
		}
	}
}
