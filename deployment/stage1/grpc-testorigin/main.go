// grpc-testorigin gRPC 测试源站（NG-GRPC G1 批次 C 联调源站；与
// deployment/stage1/testorigin 同族纪律：受控源站标记契约 X-Wdsp-Origin-Mark
// 回写响应 metadata，证明请求真实到达源站——gRPC 业务状态不能替代到达证据）。
//
// 形态：零 protoc 依赖——服务/消息描述符经 descriptorpb.FileDescriptorProto
// 手工构造（等价 echo.proto），protodesc 编译后 dynamicpb 编解码；
// 子命令 -dump-descriptor 导出 FileDescriptorSet（**仅 EchoService**——
// OtherService 只在源站注册不导出（R03「未绑定服务直达源站」对测承载）。
//
// 方法面（联调用例映射）：
//   - EchoService/Echo（unary）：R01 正常流/R04 结构违规各分支（嵌套链/
//     big_text 长度/repeated tags/enum 越界注入）
//   - EchoService/LargeEcho（unary 大消息回显）：R01 大消息（h2 分片重组）
//   - EchoService/CollectEcho（client-streaming）：R05 streaming 降级
//   - OtherService/Ping（unary；**不在导出描述符集**）：R03 缺描述符不误断
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	_ "google.golang.org/grpc/encoding/gzip" // R02：安装 gzip decompressor（源站解压客户端压缩消息）
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// originMark 受控源站标记（响应 metadata 回写；与 testorigin HTTP 头同契约键）。
const originMark = "x-wdsp-origin-mark"

// echoFileProto echo.proto 等价描述（package echo；EchoService 大写驼峰
// （批次 C 词表裁决实证面）；消息覆盖结构校验各分支字段）。
func echoFileProto() *descriptorpb.FileDescriptorProto {
	str := func(s string) *string { return &s }
	i32 := func(i int32) *int32 { return &i }
	label := func(l descriptorpb.FieldDescriptorProto_Label) *descriptorpb.FieldDescriptorProto_Label { return &l }
	typ := func(t descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto_Type { return &t }
	msgField := func(name string, num int32, l descriptorpb.FieldDescriptorProto_Label, t descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: str(name), Number: i32(num), Label: label(l), Type: typ(t), JsonName: str(name)}
		if typeName != "" {
			f.TypeName = str(typeName)
		}
		return f
	}
	return &descriptorpb.FileDescriptorProto{
		Name:    str("echo.proto"),
		Package: str("echo"),
		Syntax:  str("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: str("Nested"),
				Field: []*descriptorpb.FieldDescriptorProto{
					msgField("name", 1, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
					msgField("child", 2, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".echo.Nested"),
				},
			},
			{
				Name: str("EchoRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					msgField("text", 1, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
					msgField("big_text", 2, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
					msgField("tags", 3, descriptorpb.FieldDescriptorProto_LABEL_REPEATED, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
					msgField("nested", 4, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, ".echo.Nested"),
					msgField("color", 5, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_ENUM, ".echo.Color"),
				},
			},
			{
				Name: str("EchoResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					msgField("text", 1, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
					msgField("origin_mark", 2, descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL, descriptorpb.FieldDescriptorProto_TYPE_STRING, ""),
				},
			},
		},
		EnumType: []*descriptorpb.EnumDescriptorProto{
			{
				Name: str("Color"),
				Value: []*descriptorpb.EnumValueDescriptorProto{
					{Name: str("COLOR_UNSPECIFIED"), Number: i32(0)},
					{Name: str("RED"), Number: i32(1)},
					{Name: str("GREEN"), Number: i32(2)},
				},
			},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: str("EchoService"),
				Method: []*descriptorpb.MethodDescriptorProto{
					{Name: str("Echo"), InputType: str(".echo.EchoRequest"), OutputType: str(".echo.EchoResponse")},
					{Name: str("LargeEcho"), InputType: str(".echo.EchoRequest"), OutputType: str(".echo.EchoResponse")},
					{Name: str("CollectEcho"), InputType: str(".echo.EchoRequest"), OutputType: str(".echo.EchoResponse"), ClientStreaming: proto.Bool(true)},
				},
			},
		},
	}
}

// mustFiles 编译描述符集（含 EchoService 的文件；错误即退出——测试源站不容错）。
func mustFiles() protoreflect.FileDescriptor {
	fd, err := protodesc.NewFile(echoFileProto(), nil)
	if err != nil {
		log.Fatalf("compile echo descriptor: %v", err)
	}
	return fd
}

// registry 测试源站消息注册表（请求/响应 dynamicpb 解码用）。
type registry struct {
	echoReq  protoreflect.MessageType
	echoResp protoreflect.MessageType
}

func newRegistry() *registry {
	fd := mustFiles()
	return &registry{
		echoReq:  dynamicpb.NewMessageType(fd.Messages().ByName("EchoRequest")),
		echoResp: dynamicpb.NewMessageType(fd.Messages().ByName("EchoResponse")),
	}
}

// originHeader 源站到达标记回写（响应 metadata；读取方（E2E/断言）按 metadata 取）。
func originHeader(ctx context.Context) {
	_ = grpc.SetHeader(ctx, metadata.Pairs(originMark, "grpc-test-origin"))
}

// echoUnary Echo/LargeEcho 公共回显逻辑（text 原文回显 + origin_mark 字段）。
func (r *registry) echoUnary(ctx context.Context, in *dynamicpb.Message) (*dynamicpb.Message, error) {
	originHeader(ctx)
	out := r.echoResp.New().(*dynamicpb.Message)
	if in != nil {
		out.Set(out.Descriptor().Fields().ByName("text"), in.Get(in.Descriptor().Fields().ByName("text")))
	}
	out.Set(out.Descriptor().Fields().ByName("origin_mark"), protoreflect.ValueOfString("grpc-test-origin"))
	return out, nil
}

// echoHandler 生成方法 handler（grpc.MethodDesc.Handler 形态；dec 注入 dynamicpb 消息）。
func (r *registry) echoHandler() func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		in := r.echoReq.New().(*dynamicpb.Message)
		if err := dec(in); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return r.echoUnary(ctx, in)
		}
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/echo.EchoService/Echo"}
		return interceptor(ctx, in, info, func(ctx context.Context, req any) (any, error) {
			return r.echoUnary(ctx, req.(*dynamicpb.Message))
		})
	}
}

// collectHandler CollectEcho（client-streaming）：逐条收读回显计数（R05 streaming
// 降级对测——源站正常完成流式调用，网关不得误判违规也不得冒充深检）。
func (r *registry) collectHandler() func(srv any, stream grpc.ServerStream) error {
	return func(srv any, stream grpc.ServerStream) error {
		originHeader(stream.Context())
		n := 0
		for {
			in := r.echoReq.New().(*dynamicpb.Message)
			if err := stream.RecvMsg(in); err != nil {
				if err.Error() == "EOF" {
					break
				}
				return err
			}
			n++
		}
		out := r.echoResp.New().(*dynamicpb.Message)
		out.Set(out.Descriptor().Fields().ByName("text"), protoreflect.ValueOfString(fmt.Sprintf("collected:%d", n)))
		out.Set(out.Descriptor().Fields().ByName("origin_mark"), protoreflect.ValueOfString("grpc-test-origin"))
		return stream.SendMsg(out)
	}
}

// pingHandler OtherService/Ping（不在导出描述符集——R03 缺描述符直达源站证据承载）。
func (r *registry) pingHandler() func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	return func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		in := r.echoReq.New().(*dynamicpb.Message)
		if err := dec(in); err != nil {
			return nil, err
		}
		originHeader(ctx)
		out := r.echoResp.New().(*dynamicpb.Message)
		out.Set(out.Descriptor().Fields().ByName("text"), in.Get(in.Descriptor().Fields().ByName("text")))
		out.Set(out.Descriptor().Fields().ByName("origin_mark"), protoreflect.ValueOfString("grpc-test-origin"))
		return out, nil
	}
}

// dumpDescriptor 导出 FileDescriptorSet（仅 echo.proto（含 EchoService）；
// OtherService 不入集（R03 语义承载））。
func dumpDescriptor(path string) error {
	fds := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{echoFileProto()}}
	raw, err := proto.Marshal(fds)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func main() {
	dump := flag.String("dump-descriptor", "", "导出 FileDescriptorSet 到指定路径后退出")
	listen := flag.String("listen", ":18571", "gRPC 监听地址（h2c 明文，内网测试源站）")
	flag.Parse()
	if *dump != "" {
		if err := dumpDescriptor(*dump); err != nil {
			log.Fatalf("dump descriptor: %v", err)
		}
		log.Printf("descriptor set written: %s", *dump)
		return
	}

	reg := newRegistry()
	// R02 大消息验收：接收上限放宽（默认 4MiB——R02-observe 的 20MiB 消息
	// 须真实到达并回显（联调实证源站默认限制会误拒大消息）
	srv := grpc.NewServer(grpc.MaxRecvMsgSize(64<<20), grpc.MaxSendMsgSize(64<<20))
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "echo.EchoService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Echo", Handler: reg.echoHandler()},
			{MethodName: "LargeEcho", Handler: reg.echoHandler()},
		},
		Streams: []grpc.StreamDesc{
			{StreamName: "CollectEcho", Handler: reg.collectHandler(), ClientStreams: true},
		},
		Metadata: "echo.proto",
	}, nil)
	// OtherService：源站注册但不在导出描述符集（R03 缺描述符不误断对测承载）
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: "echo.OtherService",
		HandlerType: (*any)(nil),
		Methods:     []grpc.MethodDesc{{MethodName: "Ping", Handler: reg.pingHandler()}},
		Metadata:    "other.proto",
	}, nil)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("grpc-testorigin listening on %s (EchoService{Echo,LargeEcho,CollectEcho} + OtherService{Ping})", *listen)
	if err := srv.Serve(ln); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
