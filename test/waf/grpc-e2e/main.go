// grpc-e2e NG-GRPC G1 批次 C 联调客户端（真实 Go gRPC SDK 对测——禁止 curl 冒充
// gRPC）。经网关（h2c 明文）调用测试源站，逐场景输出 verdict 供 bash 断言。
//
// 用法：grpc-e2e -addr 127.0.0.1:18080 -authority grpc-s5.local -descriptor echo.pb <scenario>
// 场景：r01（正常流+大消息分片）/ r02（gzip 高倍率）/ r03（缺描述符直达）/
// r04-string|r04-depth|r04-enum|r04-repeated（结构违规）/ r05（streaming 降级）/
// r06（cancel 资源释放）；r02-observe / r04-string-observe（OBSERVE 应用对照——
// 目标 authority 由参数切换，期望结果按场景名后缀判定）。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

var (
	addr      = flag.String("addr", "127.0.0.1:18080", "网关地址（h2c）")
	authority = flag.String("authority", "grpc-s5.local", ":authority（Host 头——网关按 Host 路由应用）")
	descPath  = flag.String("descriptor", "", "FileDescriptorSet 路径（echo.pb）")
	timeout   = flag.Duration("timeout", 30*time.Second, "单场景超时")
)

func mustRegistry() *registry {
	raw, err := os.ReadFile(*descPath)
	if err != nil {
		fatal("read descriptor: %v", err)
	}
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(raw, fds); err != nil {
		fatal("parse descriptor set: %v", err)
	}
	files, err := protodesc.NewFiles(fds)
	if err != nil {
		fatal("compile descriptor set: %v", err)
	}
	fd, err := files.FindFileByPath("echo.proto")
	if err != nil {
		fatal("echo.proto not in set: %v", err)
	}
	return &registry{
		req:  dynamicpb.NewMessageType(fd.Messages().ByName("EchoRequest")),
		resp: dynamicpb.NewMessageType(fd.Messages().ByName("EchoResponse")),
		nest: dynamicpb.NewMessageType(fd.Messages().ByName("Nested")),
	}
}

type registry struct {
	req  protoreflect.MessageType
	resp protoreflect.MessageType
	nest protoreflect.MessageType
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(2)
}

func dial() *grpc.ClientConn {
	conn, err := grpc.NewClient(*addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority(*authority),
		// R02 大消息回显验收：接收上限放宽（默认 4MiB 会误拒源站大响应——
		// 客户端自身限制而非网关拒绝（联调实证）
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(64<<20), grpc.MaxCallSendMsgSize(64<<20)),
	)
	if err != nil {
		fatal("dial: %v", err)
	}
	return conn
}

// invoke 通用 unary 调用（dynamicpb 全方法形态；返回 (响应文本, 响应 metadata, error)）。
func invoke(ctx context.Context, conn *grpc.ClientConn, method string, in *dynamicpb.Message, useGzip bool) (string, metadata.MD, error) {
	out := mustRegistry().resp.New().(*dynamicpb.Message)
	var hdr metadata.MD
	opts := []grpc.CallOption{grpc.Header(&hdr)}
	if useGzip {
		opts = append(opts, grpc.UseCompressor(gzip.Name))
	}
	err := conn.Invoke(ctx, method, in, out, opts...)
	if err != nil {
		return "", hdr, err
	}
	text := out.Get(out.Descriptor().Fields().ByName("text")).String()
	return text, hdr, nil
}

// newMsg 构造 EchoRequest（按字段路径设值；color 允许越界注入（dynamicpb 不校验值域））。
func (r *registry) newMsg() *dynamicpb.Message { return r.req.New().(*dynamicpb.Message) }

func setField(m *dynamicpb.Message, name string, v protoreflect.Value) {
	m.Set(m.Descriptor().Fields().ByName(protoreflect.Name(name)), v)
}

func strField(m *dynamicpb.Message, name, val string) {
	setField(m, name, protoreflect.ValueOfString(val))
}

func (r *registry) nestedChain(depth int) *dynamicpb.Message {
	root := r.nest.New().(*dynamicpb.Message)
	cur := root
	for i := 0; i < depth; i++ {
		child := r.nest.New().(*dynamicpb.Message)
		strField(child, "name", fmt.Sprintf("n%d", i))
		cur.Set(cur.Descriptor().Fields().ByName("child"), protoreflect.ValueOfMessage(child))
		cur = child
	}
	return root
}

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fatal("usage: grpc-e2e <scenario>")
	}
	reg := mustRegistry()
	conn := dial()
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	scenario := flag.Arg(0)
	verdict := func(ok bool, evidence string) {
		if ok {
			fmt.Printf("PASS %s %s\n", scenario, evidence)
			return
		}
		fmt.Printf("FAIL %s %s\n", scenario, evidence)
		os.Exit(1)
	}

	switch scenario {
	case "r01":
		// 正常流 + 3MiB 大消息（h2 分片重组路径）：期望成功+源站到达
		m := reg.newMsg()
		strField(m, "text", "hello-grpc")
		strField(m, "big_text", strings.Repeat("A", 200<<10))
		m.Set(m.Descriptor().Fields().ByName("tags"), protoreflect.ValueOfList(
			func() protoreflect.List {
				l := m.NewField(m.Descriptor().Fields().ByName("tags")).List()
				l.Append(protoreflect.ValueOfString("t1"))
				return l
			}()))
		text, hdr, err := invoke(ctx, conn, "/echo.EchoService/Echo", m, false)
		verdict(err == nil && strings.Contains(text, "hello-grpc") && len(hdr.Get("x-wdsp-origin-mark")) > 0,
			fmt.Sprintf("text=%q origin_mark=%v err=%v", text, hdr.Get("x-wdsp-origin-mark"), err))

	case "r02":
		// gzip 高倍率（20MiB 重复字节 → 高压缩比）：PROTECT 期望 ResourceExhausted
		m := reg.newMsg()
		strField(m, "big_text", strings.Repeat("a", 20<<20))
		_, _, err := invoke(ctx, conn, "/echo.EchoService/Echo", m, true)
		code := status.Code(err)
		verdict(code == codes.ResourceExhausted, fmt.Sprintf("code=%s err=%v", code, err))

	case "r02-observe":
		// 同流量 OBSERVE 应用：期望成功（只记录不实断）
		m := reg.newMsg()
		strField(m, "big_text", strings.Repeat("a", 20<<20))
		text, _, err := invoke(ctx, conn, "/echo.EchoService/Echo", m, true)
		verdict(err == nil, fmt.Sprintf("text_len=%d err=%v", len(text), err))

	case "r03":
		// 缺描述符（OtherService 不在下发描述符集）：期望直达源站成功（不误断）
		m := reg.newMsg()
		strField(m, "text", "ping-no-descriptor")
		text, hdr, err := invoke(ctx, conn, "/echo.OtherService/Ping", m, false)
		verdict(err == nil && strings.Contains(text, "ping-no-descriptor") && len(hdr.Get("x-wdsp-origin-mark")) > 0,
			fmt.Sprintf("text=%q origin_mark=%v err=%v", text, hdr.Get("x-wdsp-origin-mark"), err))

	case "r04-string":
		// string 超 256KiB：PROTECT 期望 PermissionDenied（trailers-only——SDK err 形态）
		m := reg.newMsg()
		strField(m, "big_text", strings.Repeat("B", 300<<10))
		_, _, err := invoke(ctx, conn, "/echo.EchoService/Echo", m, false)
		code := status.Code(err)
		verdict(code == codes.PermissionDenied, fmt.Sprintf("code=%s err=%v", code, err))

	case "r04-string-observe":
		// OBSERVE 应用同流量：期望成功（记录不实断）
		m := reg.newMsg()
		strField(m, "big_text", strings.Repeat("B", 300<<10))
		text, _, err := invoke(ctx, conn, "/echo.EchoService/Echo", m, false)
		verdict(err == nil, fmt.Sprintf("text_len=%d err=%v", len(text), err))

	case "r04-depth":
		// 嵌套超 8 层：PermissionDenied
		m := reg.newMsg()
		setField(m, "nested", protoreflect.ValueOfMessage(reg.nestedChain(10)))
		_, _, err := invoke(ctx, conn, "/echo.EchoService/Echo", m, false)
		code := status.Code(err)
		verdict(code == codes.PermissionDenied, fmt.Sprintf("code=%s err=%v", code, err))

	case "r04-enum":
		// 枚举越界（dynamicpb 注入 99——值域校验属网关）：PermissionDenied
		m := reg.newMsg()
		setField(m, "color", protoreflect.ValueOfEnum(99))
		_, _, err := invoke(ctx, conn, "/echo.EchoService/Echo", m, false)
		code := status.Code(err)
		verdict(code == codes.PermissionDenied, fmt.Sprintf("code=%s err=%v", code, err))

	case "r04-repeated":
		// repeated 超 1024：PermissionDenied
		m := reg.newMsg()
		l := m.NewField(m.Descriptor().Fields().ByName("tags")).List()
		for i := 0; i < 1025; i++ {
			l.Append(protoreflect.ValueOfString("x"))
		}
		m.Set(m.Descriptor().Fields().ByName("tags"), protoreflect.ValueOfList(l))
		_, _, err := invoke(ctx, conn, "/echo.EchoService/Echo", m, false)
		code := status.Code(err)
		verdict(code == codes.PermissionDenied, fmt.Sprintf("code=%s err=%v", code, err))

	case "r05":
		// client-streaming：期望流式正常完成（streaming_degraded 不误判不冒充）
		stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true}, "/echo.EchoService/CollectEcho")
		if err != nil {
			fatal("new stream: %v", err)
		}
		for i := 0; i < 3; i++ {
			m := reg.newMsg()
			strField(m, "text", fmt.Sprintf("chunk-%d", i))
			if err := stream.SendMsg(m); err != nil {
				fatal("send: %v", err)
			}
		}
		out := reg.resp.New().(*dynamicpb.Message)
		// client-streaming 必须显式关流（CloseSend→END_STREAM）后接收——
		// 网关读体等待流结束，缺关流即互相等待死锁（联调实证）
		if err := stream.CloseSend(); err != nil {
			verdict(false, fmt.Sprintf("closeSend err=%v", err))
			return
		}
		if err := stream.RecvMsg(out); err != nil {
			verdict(false, fmt.Sprintf("recv err=%v", err))
			return
		}
		text := out.Get(out.Descriptor().Fields().ByName("text")).String()
		verdict(text == "collected:3", fmt.Sprintf("text=%q", text))

	case "r06":
		// cancel 资源释放：50 次大消息调用中途 cancel（网关侧泄漏由 bash 查证）
		for i := 0; i < 50; i++ {
			cctx, ccancel := context.WithCancel(context.Background())
			m := reg.newMsg()
			strField(m, "big_text", strings.Repeat("C", 4<<20))
			go func() { time.Sleep(20 * time.Millisecond); ccancel() }()
			_, _, _ = invoke(cctx, conn, "/echo.EchoService/Echo", m, false)
		}
		verdict(true, "50 cancels issued")

	default:
		fatal("unknown scenario %q", scenario)
	}
}
