// grpcload：S8 批次 B 档 2 gRPC 臂采样器（测试基建，非生产代码）。
// 形态与 test/waf/grpc-e2e 一致：官方 Go SDK（google.golang.org/grpc）+ h2c +
// dynamicpb 动态消息（FileDescriptorSet 运行时编译，零 protoc 依赖）；
// 单连接循环 N 次 unary Echo（≤1KiB），客户端视角计时落 CSV。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FATAL: "+format+"\n", args...)
	os.Exit(2)
}

func main() {
	var (
		addr      = flag.String("addr", "127.0.0.1:18080", "网关地址（h2c）")
		authority = flag.String("authority", "grpc2-s5.local", ":authority（Host 路由）")
		descPath  = flag.String("descriptor", "", "FileDescriptorSet 路径（必填）")
		n         = flag.Int("n", 300, "采样数")
		warmup    = flag.Int("warmup", 10, "预热数（丢弃）")
		out       = flag.String("out", "", "CSV 输出（必填）")
		method    = flag.String("method", "/echo.EchoService/Echo", "unary 全限定方法")
		msgName   = flag.String("msg", "EchoRequest", "请求消息名")
	)
	flag.Parse()
	if *descPath == "" || *out == "" {
		fatal("usage: grpcload -descriptor D -out F [-authority H] [-n N]")
	}

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
	reqT := dynamicpb.NewMessageType(fd.Messages().ByName(protoreflect.Name(*msgName)))
	respT := dynamicpb.NewMessageType(fd.Messages().ByName("EchoResponse"))

	conn, err := grpc.NewClient(*addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority(*authority),
	)
	if err != nil {
		fatal("dial: %v", err)
	}
	defer conn.Close()

	f, err := os.Create(*out)
	if err != nil {
		fatal("create out: %v", err)
	}
	defer f.Close()
	fmt.Fprintln(f, "seq,duration_ms,code")

	ok := 0
	total := *warmup + *n
	for i := 0; i < total; i++ {
		in := reqT.New().(*dynamicpb.Message)
		in.Set(in.Descriptor().Fields().ByName("text"), protoreflect.ValueOfString("perf-arm-r1"))
		outMsg := respT.New().(*dynamicpb.Message)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		err := conn.Invoke(ctx, *method, in, outMsg)
		durMs := float64(time.Since(start).Nanoseconds()) / 1e6
		cancel()
		if i < *warmup {
			continue
		}
		code := "OK"
		if err != nil {
			code = err.Error()
			if len(code) > 60 {
				code = code[:60]
			}
		} else {
			ok++
		}
		fmt.Fprintf(f, "%d,%.3f,%s\n", i, durMs, code)
	}
	fmt.Printf("grpcload n=%d ok=%d authority=%s\n", *n, ok, *authority)
}
