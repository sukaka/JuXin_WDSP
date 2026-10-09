module github.com/jiuzhang-waf/gateway/dynamic_security

go 1.25

// google.golang.org/protobuf 由间接依赖转为直接使用（W14-DESC / P2-05 深化：
// gRPC 描述符编译 protodesc + 动态消息 dynamicpb）。版本与仓库根 gateway/go.mod、
// modules/jiuzhang_guard/go.mod 既有锁定 v1.36.11 一致，属既有锁定版本启用，
// 不引入新外部库。
require google.golang.org/protobuf v1.36.11

require (
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/vektah/gqlparser/v2 v2.5.60
)
