# S5 阶段小结（NG-GRPC gRPC G1：unary 有界深度检测 —— 阶段关闭）

日期：2026-10-07 ｜ 设计冻结：`docs/nextgen/NG-GRPC-g1-unary.md`（实现状态 §7 本批追加）
依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §10（方向五）+ §15.2 NG-GRPC-01~03 + §16.2 NG-T-R01~R06

## 批次状态一览

| 批次 | 范围 | 状态 | 关键交付 |
|---|---|---|---|
| 设计冻结 | D1~D10 契约（范围/帧读取/描述符绑定/字段深检/压缩/协议化执行/trailers/覆盖/管理面/测试） | **PASS** | `docs/nextgen/NG-GRPC-g1-unary.md` |
| 批次 A（另一执行者） | 帧读取器（parser/grpcframe：流式重组+四重预算+错误三分类） | **PASS** | gateway `dynamic_security/parser/grpcframe/` |
| 批次 B1（本执行者） | 描述符 per-app 绑定管理面（server 单轨） | **PASS** | 迁移 000179/000180、`apigrpcdesc` CRUD 5 端点、发布段、能力门 grpc/2、未登记服务差集；OpenAPI +5 → 705 |
| 批次 B2（agent-442 + 编排收尾） | gateway 深检执行（grpcguard+装配+trailers-only 执行面+能力自报 grpc/2） | **PASS** | `detectors/grpcguard/`（grpcguard.go+structure.go）、`jiuzhang_guard/apigrpcguard.go`、`apiprotect.go writeAPIGRPCErrorResponse` |
| 批次 C（本执行者） | 联调验收（grpc-testorigin+E2E 客户端+R01~R06+回归+文档） | **PASS** | `deployment/stage1/grpc-testorigin/`、`test/waf/grpc-e2e/`、出口记录（本文档） |

## NG-T-R01~R06 验收对照（stage5 真实 Go gRPC SDK 对测，2026-10-07）

| 用例 | 断言（设计 §4） | 结论与证据 |
|---|---|---|
| R01 分片帧/长度/空消息 | 正确重组，有界内存，不错位读取 | **PASS**：r01（200KiB=13×h2 DATA 帧分片）双应用 `PASS text="hello-grpc" origin_mark=[grpc-test-origin]`（源站到达 metadata 实证）；覆盖 `completion=full bytes_read=200KiB+5 descriptor=echo-g1 descriptor_hash=6abdee3a` 与实际一致；错位/长度伪造由批次 A 读取器三分类承载（ProtocolError/BudgetError→8 语义，编码错误 UNKNOWN 不映射） |
| R02 压缩膨胀/未知算法 | 不无限解压，覆盖状态与错误语义正确 | **PASS**：20MiB 高倍率 gzip（压缩后 ~20KB）：PROTECT `code=ResourceExhausted desc="grpc request exceeds resource budget"`（trailers-only 固定短语 `grpc request exceeds resource budget`）；OBSERVE `err=<nil>`（放行+源站（MaxRecvMsgSize 64MiB 放宽后）真回显）；预算触顶 `grpc.compression_budget_exceeded`（8）/gzip 损坏 `decode_error` UNKNOWN 双路径分明 |
| R03 repeated/map/oneof/缺描述符 | 字段语义正确；缺描述符不称完整深检 | **PASS**：缺描述符 `PASS text="ping-no-descriptor" origin_mark=[grpc-test-origin]`（echo.OtherService 未登记**直达源站**（origin_mark 实证），覆盖 `skip_reason=no_descriptor`，PROTECT 引擎下零 BLOCK（UNKNOWN 恒不阻断红线））；结构分支见 R04 |
| R04 一元违规请求 | 返回规范 gRPC 错误，测试服务未执行 | **PASS**：四分支全过——string 超 256KiB（read=307200）/嵌套 9 层（depth_exceeded read=9）/枚举 99 越界/repeated 1025，PROTECT `code=PermissionDenied desc="grpc request rejected by protection policy"`（**trailers-only 纯 gRPC 错误**——客户端 desc 无 transport 错误前缀（与 HTML 403 形态差分实证），grpc-message 固定短语防探测）；OBSERVE（r04-string-observe）`err=<nil>` 放行有记录（field_violation OBSERVE 在册）；源站未执行（grpcguard 先于源站拦截） |
| R05 流首条正常后续违规 | 未实现 G2/G3 则明确部分覆盖 | **PASS**：client-streaming `PASS text="collected:3"`（3 条消息流式正常完成，不误判违规）；覆盖 `skip_reason=streaming_degraded` + `grpc.streaming_observed {messages_seen:2}`——降级即如实声明不覆盖，**不报告**「整个调用通过」 |
| R06 cancel/deadline/慢消费 | 资源释放、背压有效、无任务泄漏 | **PASS**：50 次大消息中途 cancel（20ms 后 RST_STREAM）→ 网关 RSS 598.5→422.6MiB（**无驻留反降**）、caddy.log 零 panic/runtime error、取消路径 `request.body_preserve_skipped{reason:body_read_error}` OBSERVE 如实披露（fail-open 不静默）；读取器无后台 goroutine（解析全在请求 goroutine 内） |

**NG-T-C01**：无描述符/无绑定/非 gRPC 流量全链零行为（grpcguard 装配 nil 零行为；存量回归 40/40、13/13 不回退）。

## 回归输出（原样关键行）

```
阶段5真实网关测试汇总：总用例数 40，通过 40，失败 0
CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败
server：ok apigrpcdesc 1.573s / gatewayconfig 2.023s / guardconfig 1.872s / applications 2.318s / app（-count=1）
gateway：dynamic_security / jiuzhang_guard（含 grpcguard -race 8 测试函数）/ gateway 根三模块全 ok
python3 tools/check-api-reconcile.py：代码注册路由 705  OpenAPI 片段收录 705  对账通过：双向零差集
gofmt：0（本批文件干净）
```

## 联调证据索引

- 客户端 verdict（`test/waf/grpc-e2e` 11 场景）：R01~R06 逐条 PASS 行（上文对照表原样引用）
- 覆盖/事件：网关 `api-runtime-events.log`——`grpc.coverage_v1`（full/skipped(no_descriptor/streaming_degraded) 读数原文）、`grpc.field_violation`/`grpc.enum_out_of_range`（规则+路径+读数）、`grpc.streaming_observed`、`request.body_preserve_skipped{body_read_error}`（cancel 披露）
- 能力门：CAP_MISSING 死锁实证 → capability_report 恒报修正 → `detectors.grpc.unary grpc/2` 自报在册 + 含 PROTECT 绑定发布 SUCCESS
- 环境适配：h2c transport（autosave `versions:["h2c"]`）、WAF 例外（REMOVE_RULE_TAG attack-protocol+attack-sqli+920180/920470/942100/9000102，uri_regex `^/echo\.`，methods=POST，两应用 ENABLED）、bot 墓碑保留（CC 探针兼容）

## 偏差与裁决登记

1. **B1 词表裁决（已闭环）**：server 服务名 CHECK 全小写误拒真实大写驼峰服务名 → 放宽对齐 protobuf 实际规则（包段小写 snake+服务段大写驼峰），迁移 000180+单测+PG 契约。
2. **能力门死锁修正（gateway）**：GRPCUnary 自报绑定配置态 → 恒报进程能力（与 flowguard/az/3 同纪律），否则首次引入描述符的发布必然 fail-closed。
3. **发布段 handler 映射缺失（server）**：`gatewayconfig/guard.go` 补 `h["api_grpc_bindings"]`（绑定落 PG 不下发导致双闸恒 OBSERVE）。
4. **h2c 回源能力（server 新增）**：upstream scheme 词表+h2c → transport versions（gRPC 明文回源必备）。
5. **WAF 语义不适配以例外承载**：CRS/CUSTOM_PACK 对 gRPC 的固有误检（920180 无 CL/9000102 评估/942100 libinjection 撞 gzip 随机字节）——WAF 例外（tag+rule_ids）范围限定（应用+gRPC 路径+POST）；**例外 uri_prefix 段边界匹配教训**（`/echo.` 不匹配 `/echo.EchoService/...`，须全限定段或 uri_regex）。
6. **遗留未定性**：>1MiB 无压缩 gRPC 大请求体经 h2c 上游转发挂起（200~300KiB 通、3MiB 稳定 DeadlineExceeded、源站未收到、网关已读全放行）——转发层问题（检测层帧预算语义正确），列后续排查。
7. **E2E 工具自伤三处（已修）**：SDK 默认 4MiB 接收上限/client-streaming 缺 CloseSend 死锁/r01 消息踩预算线（200KiB 分离正常流与违规验证）；源站默认 4MiB 接收上限放宽 64MiB。

## S5 关闭声明

NG-GRPC G1（unary 有界深度检测）设计 D1~D10 全部落地，NG-T-R01~R06 经真实 Go gRPC SDK 对测全过（无 curl 冒充），UNKNOWN 恒不阻断红线全程成立（缺描述符/解码失败/依赖缺席放行+披露），回归零回退（40/40、13/13、server/gateway 全量测试绿、reconcile 705 双向零差集、gofmt 干净），现场可复核（stage5 全栈 healthy，grpc-testorigin/echo 描述符/绑定/例外在册）。**S5 阶段关闭**；G2/G3（streaming 逐消息检查与背压）与 >1MiB 无压缩大体 h2c 转发问题列入后续批次。
