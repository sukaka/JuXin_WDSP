# 阶段5 测试报告（IP访问控制、真实客户端IP识别与CC防护）

## 1. 测试环境

| 项目 | 值 |
|------|-----|
| 主机 | macOS（Apple Silicon 虚拟化），Docker Desktop |
| Go | 1.25.6 |
| Node.js | 24.13.0 |
| PostgreSQL | 16.4-alpine |
| Valkey | 8.1.8-alpine |
| Caddy | v2.11.4 + coraza-caddy v2.5.0 + jiuzhang_guard（自主模块）+ CRS v4.28.0 |
| 压测工具 | ApacheBench（ab）+ 自研 flood 脚本 |
| 测试日期 | 2026-07-21 |

## 2. 测试结果汇总

| 测试类别 | 总数 | 通过 | 失败 |
|---------|------|------|------|
| jiuzhang_guard 模块单元测试 | 41 测试函数（9 包） | 41 | 0 |
| 后端单元测试（阶段5相关包） | 283 用例/子用例 | 283 | 0 |
| 后端接口集成测试（阶段5） | 16 | 16 | 0 |
| 阶段2/3/4 后端回归（单元+集成） | 全部 | 通过 | 0 |
| 前端单元测试 | 59（阶段5新增 14） | 59 | 0 |
| 真实网关测试 | 40 | 40 | 0 |
| 安全测试（阶段5） | 25 | 25 | 0 |
| Fail-closed 真实验证 | 5 | 5 | 0 |
| 性能测试 | 9 | 9 | 0 |
| Playwright E2E（阶段5） | 6 | 6 | 0 |
| E2E 回归（阶段4） | 5 | 5 | 0 |

## 3. jiuzhang_guard 模块单元测试（41 测试函数，9 包全绿）

| 包 | 覆盖 |
|----|------|
| cidr | v4/v6/CIDR/映射归一/掩码化/域名·端口·协议·通配·控制字符拒绝/匹配器 |
| clientip | 直接访问/伪造XFF/单级/多级/混合链/超长链回退/非法头回退/X-Real-IP/Forwarded/自定义头/IPv6/映射/控制字符 |
| trustedproxy | 优先级匹配/头类型校验/自定义头名校验 |
| accesscontrol | 分层优先级/同层优先级/临时到期/未来生效/v6 CIDR |
| ratelimit | 令牌桶阈值/突发/恢复/滑动窗口加权/键隔离/非法参数/Valkey结果解析/故障传播 |
| counters | 有界 LRU（经 ratelimit 间接）/Valkey 客户端（真实栈验证） |
| temporaryblock | 存取往返/损坏条目计数/应用与全局封禁/过期/轮询同步/解封生效 |
| events | JSONL 写入/字段截断/控制字符剥离/单行保证 |
| module（根包） | 拒绝403/白优先/保护地址/伪造XFF忽略/可信代理真实IP封禁与改写/临时封禁/429+Retry-After/无内部泄露/观察不阻断/自动封禁/URI匹配/Fail-open·Fail-closed |

## 4. 后端接口集成测试（16，`server/tests/stage5_integration_test.go`）

可信代理 CRUD/命中测试/保护地址（refresh 幂等、系统地址禁删）/黑白名单 CRUD/临时规则延期解封/
保护地址封禁拒绝/导入（dry_run 行级定位、ALL_OR_NOTHING、SKIP_ERRORS、文本格式）/导出公式注入转义/
CC策略 CRUD（零窗口/负阈值/缺封禁时长/非法正则各 400）/干跑模拟/临时封禁列表/事件列表与导出/
版本列表/校验API/RBAC 边界（审计只读 200+写 403、系统管理员可信代理 200+业务规则 403）/
到期自动失效调度（临时规则与封禁到期标记 EXPIRED + 系统审计）/证书绑定解绑独立接口（含域名不匹配 400）。

## 4.1 Fail-closed 真实验证（5，`test/security/stage5-failclosed-test.sh`）

`GUARD_FAIL_OPEN=false` 发布后暂停 Valkey：CC 请求按 429 拒绝（Fail-closed）且
RATE_LIMIT_ENGINE_ERROR 告警入库；恢复 `GUARD_FAIL_OPEN=true` 发布后故障放行。
故障策略随发布下发逐实例生效，无需重启网关。

## 5. 真实网关测试（40，`test/waf/scripts/stage5-gateway-tests.sh`）

- 伪造防护：伪造XFF/X-Real-IP忽略、X-Real-Ip服务端覆盖、伪造轮换不能绕过CC、连接源黑名单403、阻断未到源站；
- 真实IP：单级/多级可信代理、超长链回退、非法头回退；
- 黑白名单：CIDR阻断、全局白>全局黑、应用白>应用黑；
- CC：阈值以下/达阈值429/Retry-After+X-Jiuzhang-Request-ID/无内部泄露/不同IP独立/URI级共享/观察不阻断/临时封禁429→403/白名单绕过；
- 临时封禁：记录入库、人工解封生效；
- 事件：8 类事件全部入库、Request ID 可关联；
- Valkey 故障：Fail-open 放行 + RATE_LIMIT_ENGINE_ERROR 告警。

## 6. 安全测试（25，`test/security/stage5-security-tests.sh`）

多重代理头首值、未配置头类型忽略、映射归一封禁、CIDR边界内外、裸socket不崩溃、
随机键耗尽有界（内存<512MiB、键增长有界）、Valkey键无注入、并发发布一致、
过去时间/负阈值/零窗口/危险正则 400、超大导入（>10000行）400、CSV公式注入转义、
日志注入单行无字段、存储型XSS安全返回、429不反射、保护地址封禁拒绝、审计管理员越权 403。

## 7. 性能测试（9，`test/performance/stage5-performance-tests.sh`，结果存档 `stage5-performance-result.txt`）

| 指标 | 结果 | 目标 |
|------|------|------|
| 基线 P50/P95/P99 | 3ms / 9ms / 11ms（RPS 12728） | - |
| 1000 条黑名单 P95 | 7ms（Δ<5ms） | <5ms 新增 |
| 10000 条黑名单 P95 | 7ms（Δ<5ms） | <5ms 新增 |
| 1000 条 CIDR P95 | 7ms（Δ<5ms） | <5ms 新增 |
| CC 计数（100 策略加载）P95 | 6ms（Δ<10ms） | <10ms 新增 |
| 200 并发 20000 请求 | RPS 14742，0 失败，P95 29ms | 500 RPS 无持续错误 |
| 随机 IP/URI 键攻击 | 内存 218.7→189.2MiB（稳定），键增长有界（TTL 过期） | 不无限增长 |
| 发布期间打流 | 0 失败 | 旧策略持续可用 |

## 8. E2E（6，`web/e2e/stage5-access-control.spec.ts`）

可信代理 UI 全流程、事件来源黑名单发布阻断、白名单优先级、CC策略发布429、
临时封禁与解封、审计管理员只读。阶段4 E2E 回归 5 用例同步通过。

## 9. 结论

阶段5全部测试通过，满足任务书退出条件：jiuzhang_guard 可重复构建并真实加载；
真实IP识别正确且伪造无效；黑白名单/CIDR/IPv6/临时规则/优先级正确；CC限速各维度生效；
429 与 Retry-After 正确且无内部泄露；临时封禁与人工解封链路闭环；事件统一入库且 Request ID 可关联；
发布失败不影响当前配置、可回滚；三权边界与全部安全项实测通过；性能目标全部达到。
