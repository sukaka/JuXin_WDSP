# S8 NG-REL-01 跨模块全量回归冻结报告

> 日期：2026-10-09 ｜ 依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §15.2 NG-REL-01（「跨模块/回归/容量与恢复｜冻结报告，强制项全部 PASS」）
> 口径：全部套件由本批**亲跑**并原样记录关键输出，不信既有记录；失败项如实登记根因与处置，不冒充通过；未执行项一律 NOT_RUN 不折算。
> 配套文档：验收对账表 `docs/nextgen/s8/S8-ACCEPTANCE-MATRIX.md`。

## 1. 环境指纹（2026-10-09 04:30 实测）

```
date:    2026-10-09 04:30:26 +0800
OS:      macOS 26.2 (25C56) ｜ arch: arm64 ｜ kernel: Darwin 25.2.0 arm64
go:      go version go1.25.6 darwin/amd64（server/gateway go.mod 均 directive go 1.25.6）
node:    v24.13.0 ｜ npm: 11.6.2
python:  Python 3.12.0（/Library/Frameworks/Python.framework/Versions/3.12/bin/python3，reconcile 指定解释器）
docker:  client 28.3.0 ｜ server 28.3.0（Docker Desktop）
stage5:  jiuzhang-stage5-{api,gateway,gateway-b,postgres,valkey,testorigin,grpc-testorigin,mcp-testorigin,...} 全 healthy
         API http://127.0.0.1:18081 ｜ 网关 http://127.0.0.1:18080 ｜ gateway-b 18083
```

**性能判定注意（承接 S1 §3 结论）**：本环境为 Mac 构建机+Docker Desktop，请求时延波动远大于性能候选门槛（±4 倍），本报告不含性能门槛判定，性能项一律列 §8 NOT_RUN。

## 2. 源码状态快照（冻结现状，如实登记）

```
分支: main ｜ HEAD: e341853 feat(network-tools): add network diagnostics and NTP/DNS settings
工作区: 384 个修改（M）+ 305 个未跟踪（??）
  按顶层目录: test 247 ｜ server 173 ｜ gateway 97 ｜ web 64 ｜ output 36+11 ｜ ops 17 ｜ docs 11 ｜ wdsp-agent 10 ｜ deployment 8 ｜ tools 4 ｜ licenses 4
```

S1~S7 全部交付物（含迁移 000168~000184、`web/src/pages/api-mcp/`、`web/src/pages/api-machine-identities/` 两页面目录）当前均为**工作区未提交改动**；提交/推送按 AGENTS.md 协作纪律属编排者（Codex）职责，本批不做任何 git 写操作。本快照即 NG-REL-01「冻结报告」的源码状态登记。

## 3. 回归套件逐条记录（命令原样 + 关键输出原样 + 结论）

执行次序说明：server/gateway/web/协议套件为首轮（04:14~04:18 前后）；stage8 三套件首轮三项红灯（§4），处置后于 04:30 起串行复跑；stage5 链与 gateway 两模块在**最终环境状态**（§4 处置完成后）于 04:38 复跑定案。

### 3.1 server 全量单测

```
命令: cd server && go test ./... -count=1（直捕退出码）
输出: ok 103 包 ｜ FAIL 0 ｜ go_test_exit=0
结论: PASS
```

注：首轮曾因管道 `$?` 取到 tail 退出码污染记录、另一次高负载并行复跑 awk 统计出 fail=3 假象；本次 `-count=1` 直捕退出码复跑零 FAIL 定案。

### 3.2 gateway 三个模块单测

```
命令: cd gateway && go test ./... -count=1（直捕退出码）
输出: ok 7 包（eventparser 0.842s / corazasemantics 1.786s / havipd 1.717s /
      internal/eventparser 1.223s / mirrorcap 4.441s / netmgrd 4.576s / tproxyd 5.889s）
      ｜ gateway_root_exit=0
命令: cd gateway/dynamic_security && go test ./... -count=1 ｜ dynsec_exit=0（ok 23 包，零 FAIL）
命令: cd gateway/modules/jiuzhang_guard && go test ./... -count=1 ｜ guard_exit=0（ok 17 包，零 FAIL）
结论: PASS（tproxyd 首轮批跑失败一次的 flaky 定性见 §5）
```

### 3.3 web 前端

```
命令: cd web && npm run typecheck && npm run lint && npx vitest run（逐段直捕退出码）
输出: tc_exit=0 ｜ lint_exit=0 ｜ Test Files 139 passed (139) ｜ Tests 1070 passed (1070) ｜ vitest_exit=0
结论: PASS
```

### 3.4 stage5 存量回归链（最终环境状态复跑）

```
命令: bash test/waf/scripts/stage5-gateway-tests.sh        → 通过: 40（失败 0）｜ exit=0
命令: bash test/waf/scripts/custom-pack-blocking-tests.sh  → CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败 ｜ exit=0
命令: bash test/waf/scripts/authz-cross-module-contract-gate.sh → AUTHZ-01 real Provider environment gate: PASS ｜ exit=0
结论: PASS（40/40 + 13/13 + 能力门契约门）
```

### 3.5 stage8 三套件（处置后串行复跑）

```
命令: bash test/waf/scripts/stage8-gateway-tests.sh            → 阶段8 全链路验证：15/15 通过，0 失败 ｜ exit=0
命令: bash test/waf/scripts/stage8-replay-tests.sh             → 阶段8 流量回放测试：10/10 通过，0 失败 ｜ exit=0
命令: bash test/waf/scripts/stage8-unified-decision-tests.sh   → §207 统一决策验证：23/23 通过，0 失败 ｜ exit=0
结论: PASS（合计 48 用例零失败；首轮红灯与处置见 §4）
```

### 3.6 OpenAPI 双向对账

```
命令: /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 tools/check-api-reconcile.py
输出: 代码注册路由: 727  OpenAPI 片段收录: 727 ｜ 对账通过：双向零差集
结论: PASS（727，与 S7 出口持平）
```

### 3.7 协议异常套件（阶段1 POC 适配物）

```
命令: python3 test/waf/scripts/protocol-tests.py（打 stage5 网关 18080）
输出: 2/5 通过（proto-conflicting-content-length、proto-duplicate-te-headers 过）；
      proto-oversized-header（得 200 期望 431/400）、proto-invalid-method（得 200）、proto-body-type-mismatch（得 200）失败
结论: 不定性为产品缺陷——POC 适配差异，逐条定性与正向对照见 §6
```

## 4. 首轮三项红灯：根因链与处置（全部闭环）

### 4.1 现象（首轮 04:14~04:17 本地）

- `stage8-gateway-tests.sh` **14/15**：失败项「OBSERVE 模式类型偏离不阻断（=403）」；
- `stage8-replay-tests.sh`：setup 首次发布 FAILED → ABORT（未实际跑用例）；
- `stage8-unified-decision-tests.sh`：「策略发布成功（OBSERVE 生效）」FAILED → ABORT。

### 4.2 根因链（两层，DB 实证）

**第一层——JWT 信任链防静默降级校验按设计拒发**（三套件共同直接原因）：

```
gateway_publish_tasks（2026-10-08 20:17:02~04 UTC，三条 FAILED）:
  failure_code=GUARD_SNAPSHOT_FAILED
  failure_message=应用 [mcps5p] 的 JWT 信任策略为 PROTECT，但 API 动态管线模式为 OBSERVE，
                  发布会把强制校验静默降级为观测，拒绝发布
```

- 校验实现 `server/internal/guardconfig/jwt_trust.go:64-70`：任一应用 jwt_trust=PROTECT 时全局 API 动态管线有效模式必须为 PROTECT，否则拒发——**安全校验按设计工作，非产品缺陷**。
- mcps5p jwt_trust=PROTECT 为 S6 残留现场（`jwt_trust_policies` 表：2026-10-07 14:52 UTC 起，version=11）；S7 期间全局管线=PROTECT（一致，故 S7 全绿），S7 收尾全局留在 PROTECT。
- `stage8-gateway-tests.sh` 全程不在第 6 步前切 OBSERVE——脚本假设环境缺省 OBSERVE（S7 前一直成立）。实际模式为 PROTECT 残留：第 6 步类型偏离请求实测 403（PROTECT 实断）→ 用例失败；第 7 步 PUT PROTECT+发布 SUCCESS（20:17:01 UTC，一致态）；第 8 步「还原 OBSERVE」PUT 成功但发布被校验拒（20:17:02 UTC）——管理面 OBSERVE/网关仍 PROTECT 快照。后续两套件 setup 发布同因 ABORT。

**第二层——s5ud 缺 Bot 墓碑导致发布后冒烟 fail-closed**（第一层修复后暴露）：

```
gateway_publish_tasks（2026-10-08 20:26 UTC，两条 FAILED）:
  failure_code=VERIFY_FAILED_ROLLED_BACK
  failure_message=发布后验证失败，已自动回滚: 发布后流量验证未通过：[s5ud/CC] CC 探针响应与防护链预期不符（status=404）
```

- 发布冒烟探针路径固定 `/_wdsp/bot/v1/publish-smoke`（`server/internal/gatewayconfig/publisher_smoke.go:80`）：guard 本地 404 墓碑（正文恰 "404 not found"+no-store）证明完整防护链生效；s5ud（stage8-unified-decision 套件 20:17 自建应用）**无 bot_policies 行**，探针穿透源站拿到非墓碑 404 → FAIL → 自动回滚。
- 部署契约已知：`S3-AZ03-EXIT-NOTE.md` 联调新发现 3 明文「新应用发布验证需 Bot route_reservation=RESERVED_TOMBSTONE（首次 OFF 无墓碑探针 404 fail-closed）」——**套件脚本未遵守既有契约，属测试脚本缺口，非产品缺陷**；冒烟校验 fail-closed 并自动回滚按设计工作（本批顺带实证了该回滚路径真实有效）。

### 4.3 处置动作（测试环境状态整理，零生产代码改动）

1. `PUT /api/v1/applications/8bf5e2d2-…/jwt-trust-policy`：mcps5p mode PROTECT→OBSERVE（expected_version=11→12，issuers/selectors 原样保留，reason 注明 S8 回归前置）→ 200；
2. `PUT /api/v1/applications/7e8bed42-…/bot-policy`：s5ud 补 OFF+RESERVED_TOMBSTONE（对齐其余套件约定）→ 200；
3. 验证发布：`POST /api/v1/api-security/policy/publish` → **SUCCESS**（20:29:53 UTC，「流量验证通过（9 项探针 PASS，3 项 SKIP）」）——两层根因判断双验证；
4. 三套件串行复跑（§3.5）全绿；stage5 链与 gateway 模块在最终状态复跑（§3.2/§3.4）全绿。

### 4.4 登记事项（移交编排者裁决，本批不改脚本）

- `stage8-gateway-tests.sh` 缺省 OBSERVE 假设无自查（首轮 14/15 的直接诱因）；`stage8-unified-decision-tests.sh` 建应用不补 Bot 墓碑。建议两脚本补前置自查/墓碑（测试侧整改，不属本批范围）。

## 5. tproxyd flaky 定性（gateway 根模块）

| 轮次 | 形态 | 结果 |
|---|---|---|
| 首轮（多模块并行批跑） | `FAIL github.com/jiuzhang-waf/gateway/tproxyd 4.738s` | FAIL |
| 单跑 `go test ./tproxyd/ -count=1` | `ok 3.877s` | PASS |
| 根模块全量复跑（直捕退出码，本批定案轮） | `ok ... tproxyd 5.889s` ｜ `gateway_root_exit=0` | PASS |

定性：**高负载并行下资源竞争型 flaky**（2/3 通过，单跑与全量复跑均绿，失败仅现于多模块并行批跑）。按纪律只记录不修；未抓到 `--- FAIL:` 测试名（首轮批跑日志未保留失败用例名），若复现建议 `go test ./tproxyd/ -count=20` 定位。

## 6. protocol-tests.py 三条失败断言的定性（POC 适配差异，非产品缺陷）

脚本头自述「九章阶段1 协议异常测试…**仅对本地 POC 网关执行**」，无 Host 头概念（全部 `Host: 127.0.0.1`），断言编码 stage1 POC 网关前提。逐条实测定性（stage5 环境，2026-10-09）：

| 用例 | 实测 | 定性 |
|---|---|---|
| proto-oversized-header（128KB 头期望 431/400，得 200） | 带 WAF-On 宿主头（sf-s5.local）复测仍 200 | Caddy 平台缺省头部上限 1MB，128KB 在限内放行；断言编码 POC 网关 64KB 上限。**平台缺省差异**；「stage5 网关未收紧头部尺寸上限」登记为配置评审项（§8 移交 13），非回归 |
| proto-invalid-method（HACKMETHOD 期望 403/400/405/501，得 200） | 缺省宿主 waf-s5.local 当前发布快照 `SecRuleEngine Off`（现行配置实证：srv0 路由 9 `waf` handler 指令首行）→ CRS 911 不求值；**正向对照**：同请求打 WAF-On 宿主 sf-s5.local → **403**（CRS 911 拦截生效） | 宿主 WAF 策略 Off 下的预期放行+脚本 POC 适配；WAF-On 路径实证拦截 |
| proto-body-type-mismatch（声明 JSON 发 XML 期望 403/400，得 200） | 同上 Off 原因；**正向对照**：sf-s5.local → **400**（JSON 解析失败拒绝生效）；SQLi 对照 → **403** | 同上 |
| proto-conflicting-content-length / proto-duplicate-te-headers | 通过 | Go HTTP 解析层拒绝，平台级行为成立 |

结论：本套件在 stage5 环境记 **2/5 通过、3 条 NOT_APPLICABLE（POC 前提不成立）**，不计入红灯；套件是否适配 stage5 常规回归（加 Host 头/指 WAF-On 宿主/调整头部上限断言）移交编排者裁决。

## 7. 容量与恢复汇总表（跨阶段证据聚合）

| 场景 | 结论 | 证据 |
|---|---|---|
| FLOW Valkey 故障 | 停 Valkey 恒 UNKNOWN 放行、不切本地降级；恢复后 fencing 单调延续、PG 可对账 | S4 F07（S4-EXIT-SUMMARY F07 行+Caddy 日志 D8） |
| 网关重启 | 热状态经 PG 事实源读回恢复 | S4 F07 |
| AZ 撤销水位回滚 | 回滚到低水位快照拒载 fail-closed（ROLLBACK_PUBLISH_FAILED），PreviousValid 资格过滤 | S3-AZ02 D3/D4-1 |
| 机器身份撤销水位回滚 | 同上机制独立实证；已撤销键不复活 | S7 I04（i04-rollback-task.json/i04-watermark.log） |
| 机器身份重放存储（Valkey）中断 | PROTECT 双节点 503+MID_UNAVAILABLE；OBSERVE 放行+披露；恢复后正常 | S7 I03 |
| 依赖缺席/旧节点能力门 | fail-closed CAPABILITY_MISSING 不发送 /load（az/2、az/3、mcp/1、mcp/2、grpc/2、mid/1 六组三态实证） | S3/S5/S6/S7 各能力门节 |
| MCP 目录完整性 | catalog_hash 装配期重算比对，不一致拒装 | S6 批次 B2/偏差 1 |
| 发布冒烟失败自动回滚 | VERIFY_FAILED_ROLLED_BACK 真实触发并自动回滚（本批 §4.2 第二层实证，非演练） | 本报告 §4 |
| CC 计数精确性 | CC_EXACT 探针打满阈值 N 验证第 N+1 次 429（可验证策略；动作非 REJECT 实断如实 SKIP） | publisher_smoke.go 第四探针；本批发布 3 项 SKIP 原样在册 |
| 快照体积基准（200000 relations/10000 冲突上限形态） | **NOT_RUN** | S3-AZ02 遗留 5 |
| 24h 稳定性 | **NOT_RUN** | §8 |
| 性能正式双报告（amd64 固定硬件+兆芯/openEuler） | **NOT_RUN**（本环境噪声大于门槛，S1 §3 结论承接） | §8 |

## 8. NOT_RUN 清单（不折算为通过）

1. **NG-REL-02 全部**：纯离线测试机完整包安装/前台升级/失败恢复（含 openEuler 测试）——批次 D；
2. **NG-REL-03 全部**：运维/限制/版本与交付清单（需用户批准发布）——批次 D；
3. **§16 D01~D08** 发布与运行矩阵——随批次 D（D04/D06/D07 有部分间接证据在册，不折算）；
4. **24h 稳定性**与**高并发长时**（D06 主臂）；
5. **性能门槛正式双报告**（普通 amd64 固定硬件 + 兆芯/openEuler；本环境不可判定，S1 §3）；
6. **ha-lab 双节点分区演练矩阵**（A07 分区断言、AZ-02/03 与 FLOW 合并编排）；
7. go-ftw 10014xx 簇整改后复跑（S1 §5.3，用例设计问题定责在册）；
8. MCP 调用预算（max_calls_per_minute/429）stage5 联调证据（S6 §已知限制，单测承载）；
9. AZ CLOCK_SKEW 负向漂移 stage5 实证（需节点时钟注入设施，S3-AZ03 遗留 1）。

## 9. 结论（NG-REL-01 强制项判定）

- 回归套件 **10/10 全绿**（server 103 包 / gateway 7+23+17 包 / web 139 文件 1070 用例 / stage5 40+13+契约门 / stage8 15+10+23 / reconcile 727 双向零差集），全部直捕退出码原样记录；
- 首轮三项红灯全部查明根因（安全校验按设计拒发+套件脚本缺口），处置后复跑全绿，**零生产代码改动**；
- tproxyd flaky、protocol-tests POC 适配差异如实定性登记；
- 容量与恢复：九项场景有实证（含本批真实触发的发布冒烟自动回滚），三项标 NOT_RUN；
- **NG-REL-01 强制项（已交付范围回归+跨模块矩阵断言）全部 PASS**；§16 总计数 PASS 50 / PARTIAL 2 / NOT_APPLICABLE 1 / NOT_RUN 8，缺口去向见对账表 §3。

**NG-REL-01 按完成证据「冻结报告，强制项全部 PASS」判定达成**；NG-REL-02/03 留批次 D。
