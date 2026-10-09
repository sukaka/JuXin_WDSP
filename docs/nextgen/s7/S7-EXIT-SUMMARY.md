# S7 阶段小结（NG-ID G1：机器身份（HTTP Message Signatures）首期 —— 阶段关闭）

日期：2026-10-09 ｜ 设计冻结：`docs/nextgen/NG-ID-g1-machine-identity.md`（实现状态 §7 同文件追加）
依据：`docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md` §12（方向七）+ §15.2 NG-ID-01~03 + §16.4 NG-T-I01~I05 + §4 共用安全契约

## 批次状态一览

| 批次 | 范围 | 状态 | 关键交付 |
|---|---|---|---|
| 设计冻结 | D1~D14 契约（路线/登记模型/公钥导入/验证链/重放/轮换撤销/防护协同/UNKNOWN/预算/错误语义/能力门/管理面/覆盖/接入契约） | **PASS** | `docs/nextgen/NG-ID-g1-machine-identity.md` |
| 批次 A（另一执行者） | HTTP 签名验证纯库（RFC 8941 SF 子集+基线重构+三算法验签+预算+重放 Store）+RFC 9421 附录 B 黄金样本+fuzz | **PASS** | gateway `dynamic_security/httpsig/`（零第三方依赖） |
| 批次 B1（另一执行者） | 登记管理面+发布段（server 单轨） | **PASS** | 迁移 000183/000184、`apimachineid` 12 端点（jwt_trust.read/manage 零新增权限）、发布三段逐字冻结、capability_gate facts、OpenAPI +12 → 727 双向零差集 |
| 批次 B2（另一执行者） | machineid 执行面（gateway 单轨） | **PASS** | `detectors/machineid/`（十步验证链+冻结 reason 词表）、`jiuzhang_guard/apimachineid.go` 装配（水位拒载 fail-closed/committed 直写错误语义）、bot_step 三重豁免消费点、能力自报 mid/1 恒报、覆盖双承载 |
| 批次 C（本执行者） | 联调验收（参照客户端+双网关 overlay+I01~I05+能力门三态+C01/C04/C09+回归+文档） | **PASS** | `test/waf/mid-e2e/`（Go stdlib 三算法参照签名器，零第三方依赖）、`deployment/docker-compose.stage5-mid.yml`、`test/waf/mid-e2e/run-stage5.sh`、出口记录（本文档）；联调修正两处跨轨对齐+客户端合规化（§偏差与裁决 1/2/6） |

## NG-T-I01~I05 验收对照（stage5 真实环境参照客户端对测，2026-10-09）

证据目录 `output/evidence/mid-g1-20261009-035133/`（`all` 单轮全量：records.log **90 PASS 0 FAIL**）。

| 用例 | 断言（设计 §4） | 结论与证据 |
|---|---|---|
| I01 有效证明/方法或 URI 变化 | 三算法有效签名通过（VERIFIED 在册+源站到达）；改方法/路径/query 任一 → 401（与协议规范一致）；RFC 9421 附录 B 黄金样本逐字节 | **PASS**：ed25519/ecdsa-p256-sha256/rsa-pss-sha512 各 `status=200`+`X-Wdsp-Origin-Mark` 源站到达+MID_VERIFIED 事件在册；篡改 method/path/query → 401 `MID-SIGNATURE-INVALID`、篡改 body → 401 `MID-DIGEST-MISMATCH`（裁决 1 集合断言生效）；多标签 → 401 `MID-SIGNATURE-MALFORMED`；未签名（proof_required）→ 401；omit @path → 401 `MID-COVERAGE-INSUFFICIENT`；keyid URL 形态 → 401 `MID-KEY-UNKNOWN`（不抓取）；过期证明/寿命超限 → `MID-PROOF-EXPIRED`、未来 created → `MID-CLOCK-SKEW`；OBSERVE 对照：未签名 200 放行+覆盖观测 `NOT_APPLICABLE`/`MID-NA-UNSIGNED-001` 在册（i01-na-coverage.json）、篡改放行到源站+MID_OBSERVED 在册。黄金样本由 `httpsig` 单测承载（附录 B 向量逐字节+fuzz+leak 全绿） |
| I02 Token 与密钥绑定不符 | keyid 未登记/alg 与登记不符/principal_binding 与 JWT VERIFIED 主体不一致 → 401 不升级可信机器身份；JWT 缺席机器身份独立成立 | **PASS**：principal_binding 录入 alice 指纹+发布后——alice `200` 放行/bob `401 MID-PRINCIPAL-MISMATCH`（不升级可信机器身份）/无 JWT 签名独立成立 `200`（不冒充人类主体）；k-ghost（未登记）与 k-dis（DISABLED 身份键不下发）均 401 `MID-KEY-UNKNOWN`；alg 声称与登记不符、词表外 hmac-sha256 均 401 `MID-ALG-REJECTED`；**裁决 3 线值实证**：autosave `principal_binding=871091b247c9ad35a76c665b57459d8f` == HMAC-SHA256(identity_salt, "jwt-principal:"+录入值) 截前 16 字节 hex（autosave-i02.json 与 python 复算一致） |
| I03 两节点重放/存储不可用 | A 收 nonce N → B 同 nonce 同身份重放 401（Valkey SET NX 原子，无一放行两次）；停 Valkey PROTECT 双节点 503+OBSERVE 放行披露；恢复后正常 | **PASS**：gateway-b（`docker-compose.stage5-mid.yml` 叠加实例，共享 autosave 卷+共享 Valkey，端口 18083）配置收敛签名探针 200；固定 nonce：A `200` → B `401 MID-REPLAY-DETECTED` → 回本节点 A `401 MID-REPLAY-DETECTED`；Valkey 键 `mid:v1:nonce:{a11000b4…}:bbc443b0…` EXISTS=1（hash tag 同槽在册，i03-nonce-key.txt）；停 Valkey → 双节点 `503`+MID_UNAVAILABLE 事件、OBSERVE 应用 `200`+MID_OBSERVED 披露（dependency_unavailable 语义）；恢复后双节点 200 |
| I04 撤销/轮换/回滚 | revoke 发布后 401 MID-KEY-REVOKED；rotate 重叠窗口新旧键均过；普通回滚到低水位快照拒载 fail-closed 且已撤销键不复活；旧节点能力门 fail-closed；旧键状态管理面可见 | **PASS**：撤销 k-rsa+发布 → `401 MID-KEY-REVOKED`；轮换 k-ed→k-ed2 → RETIRED 窗口内旧键 `200`+新键 `200`；管理面读回状态机 REVOKED+revoked_seq≥1 / RETIRED+retire_overlap_until / ACTIVE（i04-identity.json）；回滚水位 0 快照 → 发布任务 **FAILED(ROLLBACK_PUBLISH_FAILED)**（i04-rollback-task.json）+网关日志 `MID_WATERMARK_REGRESSION: incoming machine identity snapshot watermark below applied, config load rejected (fail-closed)` 在册（i04-watermark.log）+回滚被拒后 k-rsa 仍 `401`（网关保留现行配置，已撤销键不复活）；能力门三态见下 |
| I05 合法机器发起 WAF/CC/Bot 攻击 | VERIFIED 机器携 SQLi → WAF 照拦（CRS 事件在册）；超配额 → 限速照判；未声明 exempt 的 VERIFIED 机器 → Bot 挑战照走；声明 exempt 且绑定命中 → 豁免事件在册 | **PASS**：签名有效 SQLi → `403`（Coraza 审计在册 i05-coraza-audit.log）且该请求 MID_VERIFIED 在册（签名有效不豁免 WAF）；CC（/submit limit 3/60s burst 3 REJECT）5 个签名请求前 3×`200` 后 2×`429`（不豁免 CC）；Bot PROTECT /articles——k-bot（未豁免）合格 HTTPS 浏览器文档导航第 3 次 `403` 挑战+BOT_CHALLENGE_OFFERED 事件在册（照走挑战）；k-bx（exempt）3×`200` 直通+`MID_BOT_EXEMPT` 事件在册（身份 exempt∩绑定命中∩VERIFIED 三重显式成立） |

**能力门三态（stage5 实证）**：无 machineid 旧节点（共享卷 exec 覆写清单注入删除 machineid 自报，保属主——docker cp root 化连锁先例；真实清单入口一次快照防恢复源污染）→ 发布 **FAILED CAPABILITY_MISSING**：`CAP_MISSING:detectors.machineid(required=mid/1,actual=)`（不发送 /load，capgate-old-task.json）；五绑定全改 OBSERVE → 旧清单在位发布 **SUCCESS**（零需求滚动升级）；恢复真实清单（mid/1 恒报）+改回 PROTECT → 发布 **SUCCESS** 收载（环境已复原 PROTECT 绑定+真实清单）。

**NG-T-C01**：无绑定应用（waf-s5.local）未签名 /ping → 200 普通流量直达+零 MID 事件（机器身份零行为）；存量回归 40/40、13/13 不回退。**C04**：白名单（ALLOW 198.51.100.77 RFC5737）+CC（/download limit 1/60s）——未签名 XFF 非白名单首发 `401 MID-SIGNATURE-MALFORMED`（CC 计数后机器身份拒绝）→ 再发 `429`（CC 先于机器身份饱和实证）；XFF 白名单未签名仍 `401`（跳过 CC **不绕过**机器身份——serveNext 统一出口顺序实证）。**C09**：未认证 GET 401；AUDIT_ADMIN 一次性探针用户读 200/写 403（jwt_trust.read 三角色全授+manage 仅 SYSTEM_ADMIN/SECURITY_ADMIN 种子口径实证）；写操作 HIGH 审计 ≥50 条在册（module=api_security，示例 action=rotate_key）。

## 回归输出（原样关键行）

```
阶段5真实网关测试汇总：总用例数 40，通过 40，失败 0
CUSTOM_PACK 二次阻断评估验证：13/13 通过，0 失败
server：ok guardconfig 2.4s / apimachineid 2.3s / gatewayconfig 2.0s / app 2.3s（-count=1）
gateway：dynamic_security ok httpsig 1.4s / machineid 1.2s；jiuzhang_guard 模块全量 ok（-count=1）
python3.12 tools/check-api-reconcile.py：代码注册路由 727  OpenAPI 片段收录 727  对账通过：双向零差集
gofmt：0（本批文件干净）；go build server/gateway 全过
```

（断点复核：2h 超时中断后 40/40 与 13/13 于 2026-10-09 串行复跑原样全绿。）

## 联调证据索引

- 证据目录：`output/evidence/mid-g1-20261009-035133/`（records.log 90 PASS 0 FAIL 全矩阵单轮；client.log 客户端 VERDICT 原样；ids.env 身份/应用锚点；jwks.json 参照 JWKS；autosave-i02.json 裁决 3 线值；i01-na-coverage.json 覆盖观测原文；i03-nonce-key.txt Valkey 重放键；i04-identity.json 状态机读回/i04-rotate.json 轮换响应/i04-rollback-task.json 回滚 FAILED 任务原文/i04-watermark.log 水位回归日志；i05-coraza-audit.log CRS 阻断审计/i05-bot-offered.log 挑战事件；capability-old.json/capability-real.json 清单快照/capgate-old-task.json 能力门失败任务原文；audits.json HIGH 审计读回；events-assert.log 逐 rid 事件断言流水）
- 过程性证据（分阶段迭代轮次，含失败-修复闭环）：`output/evidence/mid-g1-20261009-025953` ~ `mid-g1-20261009-034945` 各目录（UA/Content-Type 合规化与同 rid 多事件断言修正前的中间轮次如实保留）
- 网关日志：`guard-events.log`——MID_VERIFIED/MID_OBSERVED/MID_AUTH_FAILED（全 reason 词表逐格）/MID_UNAVAILABLE/MID_BOT_EXEMPT 在册；`coverage-observations.jsonl` machineid 相位读数（FULL/NOT_APPLICABLE+MID-NA-UNSIGNED-001）；`coraza-audit.log` SQLi 阻断事务；`caddy.log` MID_WATERMARK_REGRESSION 告警
- 源站：testorigin 回显 X-Wdsp-Origin-Mark（「确实到达源站」锚点，S5/S6 同纪律）

## 偏差与裁决登记

1. **裁决 3 principal_binding 发布域换算（已闭环，server 修正）**：管理面录入值是 JWT 事件可观测主体指纹（apiauthz 域 HMAC 第一层），网关消费侧比对 jwtverify 产出值域——裸值直传则 PROTECT 全误拒。修正 `server/internal/guardconfig/machine_identities.go:184` `machineIDPrincipalBindingFP`（HMAC-SHA256(identity_salt, "jwt-principal:"+录入值) 截前 16 字节 hex），装配后统一应用（`provider.go` loadAPIMachineIdentitySections 之后）；回滚快照携带换算后值、盐轮换即指纹重置（apiauthz 同纪律）。单测 `TestMachineIDPrincipalBindingFP` 黄金值+联调线值实证（autosave==python 复算）。
2. **重放 Lua 返回值形态跨轨不一致（已闭环，gateway 修正——批次 C 对批次 A 代码的联调修正，请编排者复核）**：批次 A `httpsig/replay.go` 原子脚本 `return ... and 1 or 0` 产标量 int64，共享装配通道 `counters.ValkeyClient.Eval` 契约只接受 array（`res.ToArray()`）→ 所有 PROTECT 请求 503 `replay_store_error: eval result not array`（联调首日全链实证）。修正为数组包裹返回（Redis 语义不变）；httpsig/machineid 单测复跑全绿+I03 双节点重放矩阵实证。教训：跨轨共享通道的 Lua 返回值形态应在线契约逐字冻结（S6 catalog_hash 分隔符同类教训再现）。
3. **RETIRED 窗口放行事件无 RETIRED 标注（登记，B2 遗留）**：轮换重叠窗口内旧键放行事件无 RETIRED 区分标注；窗口事实由管理面读回（keys[].status/retire_overlap_until）承载——事件侧直读属后续批网关侧增强。
4. **参照客户端 SF 库裁决（登记）**：`github.com/dunglas/httpsfv` 许可证核实 BSD-3-Clause（宽松红线通过）；为保参照实现零第三方依赖启用设计 §4 兜底条款自实现最小 SF 子集（`test/waf/mid-e2e/sf.go`）——允许的替代路径如实登记。
5. **未签名 401 语义定案（登记）**：proof_required 下未签名 → 401 `MID-SIGNATURE-MALFORMED`（网关门禁语义——准入策略判定非 UNKNOWN，机器身份无 401 专属 reason）；`MID-NA-UNSIGNED-001` 为 proof_required=false 的覆盖观测 NA 规则号——两断言在册互不冲突。
6. **CRS 共存纪律（联调新发现，参照客户端修正）**：PROTECT 应用下 ①Go 默认 UA `Go-http-client/1.1` 命中 CRS 913100 扫描器指纹（phase-1 CRITICAL 5 分 → 9000102 二次阻断评估 403）；②有体 POST 缺 Content-Type 命中 CRS 920340 CRITICAL（同路径 403）。客户端修正：默认 UA `jiuzhang-mid-e2e/1.0 (RFC9421 reference client)`（诚实标识不冒充浏览器）+有体默认 `Content-Type: application/x-www-form-urlencoded`（CRS 允许清单内，`-ct` 可覆盖）——非网关/规则缺陷；同时反向佐证 I05「机器身份不豁免 WAF」判定成立。
7. **同 rid 多机器身份事件断言修正（联调脚本）**：MID_BOT_EXEMPT（bot 步 4.5 豁免点）与 MID_VERIFIED（apiprotect 统一放行出口）同一 request_id 并存——断言辅助 ev_mid 加事件类型过滤择行。
8. **ACL 授权口径实证（登记）**：000126 种子 jwt_trust.read 三角色全授、manage 仅 SYSTEM_ADMIN/SECURITY_ADMIN——SYSTEM_ADMIN 读 200 为合规正向（初版联调断言 403 系测试预期错误已修正）；越权负向由未认证 401+AUDIT_ADMIN 探针写 403 承载；探针用户软删仍占用户名唯一约束 → 时间戳命名幂等。
9. **环境适配（stage5，S6 纪律承接+新增）**：publish_patient 长退避吸纳写操作自动发布与显式发布竞态 LOCK_BUSY；login_patient 会话缓存+新增配对守卫（cookie jar 新于缓存即弃——CSRF token 绑定会话，外部再登录致缓存失配 403 实证）；能力门清单 exec 覆写注入保属主；gateway-b 叠加 compose 端口 18083（18082 本机占用避让）+独立 logs/admin/data 卷+共享 stage5-gateway-config:/config（autosave 同源）；覆盖观测异步落盘 → 断言短轮询吸纳写入竞态。

## 已知限制与遗留

- 设计 §6 移交项原样：DPoP 路线试点、控制面批准的公钥同步通道、多签名标签、@target-uri 全形态、签名响应、机器身份↔对象所有权融合（apiauthz 联动评审）、弱指纹独立调研（§12.3 核查清单）、mTLS 客户端证书链验证。
- 撤销传播节点 ACK 拓扑可视化与 nonce 存储容量自动估算面板留移交；RETIRED 窗口事件标注（偏差 3）随后续批。
- 性能候选门槛（§1.9/D9）正式双报告（普通 amd64+兆芯）与 24h 稳定性留 §6 移交（与 ha-lab 演练矩阵合并编排）。本批 stage5 冒烟（共享 docker 序贯 n=60，access.log duration 读数）：签名+验证全链 p50≈9.3ms/p95≈14.8ms vs 无绑定基线 p50≈1.1ms/p95≈1.7ms——增量含 apiprotect 全管线与 Valkey 重放往返，非 machineid 单步读数（单步 p99 2ms 预算由 httpsig/machineid 单测锚定，正式报告待双架构）。
- 管理前端页面（身份列表/详情/导入/轮换/撤销/绑定管理）属批次 C web 轨另行交付，不在本出口范围。

## S7 关闭声明

NG-ID G1（机器身份 HTTP Message Signatures 首期）设计 D1~D14 全部落地，NG-T-I01~I05 经真实环境参照客户端（Go stdlib 三算法签名器，零第三方依赖，无 curl 冒充）对测全过，UNKNOWN 恒不阻断红线全程成立（登记册缺席/Valkey 中断/OBSERVE 全链放行+披露逐格实证），能力门三态 stage5 实证（无 mid/1 旧节点 fail-closed CAP_MISSING / mid/1 收载 / 全 OBSERVE 零需求滚动升级），撤销水位回滚 fail-closed 实证（ROLLBACK_PUBLISH_FAILED+MID_WATERMARK_REGRESSION+已撤销键不复活），回归零回退（40/40、13/13、server/gateway 测试全绿、reconcile 727 双向零差集、gofmt 干净），现场可复核（stage5 全栈 healthy，gateway-b 双节点+共享 Valkey、双应用六身份六绑定 PROTECT/OBSERVE 在册，证据目录在册）。**S7 阶段关闭**；DPoP 试点、控制面公钥同步通道、撤销 ACK 拓扑可视化、性能双报告与 24h 稳定性列入后续批次。
