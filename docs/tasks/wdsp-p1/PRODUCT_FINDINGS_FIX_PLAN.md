# P1 产品发现修复计划（13 条）

日期：2026-09-09。来源：P1 R2/R4b 真实栈演练发现（证据：docs/evidence/regressions/P1-04-R2-FINAL-REPORT.md「产品发现」节、P1-04-R4B-DRILL-REPORT.md「产品发现」节、docs/tasks/wdsp-p1/WORKLOG.md S3/S6 记录）。外加 B3 期间记录的 1 条关联风险（counters.Eval），合计 14 条登记，其中 2 条已在 P1 期间修复或定性为非缺陷，本计划覆盖剩余 12 条。

## 0. 总览与批次

| 批次 | 内容 | 条目 | 理由 |
|---|---|---|---|
| F1 高危状态一致性（立即） | 状态说谎/进程崩溃/规则不命中 | #1 回滚草稿孤儿化、#2 apigeo nil panic、#3 escapeSecLangArg 转义 | 直接影响安全语义正确性，修法小且独立 |
| F2 门禁与恢复通道口径拉齐 | 回滚绕门禁、恢复通道语义、公钥登记通道 | #4、#5、#6 | R3/R4 已建门禁体系，这些是收口 |
| F3 调查与设计决策 | flake 调查、学习态指纹、XML 体、关联键、EDGE IP | #7~#11 | 需先调查或设计评审，不直接动代码 |
| F4 文档化（随 F1/F2 顺带） | CRS 相位语义、OBSERVE offer 口径 | #12、#13 | 非代码缺陷，写清即可 |

编号按下表，全计划通用。

## 1. 条目明细

### F1 批次：高危状态一致性

**#1 runtime 策略回滚草稿孤儿化（最高优先级）**
- 现象：ENFORCE 门禁拒绝回滚发布时，`RollbackRuntimePolicy` 返回 502 且文案称「回滚策略已标记失败」，但门禁拒绝路径不调用 `MarkRuntimePolicyFailed`，草稿滞留 DRAFT；下一次无关发布将其静默带生效。
- 位置：`server/internal/apimodels/runtime_policy_handler.go:166`（发布失败路径已正确调用）vs 门禁拒绝路径（`gatewayconfig` 门禁返回 REGRESSION_GATE_REJECTED/UNAVAILABLE 时 handler 直接 502，未回写）；兜底函数已存在：`server/internal/apimodels/runtime_policy.go` `MarkRuntimePolicyFailed`（仅允许 DRAFT/VALIDATED/PUBLISHED 迁入，0 行命中幂等）。
- 修法：门禁拒绝（REJECTED 与 UNAVAILABLE 两类）在回滚场景同样调用 `MarkRuntimePolicyFailed`，文案与实际状态一致；激活路径被拒时策略滞留 VALIDATED（语义无害）但应在响应中如实说明「策略未激活、未发布」，不称已失败。检查 `ActivateModel` 同类路径。
- 验收：复刻 R4b 相位④场景——ENFORCE 无证据 rollback → 502 + 策略落 FAILED（列表可见终态）→ 再做一次无关发布 → 实证该策略不被带生效；单测覆盖门禁拒绝×回滚/激活两路径；审计行记录。
- 风险：低（复用既有幂等函数）。工作量：约 0.5 天含测试。

**#2 apigeo Sweeper nil panic**
- 现象：GeoIP mmdb 文件缺失时，apigeo 周期 sweeper 每周期 panic，可崩 API 进程（调用链 mmdb.go LookupCountry ← sweep.go:160 ← main.go:306）。本机 stage5 日志实测有 `geoip unavailable` 告警路径。
- 位置：`server/internal/apigeo/mmdb.go`（mmdb 未加载时 Lookup* 接收者为 nil 或内部 meta 为零值）+ `sweep.go`（调用前无就绪检查）。
- 修法：mmdb 未就绪时 Lookup 返回明确错误（不 panic）；Sweeper 周期任务加 nil/就绪门控，未就绪降级为「geo 字段缺失」并 Warn 一次（防抖），不阻断其他 sweep 逻辑；main.go 装配处保持 fail-open 但有状态可见（health 接口体现 geo 降级）。
- 验收：单测——无 mmdb 时 SweepOnce 100 次无 panic、错误如实返回；stage 环境删除 mmdb 后 API 存活且 health 显示降级。
- 风险：低。工作量：约 0.5 天。

**#3 escapeSecLangArg 反斜杠转义 bug**
- 现象：`server/internal/customrules/customrules.go:203` 把 `\` 转义为 `\\`，但 Coraza SecLang 解析不把 `\\` 解回 `\`，导致一切含反斜杠的正则（`\s` `\w` `\{` `\.`）写入自定义规则后**全部不命中**——用户以为有防护实际没有。
- 修法：先查 Coraza v3.7 SecLang 双引号操作值的转义词表（实测为准）：若仅需转义 `"` 则去掉反斜杠转义；若 `\\` 确为 SecLang 层义而在正则层失配，改用十六进制/字符类重写或在文档约束写法。以真实网关命中测试为判定，不以猜测为准。
- 验收：含 `\s`/`\w`/`\.` 的自定义规则在真实 stage5 栈命中（回归语料已有绊线用例可复用）；既有无反斜杠规则行为不变（R2 的 48 例基线复跑）；R2 期间改写的 5 条规避规则可还原验证。
- 风险：中（影响自定义规则生效语义，需前后对比）。工作量：约 1 天。

### F2 批次：门禁与恢复通道口径拉齐

**#4 config-versions 回滚不经回归门禁**
- 现象：`publisher.Rollback`（`server/internal/gatewayconfig/publisher.go:860`）直接 loadGatewayConfig，不经 R3 的回归门禁检查点；而 access-control 版本回滚（:932）过门禁。两条回滚路径口径不一致。
- 修法：ENFORCE 下 `Rollback` 同样过门禁，恢复通道豁免口径与 §7.3 一致（仅豁免超有效期，不豁免撤销/缺失/不完整）；OBSERVE 记录不阻断；OFF 不检查。UI 在 config-versions 回滚入口补门禁状态提示（复用 R4a 的 RegressionGateNotice）。
- 验收：ENFORCE + 无证据时 config-versions 回滚被拒；有有效证据或走 §7.3 恢复通道时放行；两条回滚路径行为对比测试。
- 风险：中（改变既有回滚路径行为，默认 OFF 不影响存量）。工作量：约 1 天。

**#5 GuardOverride 恢复不清 DB 规则本体**
- 现象：GuardOverride 快照重放恢复线上后，误伤规则本体仍在数据库；下一次正常发布会把误伤带回。R4b 实操必须「删规则+重绑证据」才真正干净。
- 修法（二选一，需产品决策）：a) 恢复通道执行后给出明确的「残留清单」警告与一键清理入口（UI+API 返回残留项）；b) 恢复通道支持「恢复并禁用差异项」选项（默认不启用）。建议先做 a)（可见性），b) 另行评估。
- 验收：演练序列复跑：误伤上线→恢复→残留清单可见→正常发布前清理→发布不带回误伤。
- 风险：低（先只做可见性）。工作量：约 1 天（含 web 提示）。

**#6 security_regression 公钥登记无管理 API**
- 现象：受信验签公钥目前只能直写 DB（system_settings），部署管理员无白名单通道；撤销同理。
- 修法：新增最小管理 API（GET/PUT `security_regression` 受信公钥列表，权限挂在 `security_regression.policy` 或新权限码；撤销保留历史报告可读但不再作新发布凭据——R3 store 层语义已支持，只缺管理面通道）；审计记录 key_id 与指纹（不记录私钥，私钥本就不入该系统）。
- 验收：API 层权限矩阵+审计测试；R4b 演练脚本改用 API 登记重跑通过。
- 风险：低。工作量：约 0.5~1 天。

### F3 批次：调查与设计决策（先评审后动代码）

**#7 CUSTOM_PACK 1001012 非确定命中 flake**
- 现象：规则 `^(?:pass|key|pwd|k|p|xor|token|secret)$` 应必中单字母参数值，10 轮回归仅 2 轮 OBSERVE 命中；命中时审计 transaction.args 为空、phase 标记缺席；手动重发不复现。
- 动作：调查项——先写确定性复现测试（同请求连发 100 次统计命中率+开 Coraza debug 日志），定位是引擎 ARGS 装配竞态、审计采样还是规则相位问题；确认根因后再定修法。若为上游 Coraza 缺陷，按合规要求回报上游或本地补丁评审。
- 验收：复现率从「偶发」变为「确定命中或确定不修并文档化」。
- 工作量：调查 1~2 天。

**#8 学习态指纹漂移**
- 现象：回放流量触发 API 端点自动发现与响应基线学习，学习结果进发布配置导致候选指纹漂移×3；证据绑定须等学习态稳定（实操判据=连发两次拒绝指纹一致）。
- 动作：设计评审——「学习冻结」窗口（发布前冻结学习写入）或学习数据与发布指纹解耦（学习结果不进指纹哈希、单独版本化）。这是 R3 门禁可用性的重要配套，建议立项。
- 工作量：设计 1 天 + 实现 2~3 天（取决方案）。

**#9 Coraza v3.7 无 XML 体处理器（XXE 缺口）**
- 现象：原始 application/xml 请求体不解析，XXE 用例双 profile 无检出直达源站（语料已转 UNKNOWN 绊线）。
- 动作：产品决策——接受缺口并文档化（推荐短期）vs 自研/引入 XML body processor（需评估 Coraza 插件点与合规）。语料绊线保留，启用 XML 解析时会立即翻红提示。
- 工作量：决策+文档 0.5 天；实现另估。

**#10 事件关联键（X-Request-Id 被覆盖）**
- 现象：网关配置把客户端注入的 X-Request-Id 覆盖为 `{http.request.uuid}`，外部关联键进不了事件管道；唯一可信关联是响应头 `X-Jiuzhang-Request-ID`。
- 动作：设计决策——是否支持「可信客户端关联键」透传模式（默认保持覆盖防伪，配置可选）。先文档化现状（安全设计文档），改进另立。
- 工作量：文档 0.5 天；实现另估。

**#11 EDGE 事件 client_ip 恒为网关出口常量**
- 现象：EDGE 类事件 client_ip 恒为 183.201.224.91（真实 IP 识别常量路径）。需核对是否为脱敏/占位口径，若是 bug 则修。
- 工作量：调查 0.5 天。

### F4 批次：文档化（非代码缺陷）

**#12 CRS 949110 相位中断抢占语义**：PROTECT 档 CRS 达阈 deny 后同相位自定义规则不执行（949110 在 phase2 的阻断优先级高于自定义规则排布预期）；OBSERVE 无此现象。写入自定义规则编排文档与规则编写指南，明确「自定义检测规则不能依赖与 CRS 阻断同相位执行」。

**#13 OBSERVE Bot offer 事件口径**：BOT_CHALLENGE_OFFERED/action=OBSERVE 是流程记录而非 finding，不入检出分母——写入事件字典文档（docs/ACCESS_CONTROL_EVENT_DESIGN.md 增补）。

### 已关闭（不需修复）

- R2-6 CRS 族归属映射：R2 期间已修。
- R2-7 同 #13（文档化归入 #13）。
- B3 关联风险 `counters.Eval` 数字串→int64：botchallenge 本体已修（luaFieldString）；**残留排查项**：全仓 grep Lua HGETALL 数字字段消费者（temporaryblock/ratelimit/riskengine 等），同类隐患逐个确认——建议并入 F1 批次顺带执行（grep+单测，0.5 天）。

## 2. 执行顺序与依赖

1. **F1**（#1→#2→#3+counters 排查）：互不依赖，可并行两个代理（#1 在 apimodels、#2 在 apigeo、#3 在 customrules+真实栈验证）。
2. **F2**（#4 依赖 R3 门禁已落地——已满足；#6 独立；#5 需产品决策 a/b）。
3. **F3** 各为调查/设计项，产出 ADR 或文档后再排实现。
4. **F4** 文档随 F1/F2 顺带提交。

每批次的回归纪律：修复后必须复跑对应证据链（#1/#4/#5 → r4b-drill.sh；#3 → test/regression/p1 stage5 回放；#2 → apigeo 单测+stage 环境）；门禁 ENFORCE 下修复自身的发布会需要新回归证据（自举顺序：先 OFF/窗口期修复，证据齐后再开 ENFORCE）。

## 3. 工作量汇总

| 批次 | 估计 |
|---|---|
| F1（#1/#2/#3+counters 排查） | 约 2.5 天 |
| F2（#4/#5a/#6） | 约 3 天 |
| F3 调查与设计（#7~#11） | 约 4~5 天（实现另估） |
| F4 文档 | 约 0.5 天 |
| 合计（不含 F3 实现） | 约 10~11 天 |

## 4. 验收总口径

- 每条修复附带：根因说明、最小改动 diff、单测/接口测试、真实栈复演证据（run_id 归档 docs/evidence/）。
- 不得为通过测试删除既有校验；修复不得改变默认关闭口径。
- 全部完成后更新 docs/tasks/wdsp-p1/DELIVERY_SUMMARY.md §5（产品发现节标记已修/版本）。
