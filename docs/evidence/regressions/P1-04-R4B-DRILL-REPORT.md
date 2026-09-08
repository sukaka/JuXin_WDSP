# P1-04 R4b 发布门禁与回退演练终验报告

- 演练时间：2026-09-08 15:00 ~ 2026-09-09 00:15（UTC+0 容器时钟）
- 环境：真实 stage5 栈（test/regression/p1/stage5/stack-up.sh，描述符 /tmp/p1reg-env.json；api/gateway/postgres/valkey/testorigin 五容器）
- 演练账号：p1reg_sec（SECURITY_ADMIN）；签名密钥 key_id=r4b-verifier-2026-09（ed25519，regsign genkey）
- 证据归档：docs/evidence/regressions/r4b-20260909T0015/（55 个文件：publish-task JSON、导入响应、gate_decisions/runs/审计 CSV 导出、psql 播种/撤销脚本）
- 策略终态：ENFORCE（policy version 4）；门禁评估全部发生在 publisher executePublish 内 saveVersion 后、loadGatewayConfig 前

## 相位结果总览

| 相位 | 内容 | 结果 |
|------|------|------|
| ①a | 证据匹配发布 | PASS：ALLOW，发布 SUCCESS（pub-a-success.json） |
| ①b | 缺失×2 / 过期×1 | PASS：全部 REGRESSION_GATE_REJECTED，版本 FAILED、is_current 不变（无半发布） |
| ①c | 证据存储 chmod 000 | PASS：REGRESSION_GATE_UNAVAILABLE 明确失败，不静默放行（已恢复 700） |
| ①d | 决策指纹核对 | PASS：31 行 gate_decisions 指纹逐行 == 对应版本 configuration_hash |
| ② | 误报回退全链 | PASS：误伤上线→FAIL 证据→ENFORCE 拒发→GuardOverride 快照重放恢复→复跑核对→失败候选未自动重发 |
| ②豁免 | 过期豁免；撤销/缺失/不完整不豁免 | PASS：4/4 逐项实证（exempt-a/b/c/d-*.json） |
| ③a | 网关停止期发布 | PASS：门禁 ALLOW 后仍 PREVIOUS_CONFIG_READ_FAILED/PUBLISH_FAILED，版本 FAILED、is_current 不变；GATEWAY_DOWN/CRITICAL 告警；恢复后重发 SUCCESS |
| ③b | 次要节点不可达 | PASS：主 SUCCESS + 节点 last_sync_result=FAILED（connection refused）+ CONFIG_PUBLISH_FAILED/HIGH 告警（pub-node-partial.json） |
| ④激活 | 模型 A/B 激活→发布 | PASS：指纹变化→无证据 REJECTED，策略不报 ACTIVE、网关指纹不变；绑定证据后发布 SUCCESS→策略 ACTIVE |
| ④回滚 | 撤销密钥后 runtime-policies/{id}/rollback | PASS（有发现）：502 不伪装成功、网关指纹不变、B 仍 ACTIVE；草稿滞留 DRAFT 与文案不符（见产品发现 5） |

BLOCKED 项：无。

## 回归 run 清单

| run_id | 结果 | 绑定指纹 | 服务端 run_ref | 用途 |
|--------|------|----------|----------------|------|
| 20260908T230148-798a3f | 48/48 | 82bdb142（后因端点发现漂移失效） | 4e9a…（baseline） | 首轮基线（如实记录失败） |
| 20260908T230741-85715c | 48/48 | 3afedd18 | 18c862b0-f322-47fe-8718-ae5c44327dae | ①主证据 |
| 20260908T231454-7f8355 | 40/48（8 FAIL） | 54fd689a（含误伤规则） | 6388e1c7-…（declared=FAIL, mandatory_failed=6） | ②误报证据 |
| 20260908T231841-65c327 | 47/48 | 未导入 | — | EDGE-001 flake 首现 |
| 20260908T233136-24ea21 | 48/48 | 未导入 | — | flake 复跑确认 |
| 20260908T234102-31b924 | 48/48 | b17ae616 | 7c49e438-0996-404a-8ed8-bddd3036bb3b | 响应基线学习后重绑 |
| 20260908T235005-75aa77 | 48/48 | 42f20bd4 | d9dd59c9-cfac-4c18-8805-e1d7a19327e4 | 误伤规则删除后重绑 |
| 20260908T235648-2a165a | 48/48 | 68713b54 | 8f2967e7-e45b-4911-9e81-9d2387a79cc7 | ④模型 A |
| 20260909T000032-7afcb2 | 47/48 | 未导入 | — | EDGE-001 flake 再现，只重跑不掩盖 |
| 20260909T000300-c54786 | 48/48 | 3143a439 | f3df1e91-3f41-452e-bfd3-89cbd0171b3f | ④模型 B |

## 关键演练路径实录

### ② 误报回退（含卡点教训）
1. OBSERVE 窗口下建误伤 L7 规则（uri prefix /search → block 403，规则 c90b28aa）并发布上线，探针实证 /search 403。
2. 误报态回归 8 FAIL（BEN-QUERY×2 + 连带 6），declared=FAIL 证据签名导入（verification=PASSED——FAIL 也是合法证据）。
3. 回 ENFORCE 后正常发布该配置被拒：「声明 FAIL 且 mandatory_failed=6」（pub-fp-rejected.json）。
4. GuardOverride 恢复：POST /api/v1/access-control/versions/d65a2f6c…/rollback → 快照重放发布 SUCCESS（restore_channel=true，决策 note「已知良好恢复通道发布」），探针 /search 200。
5. **卡点教训**：GuardOverride 只重放 guard 段，DB 里误伤规则本体仍在；下一次正常发布（绑定 b17ae616 证据）把规则带回生效配置，/search 再度 403。清除须：删除规则 → 候选指纹再变（42f20bd4，无证据被拒）→ config-versions 回滚到干净版（该通道不过门禁=既有口径）→ 干净态回归 48/48 → 绑定新指纹导入 → 发布 SUCCESS 恢复。
6. 失败候选未自动重发：恢复后 FP 指纹 54fd689a 新任务数=0。

### ④ 模型门禁
- 模型 A（schema {"q":"string"}）create→submit-review→confirm→activate：激活本身只改 DB 态+审计；发布时指纹变 68713b54 → ENFORCE REJECTED，策略滞留 VALIDATED（未报 ACTIVE），is_current 不变。绑定证据后发布 SUCCESS → 策略 ACTIVE + activated_at。
- 模型 B（加字段 extra）同路径：REJECTED（50886347）→ 回归绑定（期间学习态再漂移为 3143a439，以漂移后指纹绑定）→ SUCCESS → B ACTIVE v2、A 自动 ROLLED_BACK v1。
- 回滚：撤销密钥后 POST runtime-policies/{B}/rollback → PublishSync 门禁 BLOCK（回退目标指纹 e12c4853 无绑定）→ HTTP 502，网关 is_current 不变，B 仍 ACTIVE。

## 产品发现（全部真实栈实证）

1. **学习态指纹漂移 ×3**：回放流量触发 API 端点自动发现（8 条 api_endpoints，82bdb142→3afedd18）、响应基线学习（api_response_baselines + api_policy_version 进发布配置，→b17ae616）、④期间再漂移（50886347→3143a439）。结论：证据绑定必须在学习态稳定后做；实操判据=连发两次拒绝消息中指纹一致。建议产品侧考虑将学习态与发布指纹解耦或提供「学习冻结」窗口。
2. **WAF-BEN-EDGE-001 非确定命中 flake**：CUSTOM_PACK 规则 1001012（`^(?:pass|key|pwd|k|p|xor|token|secret)$` 本应必中 f11=k/f16=p 单字母值）在 10 轮回归中仅 2 轮 OBSERVE 命中；命中时审计 transaction.args={} 为空、phase 标记缺席（audit-edge.json），手动重发×2 均不复现。定性为引擎/语料 flake 待查，未掩盖（两次 FAIL 轮均未导入证据，只重跑）。
3. **GuardOverride 恢复不清 DB 本体**：见②卡点教训；恢复后必须删除误伤规则并重新绑定证据，否则正常发布会把误伤带回。
4. **config-versions 回滚不经过回归门禁**（publisher.Rollback 直接 loadGatewayConfig）：本次用作卡点清理通道有效，但与 access-control 版本回滚（过门禁、restore_channel 仅豁免过期）口径不一致，建议文档化或拉齐。
5. **runtime 策略回滚草稿孤儿化**：门禁拒绝路径不做 runtime 策略回写——rollback 返回 502 且文案称「回滚策略已标记失败」，实际草稿 v3（ac1b9cf0）滞留 DRAFT；下一次无关发布会将其静默带生效（runtime_policy.go:417 注释自述的风险场景真实发生）。激活路径被拒时策略滞留 VALIDATED 同理（但语义无害）。
6. 次要事实：EDGE 事件 client_ip 恒为 183.201.224.91（真实 IP 识别常量，另案）；security_regression 公钥登记无 settings API 白名单通道（部署管理员直写 DB）；发布 API 拒绝未知字段（reason 不被接受）。

## 改动文件（未 git add/commit）

- 新增 test/regression/p1/tools/pack_evidence.py（回归证据打包器：cases.jsonl→CASES_CHUNK 分块+manifest，case@PROFILE 组合键，词表映射 STANDARD→OPTIONAL）
- 新增 test/regression/p1/stage5/r4b-drill.sh（可复跑固化：P0/P1 主链自动化 + P2-P4 原语；bash -n 通过）
- 新增 docs/evidence/regressions/r4b-20260909T0015/（55 个演练证据文件）与本报告
- run.sh 等既有测试设施零改动；产品代码零改动；未新增迁移

## 测试命令与结果

- 回归执行：`bash test/performance/p0/run.sh regression --plan test/regression/p1/run-plan.stage5.example.json` ×10 轮（结果见 run 清单）
- 打包：`python3 test/regression/p1/tools/pack_evidence.py --run-dir <证据目录> --fingerprint cfgfpv1:<hash> --level FULL --out-dir <out>`
- 签名：`tools/regsign/regsign canonicalize + sign`；导入：POST /api/v1/security/regressions/imports（全部 verification=PASSED，幂等重导入 200）
- 脚本自检：`bash -n test/regression/p1/stage5/r4b-drill.sh` 通过；全角字符扫描干净
