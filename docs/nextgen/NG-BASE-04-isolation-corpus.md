# NG-BASE-04 隔离目标清单与语料计划（S0）

> 任务来源：docs/WDSP_API_WAF_NEXTGEN_RD_PLAN.md §15.2 NG-BASE-04；输入：NG-BASE-01/02/03。
> 状态：v0.1（2026-10-03）。纪律：所有语料为合成数据（RFC5737 网段、example.com 域名、虚构身份），危险样本只进隔离语料目录、不进生产运行包；任何有副作用用例只对隔离目标执行。

## 1. 隔离目标清单

| 目标 ID | 形态 | 用途 | 现状 | 缺口/动作 |
|---|---|---|---|---|
| ENV-S5 | stage5 本地栈（Mac，8 容器） | S1 大部分功能回归；协议解析/覆盖/决策链路 | 运行中（api 18081 / gw 18080；shop.example.com 引擎 On、waf-s5.local Off） | 无需新建；用例注意当前应用模式状态 |
| ENV-REC | 记录型测试源站 | HTTP 链一致性：登记规范化方法/路径/头结构/请求计数/体摘要 | stage5-testorigin 具备基础 echo 能力 | S1 NG-HTTP-01 扩展记录维度（头结构/计数/体摘要），不落真实凭据 |
| ENV-2N | 双网关节点对（stage5 扩展或 ha-lab） | 授权水位/CAS/重放/租约/分区用例 | deployment/ha-lab/ 存在参考 | S3/S4 启动前按任务书冻结双节点形态与 Valkey 共享/分区切换方法 |
| ENV-GQL | GraphQL 测试服务 | 正常深查询/浅而贵查询/fragment 循环/变量放大 | 无 | S2 任务书选型（轻量可固定版本；可自研最小服务） |
| ENV-GRPC | gRPC 测试服务（含压缩、repeated/map/oneof、流式） | G1/G2 边界与协议化执行 | 无 | S5 任务书定实现（Go 自研首选，描述符离线导入链路复用） |
| ENV-MCP | MCP 测试服务（HTTP 传输、工具目录可变、长流） | 工具 ACL/参数/结果/未知扩展 | 无 | S6 任务书定；必须支持「同名工具换 Schema」开关 |
| ENV-OE | openEuler 24.03 兆芯机（192.168.3.201） | 真实环境验收（S8） | 在线（现跑 1.2.1 docker 部署） | K5 签核前不得作为 NG 验收环境；当前仅作交付试验 |
| ENV-OE2 | openEuler 双节点资源 | S3/S4/S8 多节点验收 | 不存在 | K5 待批 |

出口纪律：全部隔离目标出网仅允许清单内地址；回放仅使用合成语料；禁止对生产系统「只读 GET 回放」（GET 也可能有副作用，RD_PLAN §5.3）。

## 2. 语料注册表（schema）

每条语料登记：`id / 方向 / 类别(normal|abnormal|unknown) / 内容或生成器 / 摘要(sha256) / 真值标签(期望状态码、期望 Finding、源站是否应收到) / 关联 NG-T 用例 / 限制说明`。语料目录：`test/nextgen/corpus/<direction>/`，注册表 `registry.json` 随目录版本化；摘要变更必须同步更新真值标签评审记录。

## 3. 初始语料清单（S0 冻结 24 条种子；扩编在 S1 任务书）

### 3.1 共用与 HTTP 链（NG-HTTP）

| id | 类别 | 摘要描述 | 真值标签 | 关联 |
|---|---|---|---|---|
| HC-N01 | normal | 常规 GET/POST（表单/JSON，多重普通头） | 网关与源站解释一致、计数 1 | NG-T-H01 |
| HC-A01 | abnormal | 重复 Content-Length 与 Transfer-Encoding 冲突组合（隔离集） | 无走私、不污染同连接后继请求 | NG-T-H01 |
| HC-A02 | abnormal | HTTP/2→HTTP/1.1 转换 + 路径重写 + 绝对形式请求 | 安全判断与源站目标一致 | NG-T-H02 |
| HC-A03 | abnormal | Host 与 :authority 不一致、伪造转发头覆盖目标 | 权限/身份绑定目标不被不可信来源覆盖 | NG-T-H03 |
| HC-U01 | unknown | 合法但罕见方法/超大正常头集合 | 如实记录覆盖状态，不误判攻击 | NG-T-H01 |

### 3.2 GraphQL（NG-GQL）

| id | 类别 | 摘要描述 | 真值标签 | 关联 |
|---|---|---|---|---|
| GQ-N01 | normal | 批准预算内的正常深查询（深度≈8）与合法 fragment/变量 | 通过且不误拒 | NG-T-G02/G03 |
| GQ-A01 | abnormal | fragment 自引用循环 + alias 膨胀（>100） | 有界终止、成本如实 | NG-T-G02 |
| GQ-A02 | abnormal | 浅而贵查询（单字段 × 大列表上界）与 JSON 数组 batch=50 | 识别为昂贵；按配置处置 | NG-T-G02/G04 |
| GQ-A03 | abnormal | 单文档多 operation 未指定 operationName / 指定不存在 operation | 分别按协议错误处理，不全文执行 | NG-T-G01 |
| GQ-U01 | unknown | 含未知指令/自定义标量的合法文档 | 保守上界或标未知，不误判 | NG-T-G03 |

### 3.3 gRPC（NG-GRPC）

| id | 类别 | 摘要描述 | 真值标签 | 关联 |
|---|---|---|---|---|
| GR-N01 | normal | unary 正常消息（含 repeated/map/oneof）+ 批准压缩算法 | 正确重组与字段判定 | NG-T-R03 |
| GR-A01 | abnormal | 分片帧/错误长度/空消息/未知 encoding | 有界内存、不错位、正确错误语义 | NG-T-R01/R02 |
| GR-A02 | abnormal | 压缩炸弹（高倍率小输入） | 解压预算终止，LIMIT_EXCEEDED | NG-T-R02 |
| GR-U01 | unknown | 缺描述符的合法服务调用 | 不声称完整深检（覆盖状态如实） | NG-T-R03 |

### 3.4 授权与流程（NG-AZ/FLOW）

| id | 类别 | 摘要描述 | 真值标签 | 关联 |
|---|---|---|---|---|
| AZ-N01 | normal | 有效本人 OWNER 访问（可信主体+有效关系） | 通过 | NG-T-A01 |
| AZ-A01 | abnormal | 有效他人 OWNER 排他对象（BOLA）、越角色动作（BFLA） | 按模式观察或阻断；源站/工具未执行 | NG-T-A01/A08 |
| AZ-A02 | abnormal | 撤销后命中旧快照、乱序/重复来源事件、同名对象跨租户 | 水位不下降；缺口可见；租户隔离 | NG-T-A03/A05/A06 |
| AZ-U01 | unknown | 历史推断所有者、共享对象、关系冲突 | UNKNOWN，不产生实断 | NG-T-A02/A03/A04 |
| FL-N01 | normal | 正常三步流程 + 合法并行步骤 | 成功响应后才确认；并行不误拒 | NG-T-F01 |
| FL-A01 | abnormal | 双节点同步执行同一步、同幂等键异参、迟到旧 fencing | 原子预留；异参冲突；旧 token 不覆盖 | NG-T-F02/F03/F05 |
| FL-U01 | unknown | 超时但源站已成功、取消后新实例、Valkey 故障 | INDETERMINATE 对账；不静默本地降级 | NG-T-F04/F06/F07 |

### 3.5 MCP 与机器身份（NG-MCP/ID）

| id | 类别 | 摘要描述 | 真值标签 | 关联 |
|---|---|---|---|---|
| MC-A01 | abnormal | 未授权 tools/call、Token 受众错误、伪造角色文本 | 未到达工具；认证/授权错误分开；文本不提权 | NG-T-M01/M06 |
| MC-A02 | abnormal | 同名工具换 Schema/摘要、嵌套参数/重复键/超长文本 | 旧批准不继承；按解析契约检查（非截断前缀） | NG-T-M02/M03 |
| MC-U01 | unknown | 未知扩展方法、stdio 形态、长流输出 | 明确未覆盖标识，不冒充已保护 | NG-T-M05 |
| ID-N01 | normal | 有效 DPoP/签名请求（方法/URI 绑定正确） | 验证通过 | NG-T-I01 |
| ID-A01 | abnormal | 绑定不符、两节点重放、撤销后复用 | 拒绝；原子重放拒绝；撤销不复活 | NG-T-I02/I03/I04 |

## 4. run-plan（执行计划骨架）

| 顺序 | 范围 | 环境 | 完成判据 |
|---|---|---|---|
| R1 | 变更包单元测试 + 规则/契约静态校验（ID 查重、caddy validate、OpenAPI 对账） | Mac | 全绿 |
| R2 | 隔离功能回归（语料 §3 按方向执行） | ENV-S5 + 对应 ENV-* | 真值标签全对；源站计数证据落盘 |
| R3 | 双节点/故障/回滚用例 | ENV-2N / ENV-OE2 | 水位/CAS/租约断言全过 |
| R4 | 性能分档（off/覆盖开/单模块开） | ENV-S5 或专用性能环境（固定硬件） | 满足 RD_PLAN §14.2 候选门槛；报告含噪声与置信区间 |
| R5 | openEuler/兆芯真实验收 | ENV-OE(+OE2) | 单独立项登记；Mac 结果不折算 |

每次运行保留：源码/镜像摘要、策略/语料摘要、环境标识、时间、逐例结果、候选/实际动作、源站计数、性能结果、已知限制（RD_PLAN §16.6 证据格式）。状态枚举沿用 `PASS/FAIL/SKIP/BLOCKED/NOT_RUN/NOT_APPLICABLE`，强制项 BLOCKED/NOT_RUN 即对应验收未通过。

## 5. S0 收口与 S1 入口检查

S0 四件交付齐备（BASE-01 基线、02 契约、03 威胁模型、04 隔离语料计划）。进入 S1（NG-COV-01～04、NG-HTTP-01～02）的入口条件：

- [ ] K5/K6 签核（测试资源 + 契约与威胁模型冻结稿）
- [ ] 全量回归补跑并登记（基线 §3 未跑项：server/gateway 全包 go test、web Vitest、go-ftw、性能基线）
- [ ] stage5 三个真实 IP 相关失败完成定责（修复或标注环境性原因）
- [ ] S1 任务书按本计划细化到用例级（每个 NG-T 映射具体语料 id 与断言）
