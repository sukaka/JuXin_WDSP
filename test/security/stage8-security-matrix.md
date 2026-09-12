# 阶段8 §61 安全测试逐项对账表

任务书 `docs/tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md` 六十一章共 36 项安全测试。
本表逐项对账到可执行断言：

- **矩阵脚本** `test/security/stage8-security-matrix.sh`（SEC-01…SEC-36，编号顺序=任务书条目顺序）；
- **原脚本** `test/security/stage8-security-tests.sh`（a–f 组，保留不变，部分项双覆盖）；
- 运行前提：stage5 编排 + wdsp 覆盖（`make stage8-up` 或 compose 命令见脚本头注释）。

状态口径：**已覆盖**＝脚本含实跑断言；**环境受限**＝脚本内 SKIP 项（不计失败，原因见注）；**双覆盖**＝两个脚本各自断言。

| # | §61 条目 | 断言编号 | 状态 | 验证要点 |
|---|----------|----------|------|----------|
| 1 | 路径归一化绕过 | SEC-01（2 断言） | 已覆盖 | `--path-as-is` 穿越序列非 5xx、响应无 /etc/passwd 内容 |
| 2 | 双重编码 | SEC-02 | 已覆盖 | `%25xx` 双重编码载荷非 5xx、无内部信息泄露 |
| 3 | 参数污染 | SEC-03（2 断言） | 已覆盖 | `?id=1&id=2` 非 5xx + 事件含 `parser.duplicate_query_param` |
| 4 | 重复JSON Key | SEC-04（2 断言） | 已覆盖 | 重复键非 5xx + 事件含 `parser.duplicate_json_key` |
| 5 | JSON深度攻击 | SEC-05 | 已覆盖 | 200 层嵌套（上限 32）截断而非 5xx |
| 6 | XML实体攻击 | SEC-06；原脚本 a） | 双覆盖 | DOCTYPE/外部实体不展开（无 passwd 内容）、非 000/5xx |
| 7 | 超大数组 | SEC-07 | 已覆盖 | 30 万元素数组（>1MiB）截断而非 5xx |
| 8 | 超大请求 | SEC-08；原脚本 b） | 双覆盖 | >1MiB body 截断采样而非 5xx |
| 9 | 超大响应 | SEC-09 | 环境受限 | testorigin 无超大响应端点（/echo 应答恒为小报文），需专用 fixture 源站，脚本内 SKIP |
| 10 | Multipart边界攻击 | SEC-10 | 已覆盖 | 声明边界与内容边界不匹配，流式解析不崩、非 5xx |
| 11 | 压缩炸弹 | SEC-11（2 断言） | 已覆盖 | 64MB 零字节 gzip 非 5xx + 后续 /health=200 证明引擎存活 |
| 12 | Schema绕过 | SEC-12（3 断言） | 已覆盖 | CT 混淆（JSON 伪装 text/plain）非 5xx；类型偏离/未定义参数分别产生 `schema.type_mismatch` / `schema.undefined_field` 明细 |
| 13 | 学习污染 | SEC-13 | 已覆盖 | 全部偏离/阻断/污染样本后正式模型 schema 与 content_hash 逐字节不变 |
| 14 | 模型投毒 | SEC-14（2 断言） | 已覆盖 | 重复确认已冻结模型 409；含 backdoor 字段候选未经确认不可激活 409 |
| 15 | 版本越权 | SEC-15（2 断言） | 已覆盖 | AUDIT_ADMIN（无 api_model.read）读模型 403，SECURITY_ADMIN 对照 200 |
| 16 | 模型确认越权 | SEC-16；原脚本 d）同型 | 已覆盖 | AUDIT_ADMIN confirm 403 |
| 17 | 跨应用读取模型 | SEC-17（2 断言） | 已覆盖 | 无会话 401；不存在 UUID 404 且响应无内部细节（单租户 RBAC 下以不可枚举+权限点为准，多租户隔离无独立 fixture） |
| 18 | 跨用户审计读取 | SEC-18（2 断言） | 已覆盖 | SECURITY_ADMIN 无 audits.read → 403；AUDIT_ADMIN 对照 200 |
| 19 | Token泄露 | SEC-19（3 断言） | 已覆盖 | 登录响应无口令字段、会话 Cookie 带 HttpOnly、用户列表无口令散列 |
| 20 | 敏感数据泄露 | SEC-20（3 断言）；原脚本 c） | 双覆盖 | 金丝雀明文（唯一 id_card 值）不出现在 runtime events 与 sensitive-fields 应答；敏感识别命中有事件佐证 |
| 21 | SQL注入 | SEC-21；原脚本 e） | 双覆盖 | keyword 载荷 200 无泄露（参数化 ILIKE） |
| 22 | XSS | SEC-22；原脚本 e） | 双覆盖 | `<script>` 载荷 200 且应答为 JSON 不反射 |
| 23 | SSRF特征 | SEC-23 | 已覆盖 | 云元数据 URL 作参数仅当数据，非 5xx、响应无元数据内容 |
| 24 | NoSQL注入 | SEC-24；原脚本 e） | 双覆盖 | `{"$gt":""}` 载荷 200 无泄露 |
| 25 | Mass Assignment | SEC-25（3 断言） | 已覆盖 | 模型创建带 `status`/`confirmed_at`、策略更新带未知字段、用户创建带 `is_superadmin` 均 400（DisallowUnknownFields） |
| 26 | BOLA辅助检测 | SEC-26 | 已覆盖 | 无凭据连续数字对象 ID 访问产生 `resource.unauthenticated_object_access` 观测明细 |
| 27 | BFLA辅助检测 | SEC-27 | 已覆盖（条件） | 创建+确认角色基线后匿名访问产生 `authz.bfla_anonymous`；基线建立失败时 SKIP 并注明 |
| 28 | 业务流程绕过 | SEC-28（2 断言） | 已覆盖 | FORMAL 不可回退评审 409；REJECTED 候选不可再确认 409（候选直接激活 409 见 SEC-14） |
| 29 | 图谱查询注入 | SEC-29（2 断言） | 已覆盖 | graph/topology 过滤参数非法值/注入载荷明确 400 无泄露 |
| 30 | OpenAPI恶意文件 | SEC-30（3 断言） | 已覆盖 | XML/DOCTYPE 载荷 400；外部 `$ref` 400；>16MiB 文档 400 |
| 31 | SSRF式规范导入 | SEC-31 | 已覆盖 | import-url 对回环/链路本地/localhost/file:// 四目标全 400 |
| 32 | 任意文件读取 | SEC-32（2 断言） | 已覆盖 | 网关与管理面路径穿越均读不到 /etc/passwd |
| 33 | 审计删除 | SEC-33（2 断言） | 已覆盖 | DELETE /audits/{id} 与 POST /audits/delete 均 404/405（无删除路由） |
| 34 | 绕过统一决策 | SEC-34（3 断言） | 已覆盖 | PROTECT 下两类 BLOCK 命中都恰好 403；恢复 OBSERVE 后同请求放行——处置只经管线统一出口 |
| 35 | 检测器直接返回响应 | SEC-35 | 已覆盖 | OBSERVE 下 BLOCK 类命中仍带 `X-Wdsp-Origin-Mark`（到达源站），检测器不直接产出响应 |
| 36 | AI自动确认模型 | SEC-36 | 已覆盖 | 学习/发现流量后无任何 FORMAL 版本（确认必须人工带权限发起）；执行顺序因依赖前移至人工确认之前 |

## 备注

1. **SEC-09（超大响应）** 为唯一环境受限项：现有 testorigin 无大响应 fixture，脚本内记 SKIP，不阻塞退出码。
2. **SEC-27（BFLA）** 依赖 `api_authorization.manage` 权限与基线发布通道；任一环节不满足时 SKIP 并打印原因。
3. 与学习/模型相关的断言（SEC-13/14/26/27/28/36）依赖采集器 2s 轮询，脚本内已按既有脚本惯例 `sleep 6`。
4. 网关攻击面断言统一「非 000 且非 5xx」口径（000=连接重置，即引擎崩溃信号），与 `stage8-security-tests.sh` 一致。
5. CSRF 防线由 `stage8-security-tests.sh` f）组覆盖（写接口缺 X-CSRF-Token → 403），矩阵不重复。
