# API 准入防护设计（已确认 API 白名单放行）

版本：v1.0（方案评审稿）
状态：待评审
关联文档：API_RUNTIME_COMPILER.md、API_UNIFIED_FINDING_DECISION.md、tasks/STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md（§12 PROTECTING 态原始意图）

## 1. 背景与目标

### 1.1 需求

API 动态防护目前对「未登记/未确认端点」只观测不拦截。客户希望的运营闭环是：

1. 应用上线初开**检测模式**：系统学习流量、发现端点、积累模型；
2. 经过一个学习周期，大部分 API 已识别，管理员**确认**这批 API；
3. 切换**防护模式**：从此只有已确认的 API 允许访问，未确认的一律拒绝；
4. 之后出现的新 API（新上线、低频接口被首次调用）**默认被拒绝**，必须经管理员确认后才放行。

即「端点准入级正向安全模型」（默认拒绝 + 白名单放行），与现有「模型级正向约束（schema/参数偏离）」互补。

### 1.2 目标

- 应用级 API 准入模式：OFF / OBSERVE（检测）/ PROTECT（防护），默认 OFF；
- PROTECT 下：未确认端点请求返回 403（统一响应，不区分「从未发现」与「已发现未确认」，不泄露资产情报）；
- OBSERVE 下：未确认端点仅记录观测（finding + 事件），不拦截；
- 确认工作流复用现有资产确认（CONFIRMED），确认经发布后生效；
- 切换 PROTECT 前给出覆盖率与业务影响面评估，防止误伤；
- 被拦截端点有专门列表，支持一键确认放行。

### 1.3 非目标

- 不改变 WAF（Coraza/CRS）检测/防护语义；
- 不改变 API 模式全局开关 `api_protection.mode`（schema/参数偏离防护）的既有语义；
- 不做静态资源/页面流量的准入（准入仅作用于判定为 API 的请求，见 §4.3）；
- 不引入网关轮询通道（沿用 server 推送式整站发布）。

## 2. 现状基线（调研结论，均可在代码中复核）

| 能力 | 现状 | 位置 |
|---|---|---|
| 资产生命周期 | DISCOVERED/CONFIRMED/IGNORED/DEPRECATED/ZOMBIE，确认接口与权限点 `api_asset.confirm` 已上线 | `server/internal/apiassets/store.go:579`、`handler.go:128` |
| 学习状态机 | 端点 learning_status 四态 + 模型 CANDIDATE→…→FORMAL，确认/冻结必须人工 | `learningjobs/janitor.go`、`apimodels/store.go:183` |
| 网关已知端点基线 | `APIKnownEndpoints`（endpoint_key→asset_status 全量映射）随发布下发 | `guardconfig/provider.go:472`、`apiprotect.go:695` |
| 未知端点观测 | `lifecycle.new_endpoint` Finding（OBSERVE/LOW），server 侧映射 SHADOW finding | `detectors/lifecycle.go:14`、`apiruntime/findings.go:88` |
| 决策引擎 | BLOCK 定案资格：detector ∈ {waf, api_schema, access_control} 或 cat==BLOCK 或 score≥50 | `decision/engine.go:112` |
| 下发通道 | server 组包 → Caddy Admin API `/load` 整站热加载，多节点扇出，版本校验+回滚 | `gatewayconfig/publisher.go` |
| 任务书原始意图 | §12 学习词表含 CONFIRMED/PROTECTING 态，未实现 | `STAGE_8_UNIFIED_WEB_API_DYNAMIC_PROTECTION.md:648` |

**关键差距**：① 网关无「未确认→拦截」路径；② 确认动作与发布无联动；③ 切 PROTECT 无前置校验；④ `endpoint_key` 自迁移 000137 起非全局唯一（作用域 = application+domain+binding+host），下发口径需按应用分组。

## 3. 概念与状态机

### 3.1 API 准入模式（应用级，新维度）

字段：`applications.api_admission_mode`，词表 **OFF / OBSERVE / PROTECT**，默认 **OFF**。

| 模式 | 语义 | 适用阶段 |
|---|---|---|
| OFF | 不做准入判定（现状行为） | 未启用该能力的应用 |
| OBSERVE | 检测/学习期：未确认端点照常放行，仅记录 `admission.unconfirmed_endpoint` 观测 finding；覆盖率面板持续积累 | 上线初、学习周期内 |
| PROTECT | 防护期：未确认端点 403 拒绝并记录；已确认端点正常进入后续管线 | 确认覆盖达标后 |

与既有全局 `api_protection.mode`（模型偏离防护）**正交**：准入管「这个 API 允不允许存在」，模型防护管「这个请求符不符合已学模型」。两者可独立组合，推荐运营路径：准入 OBSERVE + 模型 OBSERVE → 学习确认 → 准入 PROTECT → 模型 PROTECT。

> **实断阀门语义（实现口径）**：准入 PROTECT 产生 BLOCK 定案后，是否真实 403 由全局 `api_protection.mode` 统一阀门控制——全局 OBSERVE 时引擎将 BLOCK 降级为 OBSERVE（would-block，finding 照记），与 grpc/file/authz 等所有 BLOCK 类检测器同纪律。即「准入 PROTECT + 全局 PROTECT」才是完整实断；前端切换弹窗应在全局 OBSERVE 时提示该联动关系。

### 3.2 端点准入判定口径

请求端点键在**该应用已确认集合**中 ⇔ `asset_status = CONFIRMED`（按应用作用域匹配，见 §4.2）。

| 端点状态 | OBSERVE | PROTECT |
|---|---|---|
| CONFIRMED | 放行 | 放行 |
| DISCOVERED（已发现未确认） | 放行 + 观测 finding | **403** |
| IGNORED / DEPRECATED / ZOMBIE | 放行 + 观测 finding | **403** |
| 基线中不存在（从未发现） | 放行 + 观测 finding（沿用 SHADOW 上报为 DISCOVERED） | **403** + 上报为 DISCOVERED |

### 3.3 生命周期闭环

```
检测期:  流量 → 发现(DISCOVERED) → 学习(LEARNING→LEARNED) → 模型评审(FORMAL)
            ↓ 管理员批量确认（覆盖率面板辅助）
         CONFIRMED ──────────────┐
防护期:                           ↓
  已确认端点 → 放行 → schema/参数/WAF 等既有管线
  未确认端点 → 403 + 事件/finding → 出现在「准入拦截」列表
                → 管理员确认 → 发布 → 转为放行（finding 自动关闭）
                → 或确认其为异常 → 忽略(IGNORED)（持续拒绝）
```

## 4. 网关执行设计

### 4.1 新检测器 `api_admission`

位置：`gateway/dynamic_security/detectors/admission.go`，在 pipeline 中**最先执行**（集合查找，O(1)；PROTECT 命中拒绝时短路后续重检测器，节省 schema/模型计算）。

判定输入：当前请求的应用作用域 → 该应用的准入策略（模式 + 已确认端点集合）。

输出 Finding：

| finding_type | 条件 | OBSERVE | PROTECT |
|---|---|---|---|
| `admission.unknown_endpoint` | 基线无此端点 | OBSERVE/LOW | **BLOCK/HIGH** |
| `admission.unconfirmed_endpoint` | 有端点但非 CONFIRMED | OBSERVE/LOW | **BLOCK/HIGH** |

Category=BLOCK 即满足决策引擎硬阻断资格（`engine.go` 现有 `cat==BLOCK` 分支），**无需改决策引擎白名单**；OBSERVE 模式下降级为仅记录由引擎现有降级逻辑天然完成。

403 响应：统一 JSON `{"code":"API_ADMISSION_DENIED","message":"该接口未开放访问","request_id":"..."}`，对 unknown 与 unconfirmed 不作区分（防资产探测）；事件与 finding 内部记录真实原因。

### 4.2 下发物与作用域

`guardconfig` API 段新增（`BuildGuardConfig` 注入，随整站发布）：

```jsonc
// jiuzhang_guard 配置内
"api_admission": {
  "policies": {
    "<application_id>": {
      "mode": "PROTECT",
      "confirmed_endpoints": ["GET /v1/orders/{id}", "POST /v1/login", "..."]
    }
  }
}
```

- 键为 application_id（迁移 000137 后 endpoint_key 非全局唯一，按应用分组天然规避同键冲突）；网关按现有请求→应用解析（保护地址/Host 绑定）定位策略；解析不到应用时不做准入判定（与现状 KnownEndpoints 行为一致）。
- `confirmed_endpoints` 只含 CONFIRMED 端点键（method + normalized_path），由 `apiAssets` 新增 `ListConfirmedByApplication(ctx)` 提供；IGNORED/DEPRECATED/ZOMBIE 不下发（不在集合即拒绝，语义一致）。
- 网关模块配置新增 `APIAdmissionPolicies` 字段与校验（词表 OFF/OBSERVE/PROTECT，非法值 fail-safe 回落 OFF——**不拦截优于误拦截**，与现有 `apiDecisionMode` 回落 OBSERVE 的 fail-safe 哲学一致；OFF 语义=不启用）。

### 4.3 适用流量范围

准入判定仅作用于**判定为 API 的请求**（沿用现有 API 流量分类口径：路径前缀/Content-Type/绑定配置等，与 pipeline 装配条件一致）。未分类为 API 的请求（页面、静态资源）不做准入判定。分类争议路径由管理员通过确认/忽略显式归类（现有工作流）。

## 5. Server 设计

### 5.1 模式管理

- `applications.api_admission_mode` 新列（迁移，VARCHAR(8) 默认 'OFF'，CHECK 词表）。
- 读写入口：应用更新接口携带该字段（沿用应用更新权限与审计）；API 准入面板提供快捷切换（同接口）。
- **切换 PROTECT 前置校验（软门禁）**：服务端计算覆盖率报告，前端弹窗展示并要求显式勾选「已知晓影响面」后才提交；不硬阻断（管理员最终决策权，与产品现有模式切换风格一致）。

### 5.2 覆盖率与影响面报告（新接口）

`GET /api/v1/api-security/admission/coverage?application_id=<uuid>&hits_window=<小时数>`

- `hits_window`：命中统计窗口，正整数小时，范围 1–2160（90 天），缺省 168（7 天）；窗口受 api_runtime_events 实际留存约束，超出留存的窗口在响应中如实标注截断。
- 前端提供预设档（24 小时 / 3 天 / 7 天 / 14 天 / 30 天）+ 自定义天数输入（1–90）。

```jsonc
{
  "application_id": "...", "mode": "OBSERVE", "hits_window_hours": 168,
  "endpoints": { "confirmed": 24, "discovered": 5, "ignored": 1, "deprecated": 0, "zombie": 0 },
  "confirm_rate": 0.8,                       // confirmed / (confirmed+discovered)
  "unconfirmed_hot": [                        // 窗口内仍有命中的未确认端点（切 PROTECT 会误伤）
    { "endpoint_key": "GET /v1/coupon", "http_method": "GET", "normalized_path": "/v1/coupon",
      "asset_status": "DISCOVERED", "hits": 1320, "last_seen_at": "..." }
  ],
  "blocked": 0                                // 窗口内 PROTECT 准入拦截次数（OBSERVE 期为 0）
}
```

数据来源：`api_endpoints` 状态计数 + `api_runtime_events` 命中聚合。权限：`api_asset.read`。

### 5.3 准入拦截列表（新接口）

`GET /api/v1/api-security/admission/denied?application_id=&hits_window=&page=&page_size=`

窗口内 PROTECT 拦截的端点聚合（endpoint_key、http_method、normalized_path、asset_status、denied_count、last_denied_at、样本 client_ip 列表、first_seen_at），数据源 `api_runtime_events`（final_action=BLOCK 且 details 含 admission finding）；`hits_window` 语义同覆盖率接口。行操作：**确认**（转 CONFIRMED）/ **忽略**（转 IGNORED），复用 `api_asset.confirm` / `api_asset.ignore` 权限与现有接口；操作后提示「需发布后生效」。

### 5.4 确认 → 生效通道

复用整站发布（不新增通道）：

- 确认/忽略仅改库（现状行为），页面在存在「未发布的准入变更」时显示徽标与一键发布入口（发布走现有 `api_policy.publish`/应用发布通道与门禁 `publisher_gate.go`）；
- 发布后 `api_admission` 段随配置 `/load` 热生效，多节点扇出、版本校验、失败回滚全部沿用；
- 断网语义：网关持有最后一次发布的准入基线继续执行（fail-static）；server 恢复前新确认端点不放行——对安全功能而言这是可接受的保守行为，文档与页面均明示。

### 5.5 事件与 finding

- 网关 finding `admission.*` → server 映射新 finding_type `API_ADMISSION_DENIED`（PROTECT 实断）/ 复用 SHADOW（OBSERVE 未知端点现状），入 `api_runtime_findings`（OPEN；端点确认并发布后由 sweeper 置 RESOLVED）；
- `api_runtime_events` 照常落 final_action=BLOCK + details（准入原因、模式、应用）；
- （P2）system_alerts 新增「准入拦截突增/新端点被发现」告警规则。

## 6. 前端设计

新页面「API 准入防护」（API 安全菜单组，权限同 api 资产页）：

1. **应用准入总览表**：应用、当前模式（Badge）、确认覆盖率（进度条）、命中统计窗口选择器（预设 24 小时/3 天/7 天/14 天/30 天 + 自定义 1–90 天，作用于本页全部命中/拦截数字）、窗口内未确认命中数（>0 红色警示）、窗口内准入拦截数、操作（切换模式 / 去确认）。
2. **模式切换弹窗**：选 PROTECT 时内嵌覆盖率报告——未确认端点 TOP 列表（按 7 天命中降序，可就地批量确认）、影响面文案（「切换后以上 N 个未确认接口将被拒绝」）、勾选确认框后方可提交；切换后提示发布。
3. **准入拦截 Tab**：PROTECT 期被 403 的端点列表（次数/最近时间/样本 IP），行内「确认放行」「忽略」，批量操作，操作后发布提醒。
4. **未确认端点 Tab**：DISCOVERED 全集（复用现有资产确认交互）。
5. API 资产页（api-endpoints）增补「准入视角」筛选（未确认且近 7 天有命中）。

## 7. 安全与风险

| 风险 | 控制 |
|---|---|
| 确认集不全导致业务中断（默认拒绝的最大风险） | 切换前覆盖率 + 未确认命中榜强制展示；推荐 OBSERVE 跑满一个业务周期；回滚路径=切回 OBSERVE + 发布（分钟级） |
| 攻击者探测资产 | 403 统一响应不区分未知/未确认；不返回原因明细 |
| 低频接口首次被调即被拒 | 准入拦截列表 +（P2）告警，缩短「发现→确认」时延 |
| 配置非法/下发异常 | 网关侧非法模式回落 OFF（不拦截优于误拦截）；发布校验+回滚沿用 |
| 越权操作 | 模式切换走应用更新权限+审计；确认/忽略复用 `api_asset.confirm/ignore`+审计；全部操作落审计日志 |
| 网关断网 | fail-static：最后基线继续执行，不失控也不放行新确认 |

## 8. 权限与审计

- 不新增权限点：模式切换=应用更新权限；覆盖率/拦截列表=`api_asset.read`；确认/忽略=`api_asset.confirm`/`api_asset.ignore`；发布=`api_policy.publish`。
- 审计：模式切换（HIGH，含覆盖率快照入 details）、确认/忽略（现有）、发布（现有）。

## 9. 分阶段实施

**P1（本期 MVP）**
1. 迁移：`applications.api_admission_mode` + finding_type 词表注释；
2. server：覆盖率接口、拦截列表接口、应用更新携带模式字段、`ListConfirmedByApplication`、guardconfig 注入 api_admission 段；
3. 网关：admission 检测器 + 配置字段 + pipeline 装配（最前）+ 统一 403 响应；
4. 前端：准入防护页（总览表/切换弹窗/拦截 Tab/未确认 Tab）；
5. 测试：Go 单测（判定矩阵、覆盖率聚合、下发组装）、网关模块测试（PROTECT 403/OBSERVE 放行/未知短路）、前端 Vitest、stage5 端到端（学习→确认→PROTECT→403→确认→发布→200）。

**P2**：告警规则（拦截突增/新端点）、批量确认向导（按命中排序一键全确认）、sweeper 自动关闭已确认 finding、仪表盘卡片。

**P3**：AI 确认建议（基于流量稳定性与模型成熟度推荐确认集）、按业务类型的准入策略模板。

## 10. 测试方案要点

- 判定矩阵单测：5 种端点状态 × 3 种模式全组合；
- 并发安全：配置热加载中判定使用旧/新基线均不 panic（RWMutex 现状模式）；
- stage5 E2E：未确认接口 OBSERVE 放行 → 切 PROTECT（带覆盖率弹窗）→ 未发布仍放行 → 发布后 403 统一响应 → 确认该端点 → 再发布 → 200；同步校验事件/finding/审计落库；
- 回归：OFF 应用零影响（准入检测器不装配路径）、非 API 流量不受判定。

## 11. 待拍板决策点

| # | 问题 | 选项 | 建议 |
|---|---|---|---|
| 1 | 准入模式维度 | A 应用级 / B 全局 | **A**（学习与确认节奏天然按应用；全局一刀切误伤面大） |
| 2 | 生效通道 | A 复用整站发布 / B 新增轻量增量通道 | **A**（版本/回滚/多节点现成；B 值得 P2 再评估） |
| 3 | 切 PROTECT 门禁 | A 软提示+勾选 / B 覆盖率阈值硬门禁 | **A**（硬阈值缺乏历史数据支撑，先软后硬） |
| 4 | 未知路径处置 | A 仅 API 分类流量受控 / B 全部默认拒绝 | **A**（B 会误伤页面与静态资源） |
| 5 | 未确认命中榜窗口 | 固定 7 天 / 可自定义 | **可自定义**（预设 24h/3天/7天/14天/30天 + 自定义 1–90 天，默认 7 天；受事件留存截断并如实标注） |
