# API 安全图谱设计（阶段8 / WDSP）

## 一、目的与范围

本文档描述阶段8 API 安全图谱与调用拓扑的实现：`api_call_edges` 调用边表、
`GET /api/v1/api-security/graph` 与 `GET /api/v1/api-security/topology` 两个接口的
输出形态、前端 ECharts 力导图与应用分组卡片页面。

图谱回答两个问题：**系统里有哪些 API（节点），以及谁在调用它们（边）**。
对应任务书第三十八、三十九章；任务书允许"第一版可以使用关系表实现，不强制引入
图数据库"，实现即按此口径：节点取 `api_endpoints` 全量，边取 `api_call_edges`
全量，均为关系表直读。

覆盖代码：`server/internal/apisecurity/store.go`（图谱仓储）、
`server/internal/apisecurity/handler.go` + `routes.go`（接口）、
`web/src/pages/api-graph/`、`web/src/pages/api-topology/`（前端）、
迁移 000018 `api_call_edges`。

## 二、架构与数据流

```text
节点来源：api_endpoints（持续发现/人工确认的资产）
边来源：  api_call_edges（caller 指纹 + 目标API；当前无写入方，见第七节）

GET /api/v1/api-security/graph      （api_graph.read）
  → ListGraph：API全量（endpoint_key 升序）+ 调用边全量（call_count 降序）
  → {nodes: [...], edges: [...]}
  → 前端 ApiGraphPage：ECharts force 力导图 + 调用边明细表

GET /api/v1/api-security/topology   （api_graph.read）
  → ListTopology：API LEFT JOIN applications 按应用分组 + 调用边全量
  → {applications: [...], edges: [...]}
  → 前端 ApiTopologyPage：应用分组卡片墙 + 调用边明细表
```

## 三、数据结构

### 3.1 api_call_edges（调用边）

迁移 000018 第 268-277 行：

| 列 | 说明 |
|----|------|
| `id` | 主键 |
| `caller_fingerprint` | 调用方指纹（VARCHAR(128)，非明文） |
| `source_endpoint_id` | 源API（可空，FK `ON DELETE SET NULL`）——调用方也是已发现API时填 |
| `target_endpoint_id` | 目标API（非空，FK `ON DELETE CASCADE`） |
| `call_count` | 累计调用次数 |
| `first_seen_at` / `last_seen_at` | 首见 / 最近见时间 |

索引：`idx_api_call_edges_target (target_endpoint_id)`。边模型对应任务书第三十八章
关系清单中的两类："身份调用 API"（caller 指纹 → 目标API）与"API 前置调用 API"
（source_endpoint_id 非空时的API间边）。

### 3.2 图谱输出形态

`server/internal/apisecurity/store.go`：

- `GraphNode`（store.go:183-192）：`id`、`endpoint_key`、`http_method`、
  `normalized_path`、`application_id`（可空）、`asset_status`、
  `learning_status`、`hit_count`；
- `GraphEdge`（store.go:195-203）：与表结构一一对应；
- `Graph`（store.go:206-209）：`{nodes, edges}`；
- `ListGraph`（store.go:212-239）：节点按 `endpoint_key` 升序全量返回，
  边按 `call_count` 降序全量返回（`listEdges`，store.go:310-328）。

### 3.3 拓扑输出形态

- `TopologyGroup`（store.go:242-246）：`application_id`（可空）、
  `application_name`、`endpoints`（同 GraphNode）；
- `Topology`（store.go:249-252）：`{applications, edges}`；
- `ListTopology`（store.go:255-307）：API `LEFT JOIN applications`，
  按 `application_id NULLS LAST, endpoint_key` 排序后保序聚合分组；
  无应用归属或应用名为空的分组名回退为"未分组"（store.go:283-286）。

两接口的 OpenAPI 契约见 `server/openapi/openapi.yaml:1262-1316`，均要求
`api_graph.read` 权限（routes.go:21-24），全量返回、无分页参数。

## 四、前端呈现

### 4.1 API 安全图谱页（api-graph）

`web/src/pages/api-graph/ApiGraphPage.tsx`：

- 按需注册 ECharts 部件（`GraphChart` + Tooltip + Legend + CanvasRenderer，
  第 17 行）——公共 EChart 组件未注册 graph 系列，页面自带轻封装
  `GraphChartView`（ResizeObserver 自适应，第 40-62 行），不改公共组件；
- **力导布局**：`layout: 'force'`，`repulsion: 220`，`edgeLength: [48, 140]`，
  可缩放拖拽，强调时聚焦邻接（第 129-141 行）；
- **节点上色**：按资产状态映射（DISCOVERED 蓝 / CONFIRMED 绿 / IGNORED 灰 /
  DEPRECATED 橙，第 22-27 行，与 `web/src/utils/stage8.ts` 的
  `API_ENDPOINT_STATUS_META` 一致）；
- **外部调用方合成节点**：边的 `source_endpoint_id` 为空或不在节点集合中时，
  以 `caller:{指纹}` 合成灰色小节点（第 97-109 行），指纹截断展示
  （`truncateMiddle` 保留首尾）；
- **边宽映射调用量**：`width = 1 + (call_count / maxCallCount) × 6`（第 115 行）；
  目标API不在节点集合中的边跳过不画（第 110 行）；
- 顶部统计卡片（节点数 / 调用边数）+ 调用边明细表（指纹、目标API、调用次数，
  第 146-190 行）。

### 4.2 API 调用拓扑页（api-topology）

`web/src/pages/api-topology/ApiTopologyPage.tsx`：

- 按应用分组的卡片墙：每应用一张小卡片（应用名 + API计数），API渲染为
  `方法 + 归一化路径` 的 Tag，Tag 颜色对应资产状态（第 64-85 行）；
- 下方调用边明细表与图谱页同构（第 87-95 行）。

路由注册于 `web/src/router/index.tsx:336,346`，菜单位于 `AdminLayout.tsx:100-101`。

## 五、关键设计决策

1. **关系表实现，不引图数据库**。节点与边都是单表直读，无图遍历查询；
   图谱复杂度（多层展开、路径查找）让位于交付确定性（任务书三十八章允许）。
2. **节点即资产，不另建影子节点表**。图谱节点直接取 `api_endpoints`，
   资产状态、学习状态、命中数随节点一并输出，图谱页与资产页数据同源，
   不会出现两套口径。
3. **调用方以指纹表示**。边不记录调用方 IP/凭据明文，`caller_fingerprint`
   与身份检测的指纹纪律一致；前端也只展示截断指纹。
4. **源API可空**。外部调用方（浏览器、合作伙伴系统）不是本系统API，
   `source_endpoint_id` 置空、`ON DELETE SET NULL` 保证API删除后边的
   调用事实仍可追溯；前端据此合成外部节点，模型与展示自洽。
5. **接口全量直读**。图谱/拓扑数据量受API数量自然约束（资产规模），
   第一版不做分页与增量同步，前端一次取全量渲染。

## 六、当前实现范围与限制

- **调用边暂无写入方（核心限制）**。`api_call_edges` 已建表、两个读接口与两个
  前端页面均已实现，但全仓库无任何代码 INSERT/upsert 调用边——运行时事件采集
  链路（`server/internal/apiruntime`）当前只做API发现 upsert 与主事件入库，
  不生成调用边。因此图谱/拓扑页面当前只能展示节点与空边集合，边的数据填充
  （从运行时流量聚合 caller 指纹 + 目标API）是后续工作。
- **跨API链路边在演进中**。边模型已预留 `source_endpoint_id`（API 前置调用
  API），但网关在代理链路中尚不识别"请求由哪个上游 API 触发"，API间边
  （任务书三十九章的前后调用顺序、高频调用链）无数据来源。
- **拓扑接口前后端契约不一致（已发现缺陷）**。后端返回键为 `applications`
  （store.go:250、openapi.yaml:1291），前端 `apiGraphApi.topology()` 类型与
  页面读取的是 `groups`（`web/src/api/apiSecurity.ts:220`、
  `ApiTopologyPage.tsx:23`）——应用分组卡片墙当前渲染为空，仅边明细表可用，
  需对齐键名后修复。
- **关系维度远少于任务书**。任务书三十八章的域名、模型版本、参数、角色、租户、
  设备、业务对象、敏感数据、安全事件等实体与关系均未入图；当前图谱只有
  "API + 调用边"两类事实。
- **无过滤与时间窗**。接口无应用/身份/时间/风险过滤参数（任务书三十九章的
  多视角查看未实现）；全量读取在极端资产规模下需引入分页或采样。
- **hit_count 为API累计值**。节点的 `hit_count` 来自 `api_endpoints`，
  不是图时间窗内的调用量，与边的 `call_count` 口径不同，展示时需注意区分。

## 七、与任务书对应章节

- 第三十八章（API 安全图谱）：关系表第一版、"身份调用 API / API 前置调用 API"
  两类关系的边模型；
- 第三十九章（API 调用拓扑）：按应用分组的拓扑视图；前后调用链见第六节；
- 51.4（分类和图谱）：`GET /graph`、`GET /topology` 两个接口；
- 第五十二章：`api_graph.read` 权限点（迁移 000019 种子）；
- 第五十三章：API 图谱与拓扑前端页面。

Copyright © 聚信得仁
All Rights Reserved.
