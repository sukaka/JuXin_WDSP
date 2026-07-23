# API 产品分离设计（阶段8 / WDSP）

## 一、目的与范围

九章在同一仓库维护两条产品交付线：**WAF**（既有 Web 应用防火墙）与
**WDSP**（WAF + API 动态防护）。产品分离的核心承诺是：**同一套代码、同一套
二进制，API 能力关闭时对 WAF 交付零行为变化**。本文覆盖：

- 产品形态与能力开关（`PRODUCT_EDITION` / `API_DYNAMIC_PROTECTION_ENABLED`）；
- 关闭时零行为变化承诺在网关、发布、路由、迁移四层的落实；
- 前端菜单与路由的 capability 门控；
- 单仓双产品线的分支策略（引用 `docs/BRANCHING_AND_PRODUCT_LINES.md`）。

## 二、产品形态与能力开关

`server/internal/product/edition.go` 定义运行时产品设置（`Load()`，`edition.go:36`）：

| 环境变量 | 缺省 | 语义 |
|----------|------|------|
| `PRODUCT_EDITION` | `waf` | `waf`（纯 WAF）/ `wdsp`（含 API 动态防护）；非法值回退 waf |
| `API_DYNAMIC_PROTECTION_ENABLED` | wdsp→true / waf→false | API 检测开关；显式设置优先于 edition 缺省 |
| `API_PROTECTION_MODE` | `OBSERVE` | OFF/OBSERVE/PROTECT；非法值回退 OBSERVE（fail-safe） |
| `API_MAX_BODY_PARSE_BYTES` 等 | 1MiB 等 | 解析限制（管理面展示用） |

两层判定的分工（`edition.go:73-90`）：

- `Settings.APIDynamicProtection`：**检测开关本身**——显式 env 可覆盖 edition 缺省
  （实验室可在 waf 形态下强开做验证，`edition_test.go:34-47`）；
- `Settings.APIDynamicProtectionEnabled()`：**对外能力** = `IsWDSP() &&
  APIDynamicProtection`。即使 waf 形态下强开了检测开关，管理面路由、发布通道、
  前端能力探测仍视为关闭——产品形态以交付语义为准，不被调试开关污染
  （`edition.go:78-82`、`edition_test.go:49-66`）；
- `EffectiveAPIProtectionMode()`：能力关闭时恒为 `OFF`（`edition.go:85-90`）。

## 三、零行为变化承诺的四层落实

### 3.1 网关请求路径

`serveNext` 第一行（`apiprotect.go:48-50`）：

```go
if !g.APIDynamicProtection {
    return next.ServeHTTP(w, r)
}
```

`api_dynamic_protection` 缺省/false 时：不读请求体、不建上下文、不跑解析与
检测、不写 API 事件日志（`apievents.Logger` 仅在开启时创建，`module.go:359-374`）。
纯 WAF 路径的指令序列与阶段5 完全一致。

### 3.2 发布配置

`buildGuardHandler` 仅在 `GuardConfig.APIDynamicProtection` 为真时注入
`api_dynamic_protection / api_protection_mode / api_events_log /
api_formal_schemas / api_known_endpoints`（`gatewayconfig/guard.go:128-143`）；
管理面组装侧同样仅开启时填充（`guardconfig/provider.go:289-320`）。
**关闭时下发的 Caddy JSON 与纯 WAF 完全一致**；链路顺序（headers →
jiuzhang_guard → waf）由回归测试锁定（`gatewayconfig/guard_test.go:58-67`），
模式解析的 fail-safe 由 `guardconfig/provider_mode_test.go` 锁定。
配置快照（`access_control_versions`）对 WAF 包不含任何 api_* 键，
版本历史与回滚语义不变。

### 3.3 管理面路由

`/api/v1/api-security/*` 全部三组路由（apiassets/apimodels/apisecurity）
仅在 `APIDynamicProtectionEnabled()` 为真时注册（`app/app.go:659-678`）；
WAF 形态下这些路径返回 404，与「该功能不存在」语义一致。
产品探测接口 `GET /api/v1/product/edition` 始终可用（已登录），返回
`edition` 与 `api_dynamic_protection` 布尔（`app/app.go:679-687`），
供前端门控。

### 3.4 后台任务与数据库

- API 运行时事件采集器仅在能力开启时启动（`cmd/api/main.go:116-123`）；
- 阶段8 迁移（000016/000018 建表、000019 权限种子）使用
  `IF NOT EXISTS` / `ON CONFLICT DO NOTHING`：WAF 包执行迁移只是多建若干
  空表与权限行，**空转无害**；不执行迁移时运行路径也不读这些表
  （路由与采集器都未注册），不存在「表不存在即 panic」的依赖
  （与 `BRANCHING_AND_PRODUCT_LINES.md` §5 约定一致）；
- 权限种子（27 个 `api_*` 权限点，迁移 000019）在 WAF 形态下存在于库，
  但因路由未注册而无任何可达接口，路由守卫（RequirePermission）无从触发。

## 四、前端 capability 门控

- 能力探测：`web/src/stores/product.ts` 登录后调 `/product/edition`；
  `apiDynamicProtection = (edition==='wdsp' && api_dynamic_protection===true)`，
  **失败或未知一律按关闭处理**（SAFE_DEFAULTS，`product.ts:14-17、31-33`）；
- 菜单：12 个「接口防护」菜单项声明 `capability: 'api_dynamic_protection'`
  （`web/src/utils/menu.ts:88-172`），`filterMenusByRoles` 在能力关闭时过滤
  （`menu.ts:304-306`）；能力未初始化亦按关闭（`menu.ts:296`）；
- 路由守卫：`web/src/router/index.tsx:107-109`，能力关闭时访问 API 页面
  重定向 /404；
- 后端权限仍是最終防线：即使前端被绕过，WAF 形态下路由未注册（404）、
  WDSP 形态下逐路由权限点校验。

## 五、分支策略（单仓双产品线）

按 `docs/BRANCHING_AND_PRODUCT_LINES.md` 执行，要点摘录：

```text
main     ── WAF 可发版线（bugfix/小兼容；tag waf-vX.Y.Z）
develop  ── WDSP/阶段8 集成线（API 动态防护；tag wdsp-vX.Y.Z）
feature/stage8-* → develop；hotfix/waf-* → main → 立即回合 develop
develop → main 仅当：API 能力默认关闭 + WAF 回归通过
```

与本设计的对应关系：

| 策略要求 | 落实 |
|----------|------|
| WAF 包不带半成品 API | edition 缺省 waf + 能力关闭四层落实（§三、§四） |
| 关闭时行为与 WAF 一致 | serveNext 早退 + 下发 JSON 一致 + 回归测试锁定 |
| 能力域可独立打包 | API 代码集中于 `gateway/dynamic_security/`、
  `server/internal/{apiassets,apimodels,apisecurity,apiruntime}`、
  `/api/v1/api-security` 命名空间、独立权限点与独立迁移组 |
| 公共底座复用 | 认证/RBAC/审计/发布通道/事件采集范式全部复用阶段2-6 既有模块，
  API 逻辑不写进 Coraza 适配器或 WAF 规则页 |

未来「九章 API 安全系统」独立产品时，抽取上述能力域模块、复用本仓底座，
不再复制用户/审计/发布体系（任务书 §49）。

## 六、关键设计决策

1. **运行期开关优于编译期拆分**。一套镜像按 env 交付两种产品，避免双源码树、
   双构建管道的维护分叉；公共 bug 修一处两线受益（分支策略的根本目的）。
2. **形态判定收口在管理面**。网关只认下发 JSON 的 `api_dynamic_protection`
   布尔，不理解 edition；产品语义（wdsp 才允许对外暴露）集中在
   `product.Settings` 一处判定，网关保持哑执行。
3. **fail-closed 的前端、fail-safe 的后端**。前端探测失败按关闭（不暴露半成品
   入口）；后端模式解析失败回退 OBSERVE（不放大防护动作）；模式脏数据回退
   构造配置（`provider.go:113-120`）。
4. **模式取值三级来源**：settings 表覆盖（API 策略页，写库即审计）>
   `API_PROTECTION_MODE` env > 内置 OBSERVE 默认（`apisecurity/policy.go:95-113`）；
   三级都经白名单，发布时取当前生效值下发。
5. **迁移与路由解耦**。表可以先于功能存在（空转无害），功能不可以先于表注册；
   升级 WAF→WDSP 只需切换 env 并发布，无需数据迁移动作。
6. **回归测试即承诺**。`apiprotect_test.go:68`（关闭时 serveNext 直通、
   不注入 RequestContext）、`product/waf_regression_test.go`（API 关闭时管线
   skip、遗留 WAF 匹配路径不受影响）、`edition_test.go`（形态判定矩阵）、
   `guard_test.go:58-67`（链路顺序与处理器注入）把「零行为变化」固化为
   CI 断言，而非文档口号。

## 七、当前实现范围与限制

1. **waf 形态强开检测仅限实验室**：`API_DYNAMIC_PROTECTION_ENABLED=true` +
   `PRODUCT_EDITION=waf` 时网关侧可跑引擎（若发布通道手工构造），但管理面
   不注册路由、不注入发布配置、不启动采集器——该组合不是交付形态，
   仅供引擎开发验证（`edition_test.go:34-47`）。
2. **打包清单未分化**：当前 WAF/WDSP 交付共用 compose 与镜像，差异仅在
   环境变量；安装包级的清单分化（WDSP 专属文档/默认配置）随独立发版补充。
3. **前端只有整组门控**：12 个 API 菜单共享一个 capability，无菜单级细粒度
   开关（如只开资产不开策略）。
4. **阶段7 AI Tool（`api_*`）未装配**：任务书 §48 的 10 个只读 Tool 的实现
   代码已在工作区（`server/internal/aitools/api_tools.go`，全部 READ_ONLY、
   不调用任何写路径），但 `NewAPITools` 尚无装配调用方，运行时不可用；
   「AI 不得自动确认模型/发布/修改用途」的边界维持不变。
5. **多网关配置一致性**：API 模型/基线随发布下发到各网关；行为/限速检测的
   进程内状态为单节点语义（`detectors/window.go:9-12`），多节点部署时各节点
   独立计数，该限制与产品形态无关但影响 PROTECT 模式下的阈值口径。

## 八、与任务书章节对应

| 本文章节 | 任务书 |
|----------|--------|
| 二、能力开关 | §2.8 运行时一体化能力域可拆分、§五十五 性能（关闭零开销） |
| 三、零变化承诺 | §65 退出条件 5（API功能关闭不影响WAF）、75（能力域可独立打包） |
| 四、前端门控 | §五十三 前端页面（能力可见性） |
| 五、分支策略 | §四十九 未来独立九章API安全系统 |
| 六、决策 1/2 | §四十九（公共底座复用、API 逻辑不写死进 Coraza 适配器） |

---

Copyright © 聚信得仁
All Rights Reserved.
