# 离线授权设计（产品侧）

本文档描述九章产品侧（WAF/WDSP/API 产品线）的离线授权机制：授权文件格式、验签与公钥轮换、
机器指纹、锁定与网关透传语义、配额口径、周期复核与告警、吊销边界与换机/续期流程。

授权文件由厂家授权中心（独立系统）离线签发，产品侧只验签不联网回连，适用于完全离线的交付环境。

## 1. 授权文件格式（.lic）

授权文件为单个 JSON 文档：

```json
{
  "payload": { ... },
  "signature": "<hex 编码的 Ed25519 签名>"
}
```

- **签名输入**：对 `payload` 做 *canonical JSON* 序列化后的字节流——即按 Go `map[string]json.RawMessage`
  重构后以 `json.Marshal` 输出的**键名字典序、紧凑（无空白）** JSON。产品侧验签时用同一规则重建
  canonical 字节，保证与签发侧逐字节一致。
- **签名算法**：Ed25519，签名值以 hex 编码存放于 `signature` 字段。

`payload` 各字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `license_id` | string | 授权唯一编号（导入历史/审计标识） |
| `license_type` | string | `FORMAL`（正式）/ `TRIAL`（试用） |
| `product` | string | 生效产品形态：`waf` / `wdsp` / `api` |
| `customer` | string | 客户名称 |
| `issued_at` | string | 签发时间（RFC3339） |
| `expires_at` | string \| null | 到期日（`YYYY-MM-DD`，含当天；`null` 表示不限制） |
| `perpetual` | bool | 是否永久授权（true 时不再按 `expires_at` 判定过期） |
| `machine_fingerprint` | string \| null | 绑定的机器指纹（`sha256:...`；`null` 表示不绑定机器） |
| `quotas` | object | 配额：`max_applications` / `max_api_endpoints` / `max_qps`（非负整数，**0 = 不限制**） |
| `features` | array | 特性清单（本期仅展示，不逐项门控） |
| `version` | string/int | 授权格式版本 |
| `key_id` | string | 签名公钥标识，验签时据此选择公钥 |

产品侧对 payload 做严格校验：product 必须在词表内、quotas 各项非负；逐字段校验失败返回 400。

## 2. 验签与公钥轮换

- **固定生产信任根**：`server/internal/license/vendor_pubkey.hex` 经 `go:embed` 内置进正式服务端二进制，
  每行一条 `key_id:hexpub`（hexpub 为 64 位 hex 的 Ed25519 公钥）；支持多条并存以完成密钥轮换
  （新授权用新 key 签发，旧 key 保留至存量授权全部到期后移除）。正式运行时不接受环境变量替换信任根。
- **测试构建隔离**：集成测试若需要临时公钥，必须使用显式 `wdsp_testkeys` 测试构建或应用装配层依赖注入；
  该路径不得用于正式交付，正式构建只加载内嵌公钥表。
- **Fail-closed**：内嵌公钥表未配置任何有效公钥时，**所有授权验签失败 = 系统进入锁定态**，
  不做任何占位绕过。
- 验签按 `payload.key_id` 选择对应公钥；key_id 未知、签名不通过均判定授权无效。

## 3. 机器指纹

### 3.1 算法（与授权中心 tools/fingerprint 逐字节一致）

```text
fingerprint = "sha256:" + hex( sha256( "v1|<mac>|<machine_id>|<cpu_model>" ) )
```

三项采集（部署目标为 Linux）：

| 采集项 | 来源 |
|--------|------|
| 主要非回环网卡 MAC | 优先默认路由接口（`ip route show default` 的 dev），读 `/sys/class/net/<if>/address`；取不到按内核 ifindex 顺序回退到第一块“已启用、非回环、带 MAC”的网卡 |
| 机器标识 | `/etc/machine-id`，缺失回退 `/var/lib/dbus/machine-id` |
| CPU 型号 | `/proc/cpuinfo` 首个 `model name` 的值 |

每项拼接前规范化：去首尾空白、统一小写、连续空白折叠为单个空格；某项取不到记 `unknown`，
采集不因此失败。指纹为纯本地计算，不联网、不外发。

### 3.2 安装期采集与容器内读取

容器内无法直接获得宿主机指纹，因此采用**安装期宿主机采集**：

1. `ops/install/install.sh`（生成 `.env` 之后、启动服务之前）调用 `ops/lib/fingerprint.sh`，
   将指纹写入 `<安装根>/runtime/license/host_fingerprint`（目录 755、文件 `chmod 600`，
   属主尽量调整为 uid 1000 即 api 容器内 `jiuzhang` 用户）；采集失败仅告警不中断安装，
   可事后重新执行 `bash ops/lib/fingerprint.sh` 核对后手动补齐。
2. compose 将该目录以只读挂载进 api 容器：`<安装根>/runtime/license:/app/runtime/license:ro`
   （离线包模板见 `ops/offline-package/build.sh` 内嵌 compose，叠加在 `runtime-data` 命名卷
   挂载点之下；开发编排见 `deployment/docker-compose.stage5.yml`）。
3. 服务端读取路径由 `LICENSE_HOST_FINGERPRINT_FILE` 指定，默认
   `/app/runtime/license/host_fingerprint`。
4. **授权未绑定指纹（`machine_fingerprint = null`）时跳过本项校验**；绑定指纹的授权在导入时
   与周期复核中比对，不一致判定 `FINGERPRINT_MISMATCH`。

授权管理页面展示本机指纹，客户将其报厂家用于签发绑定授权。换机、换网卡、重装系统会改变指纹。

## 4. 生效形态与锁定语义

- **生效形态由授权决定**：有效授权的 `license.product` 决定当前生效 edition 与能力集
  （覆盖 `.env` 的 `PRODUCT_EDITION`，但不得超过安装包已装配能力——例如 waf 包未装配 API 防护
  路由，授权 wdsp 也无法解锁，如实返回错误）。**无有效授权 = 全系统锁定**。
- **锁定判定在中间件实时进行**（内存缓存授权状态），不做路由动态增删；授权状态变化即时生效，
  无需重启。
- **锁定态白名单**（仅以下可用，其余一律 `423 Locked`，错误码 `LICENSE_INVALID`）：
  - `/api/v1/auth/*`（登录/改密等）
  - `/api/v1/health`
  - `/api/v1/license/*`（授权查看/导入）
  - 管理前端静态资源
- **能力门控**（授权有效但产品形态不含某能力）：
  - `product = waf`：锁定 `/api/v1/api-security/*`（403，错误码 `LICENSE_FEATURE_DENIED`）；
  - `product = api`：锁定 Web 防护专属接口（l7-rules 等，与现有 WebWAFProtectionEnabled 口径一致）。

## 5. 网关透传语义（授权无效时）

授权无效（缺失/过期/指纹不匹配/验签失败）时，配置发布通道产出**纯透传配置**：
`Guard = nil` 且全部应用强制 `ModeBypass`，即网关在授权无效期间只做
“RequestID + 安全响应头 + reverse_proxy + Caddy 访问日志”，**不检测、不防护**。

如实记录的已知代价（这正是“不检测不防护”的语义）：

- jiuzhang_guard 事件日志与全量访问日志（access-full）停止产出；
- 真实客户端 IP 改写头（TrustedProxy 段）消失，源站看到的是网关地址；
- 临时封禁、CC 频率限制等 guard 能力全部失效；
- **Caddy 自身的 access.log 照常记录**（不经 guard 链路）。

授权恢复（导入有效授权）后自动重新发布正常防护配置。切换延迟 = 一次发布（秒级），
复用既有版本管理/回滚/审计/多节点扇出能力。

## 6. 配额口径

`quotas` 三项全部强制，**值 0 = 不限制**：

| 配额 | 强制点 | 超限行为 |
|------|--------|----------|
| `max_applications` | 应用创建前校验当前总数 | 拒绝创建：403 `LICENSE_QUOTA_EXCEEDED` + 操作审计 |
| `max_api_endpoints` | API发现落库（新API插入分支） | 停止新API落库（**已有API不受影响**），记日志并触发系统告警；不阻断运行时事件落库 |
| `max_qps` | 网关 jiuzhang_guard 全局限速（固定 key，CC 段之前） | 超出返回 429 + `Retry-After` |

`max_qps` 计数后端语义：Valkey（Redis 协议）后端为多网关节点**跨节点共享**计数桶；
memory 后端为**每节点独立**计数（多节点部署时实际全局限额 ≈ 配额 × 节点数）。

`GET /api/v1/license/status` 返回三项配额与当前用量。

## 7. 周期复核

license 服务每 **60 秒**复核一次生效授权：篡改检测（`raw_file` 重验签，见 §11.2）、
到期翻转（`expires_at` 按日判定、含当天；`perpetual = true` 不过期）、
宿主机指纹文件变化导致失配翻转。状态翻转后：

1. 更新内存授权状态（中间件门控即时生效）；
2. 触发系统告警；
3. 触发网关整站重发布（进入/退出透传态）。

## 8. 告警类型

| 类型 | 级别 | 触发 |
|------|------|------|
| `LICENSE_INVALID` | CRITICAL | 无有效授权 / 验签失败 / 指纹不匹配 |
| `LICENSE_EXPIRING_SOON` | HIGH | 距到期 ≤ 7 天 |
| `LICENSE_QUOTA_EXCEEDED` | HIGH | API配额超限（应用/QPS 配额在各自拒绝点即时提示） |

告警复用现有系统告警引擎的合并与冷却机制。

## 9. 吊销、换机与续期

- **吊销不可感知（如实声明）**：纯离线场景下产品侧无法感知授权中心的吊销操作；
  已签发的 `.lic` 在到期前持续有效。需要作废某授权时，厂家应以更短有效期重签并让客户导入新文件。
- **换机重签 / 续期**：均为“签发并导入新 `.lic`”。导入新授权自动取代旧授权
  （旧记录状态置 `SUPERSEDED`，保留在导入历史中），无需卸载或重启。
- **授权存储**：`licenses` 表保存导入历史，生效授权为状态 `ACTIVE` 的唯一一行
  （数据库部分唯一索引保证）；授权原文经主密钥加密后存储，接口与审计不回显签名与原文。

## 10. 接口与权限

| 接口 | 权限 | 说明 |
|------|------|------|
| `GET /api/v1/license/status` | 登录即可（锁定态也可访问） | 有效与否、产品、客户、到期、指纹绑定状态、三项配额与当前用量、本机指纹 |
| `POST /api/v1/license/import` | `license.manage` | 上传 `.lic` 导入：逐字段校验失败 400、验签失败 422、指纹不匹配 409 |
| `GET /api/v1/license/history` | `license.read` | 导入历史（含状态翻转记录） |

权限种子口径（系统管理域）：`SYSTEM_ADMIN` 全量（read + manage）、`AUDIT_ADMIN` 仅 read、
`SECURITY_ADMIN` 不授权。全部写操作记操作审计（RiskHigh，签名与授权原文不落明细）。

## 11. 产品形态绑定与篡改检测（2026-09 增补）

针对"root 直接改库/改环境变量解锁未授权形态"的威胁模型补充两项机制与边界声明。

### 11.1 产品形态绑定（首导绑定，切换必须重装）

- **首次导入即永久绑定**：系统第一份成功导入的授权其 `product` 即为本部署的产品形态绑定值
  （取全表按导入时间最早的一条记录，**任何状态均计入**——`SUPERSEDED`/`EXPIRED`/`INVALID`
  历史同样构成绑定，无法通过翻转状态绕过）。
- 后续导入 `product` 与绑定值不一致的授权一律拒绝：`409` + 错误码 `LICENSE_PRODUCT_BOUND`，
  提示"如需切换产品形态请重新安装部署"。同 `product` 的续期/换证照常放行
  （旧行置 `SUPERSEDED` 的语义不变）。
- 全新部署（无任何授权记录）可导入任意 `product`——即"切换产品形态 = 重新安装部署"。

### 11.2 复核篡改检测（raw_file 重验签）

周期复核（60s）此前只重解析落库 `payload` jsonb，不复验签名，root 直接
`UPDATE licenses SET payload/product=...` 可改变生效形态。现每轮复核对生效候选行：

1. 解密 `raw_file`（导入时留存的完整 `.lic` 文件密文）；
2. `ParseFile → Verify` 重验 Ed25519 签名；
3. 校验解出的 payload 关键字段（`product`/`license_id`/`expires_at`）与 DB 行一致，
   并将签名 payload 规范字节与落库 `payload` 全文比对（覆盖 `quotas`/`features` 等字段篡改）。

任一失败即判定**授权数据被篡改**：该行翻转 `INVALID`、内存状态无效（Reason 含"篡改"）、
抛出 `LICENSE_INVALID` CRITICAL 告警并触发整站重发布（网关进入透传态）。
root 可改库但无法伪造厂家签名，篡改必现。

**能力边界（如实声明）**：`raw_file` 为 `NULL` 的历史行（加密服务未装配的开发态导入）
不具备篡改检测能力，复核跳过验签并记 Debug 日志，行为与增补前一致。

### 11.3 env 与 license 的关系

- env（`PRODUCT_EDITION` / 包装配能力开关）**仅为交付能力上限，只能收窄不能放宽**：
  生效 edition = license.product ∩ 包装配能力（见 `GET /api/v1/product/edition`）。
  root 改 env 至多进一步收窄能力，无法解锁授权之外的形态。
- **生效形态由签名授权决定**：root 改 DB（§11.2）会被复核识别并翻转 `INVALID`；
  授权形态宽于本包能力（如授权 `wdsp` 但包未启 API 能力）时复核 WARN 一次
  "授权产品形态宽于本包能力，部分能力不可用"，仅告警不改变行为。
- **物理不可防范围（如实声明）**：root 清空 `licenses` 表可重置产品形态绑定（与重装等价）、
  root 重装系统或替换服务端二进制/内嵌验签公钥属于物理层攻击，软件机制无法防御，
  依赖交付与运维侧的主机完整性管控。
