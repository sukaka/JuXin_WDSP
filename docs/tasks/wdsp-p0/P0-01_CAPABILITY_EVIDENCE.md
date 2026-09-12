# P0-01：版本能力与证据清单开发任务书

日期：2026-09-06。状态：待实施。优先级：产品 P0。

前置：[开发总纲](README.md)。关联：[基准测试](P0-02_SECURITY_PERFORMANCE_BENCHMARK.md)。

## 1. 问题与交付目标

产品能力分散在开发状态、设计文档、验收报告和代码中。“已有设计”“文件存在”“已接入请求链”“真实环境通过”容易混用，历史报告也容易被错误归入新版本。

交付一个本地可运行的能力证据工具：读取受版本管理的能力清单与本轮验收记录，校验证据和构建绑定，生成可读 Markdown。先复用交付检查，不新增一套独立验收平台。

完成标准：任一能力都能追到实现入口、适用产品/部署方式、测试与构建证据；没有证据或证据不匹配时，工具明确失败或标为未验证，不能生成“发布验收通过”。

## 2. 现有实现与复用位置

以下路径为编写时现有文件/目录，实施前重新读取：

| 位置 | 用途与边界 |
|---|---|
| `server/internal/delivery/` | 现有交付检查与持久化；状态包含 PASS、PENDING、WARNING、FAIL、NOT_APPLICABLE |
| `web/src/pages/delivery-check/DeliveryCheckPage.tsx` | 复用检查结果入口，不另建重复导航 |
| `docs/DELIVERY_ACCEPTANCE_GUIDE.md` | 补充“运行环境检查”和“版本能力证据”的区别 |
| `docs/DEVELOPMENT_STATUS.md`、`docs/API_SECURITY_CURRENT_STATE.md` | 初始盘点来源，不能代替实测 |
| `docs/agents/WDSP_AGENT_REMAINING_WORK.md` | Agent 能力、阶段和受限范围来源 |
| `docs/BUSINESS_PERFORMANCE_APM_DESIGN.md`、`docs/APM_OPERATIONS_GUIDE.md` | APM 部署前提与运维边界来源 |
| `server/internal/apm/handler.go`、`server/internal/app/app.go` | 核对 APM 真实服务接线 |

现有接口：`POST /api/v1/delivery-checks/run`、`GET /api/v1/delivery-checks/{id}`、`GET /api/v1/delivery-checks/{id}/export`。本项优先不新增 HTTP 接口；若扩展现有响应，只增可选字段并保持旧调用方兼容。

例如检测 CRS 文件存在，只能证明配置材料可用，不能直接证明攻击识别、拦截率或误报率通过。

## 3. 最小实施范围

以下均为**新增约定**：

```text
docs/capabilities/capabilities.json            # 能力与实现映射，唯一手工维护的能力数据源
docs/capabilities/capabilities.schema.json     # 字段、枚举及结构约束
docs/capabilities/CAPABILITIES.md              # 自动生成，不手工改状态
tools/capability_evidence.py                  # Python 标准库实现，或项目已有等价工具
tools/tests/test_capability_evidence.py       # 校验器/生成器测试
docs/evidence/releases/<build-id>/manifest.json
docs/evidence/releases/<build-id>/artifacts/  # 经脱敏的结果、日志及索引
```

实现者如采用已有工具目录，须在 WORKLOG 更新路径映射。不得为了该工具引入外部托管服务、分析上报或不必要的运行依赖。较大的原始报告可留在本地离线证据包；仓库保留可定位的索引与校验和，不默认提交海量文件。

## 4. 数据契约

### 4.1 能力条目

每条能力须包含以下字段。列表成员排序稳定，ID 一经发布不得复用给另一能力。

| 字段 | 约束 |
|---|---|
| `id`、`name`、`owner_module` | 稳定机器 ID、中文能力名、实现模块 |
| `product_lines` | WAF / WDSP / API 的非空集合，按仓库实际授权和产品路由核实 |
| `deployment_modes` | 反向代理、镜像、Agent、APM 探针等实际适用模式，不支持的不得填写 |
| `implementation_status` | NOT_STARTED / PARTIAL / IMPLEMENTED |
| `integration_status` | NOT_CONNECTED / PARTIAL / CONNECTED |
| `verification_status` | NOT_RUN / PASS / FAIL / BLOCKED；由证据计算，禁止手填覆盖 |
| `implementation_refs` | 仓库相对路径与符号名；校验路径存在，符号定位留给代码核查 |
| `required_test_ids` | 必须实际运行的测试 ID，不可空集合获得通过 |
| `prerequisites`、`limitations` | 授权、采集、协议、数据保留、环境等前提和限制 |
| `evidence_refs` | 对应证据 manifest 中的测试记录 ID；不存在则未验证 |

可加入多个场景验证结果，例如“单节点反向代理 PASS，镜像模式 BLOCKED”。汇总状态取强制场景的最差结果，不能用一个可用场景覆盖其他必测场景。

首批清单至少包含：WAF/CRS、真实 IP、访问控制与 CC、API 资产与模型、API 请求/响应检测、身份观测、JWT 验证、API 最终决策、整条请求处置解释、例外、事件链路、配置发布与 HA、APM 入口性能、APM Trace/SQL/异常、Agent 当前实际采集/转发范围。不要把“设计覆盖”统一填成 IMPLEMENTED。

APM 必须说明：入口性能不等于代码级观测；Trace、SQL、异常取决于对应采集。Agent 未实现阶段必须单独标明，不应错误推导为 Caddy 网关同类协议也不支持。

### 4.2 构建与证据包

`manifest.json` 至少包含：

| 字段 | 规则 |
|---|---|
| `schema_version` | 初始 1；破坏性改变必须升级并保留旧版本读取/明确拒绝策略 |
| `build_id`、`product_version` | 构建唯一 ID 与实际版本；同版本多次构建不能混淆 |
| `source.commit`、`source.dirty` | 实际提交和是否存在影响构建的未提交内容 |
| `source.snapshot_sha256`、`source.file_manifest` | 对构建相关源码逐文件哈希后生成规范化摘要，记录算法及排除规则 |
| `images` | 组件版本、平台、实际镜像 digest；多架构分别记录 |
| `config_fingerprint` | 规范化非敏感有效配置的哈希，包含规则集、模式与授权模块 |
| `environment` | OS/内核、CPU/内存、存储、部署拓扑、工具版本、时钟状态 |
| `started_at`、`ended_at` | UTC RFC3339；结束不能早于开始 |
| `tests` | 测试 ID、适用能力、环境、命令模板、真实状态、证据路径/哈希、限制 |
| `release_status` | DEVELOPMENT / RELEASE_VERIFIED，由校验结果计算 |

源码快照排除 `.git`、证据输出、依赖缓存、凭据文件和运行数据；使用明确的构建输入清单并包含相关未跟踪源码。不能仅凭 `git diff` 忽略新增文件。配置指纹只计算经过字段白名单筛选的非敏感信息；不要保存 secret 的哈希来替代脱敏，低熵密码仍可被猜测。

测试状态统一为 PASS / FAIL / SKIP / BLOCKED / NOT_RUN。NOT_APPLICABLE 仅用于有明确产品范围依据的场景排除，并需要原因与审核记录，不能把必测失败改成不适用。

以下是**草稿最小示例**，故意不具备正式发布所需的镜像、测试和证据；`check --release` 必须拒绝它：

```json
{
  "schema_version": 1,
  "build_id": "draft-local",
  "product_version": "unresolved",
  "source": {
    "commit": null,
    "dirty": true,
    "snapshot_sha256": null,
    "file_manifest": []
  },
  "images": [],
  "config_fingerprint": null,
  "environment": {"id": "not-provisioned"},
  "started_at": null,
  "ended_at": null,
  "tests": [],
  "release_status": "DEVELOPMENT"
}
```

### 4.3 状态计算

1. 实现与接线状态来自代码核查，必须有引用；没有测试不能自动改成未实现，但也不能改成已验证。
2. 强制测试全部实际执行并通过，且构建/配置/环境绑定符合场景要求，才能计算该场景 PASS。
3. 任一强制用例 FAIL → FAIL；无失败但存在环境阻塞 → BLOCKED；缺失、SKIP 或未执行 → NOT_RUN，并保留细项。
4. `RELEASE_VERIFIED` 必须绑定最终不可变、可重建的干净发布输入和锁定镜像；强制范围无 FAIL/BLOCKED/NOT_RUN。源码含敏感本地运行文件但不影响构建时，用明确构建输入检查规则判断，不可简单隐藏 dirty 标记。
5. 旧版本证据可作为历史参考，不能自动为新构建背书。若需复用不受改动影响的非运行型检查，必须显式说明范围、审核人/记录和理由；安全与性能最终运行证据仍针对本轮构建。

## 5. 工具与管理页面行为

以下 CLI 为**待实现命令契约**，在工具落地前不可报告它们已运行：

```sh
python3 tools/capability_evidence.py check --catalog docs/capabilities/capabilities.json --manifest <manifest-path>
python3 tools/capability_evidence.py render --catalog docs/capabilities/capabilities.json --manifest <manifest-path> --output <report-path>
python3 tools/capability_evidence.py check --catalog docs/capabilities/capabilities.json --manifest <manifest-path> --release
python3 -m unittest discover -s tools/tests -p 'test_capability_evidence.py'
```

- `check` 对无效结构、重复 ID、断链、哈希不符、状态伪造返回非零和可读错误；检查未验证的合法草稿可返回零，但输出必须标注“结构有效，未完成验收”。`--release` 对任何未满足的发布门槛返回非零。
- `render` 不改变源清单、不执行测试、不访问网络；生成结果显示构建、日期、能力状态、证据和限制。合法未通过记录也可生成报告，但不能显示通过徽标。
- 同一输入产生相同顺序与内容，写入采用临时文件后原子替换；工具中断不得破坏原清单。
- 所有路径限定在明确的仓库根或证据包根，解析真实路径后检查目录边界；拒绝 `..` 越界、外部绝对路径、越界符号链接和远程 URL 自动获取。
- 测试的 `command` 是审计文本，校验器不得调用 shell 自动执行它。
- 对接交付页面时区分“此环境检查”与“此构建能力验证”；无证据显示未验证。沿用权限和导出机制，禁止浏览器传入任意本地路径读取报告。

## 6. 实施步骤

1. 盘点现有能力和引用，建立字段 schema、必测 ID 与第一版清单；全部新验证状态从 NOT_RUN 开始。
2. 先写校验器失败测试，再实现结构、构建绑定、文件哈希、状态聚合与路径限制。
3. 实现规范化生成器；用同一输入重复生成比较差异。
4. 接入现有交付导出说明；若增加后端字段或页面，补契约和权限回归。
5. S2/S3/S4/S5 产出结果后逐次关联；S6 才冻结正式发布证据。

## 7. 必须通过的验收用例

| ID | 操作/条件 | 预期 |
|---|---|---|
| EVD-01 | 条目代码存在、没有测试证据 | 已实现与未验证分别显示，不能 PASS |
| EVD-02 | 一个强制测试 SKIP，进程退出码为 0 | 该场景 NOT_RUN；发布门槛失败 |
| EVD-03 | 证据 commit、dirty 快照、镜像或有效配置不匹配 | 拒绝绑定；说明具体冲突 |
| EVD-04 | 篡改报告文件、删除文件、重复测试/能力 ID | 校验失败，错误能定位字段/文件 |
| EVD-05 | 路径含越界、符号链接越界、URL、恶意 command 字符串 | 拒绝越界；不发请求、不执行命令 |
| EVD-06 | 输入含不支持的 schema 版本、错误枚举/时间 | 明确失败，不按默认 PASS 容错 |
| EVD-07 | 同输入生成两次，或生成过程中注入写入失败 | 输出确定；失败时原文件完整 |
| EVD-08 | 增加影响构建的未跟踪源码 | 快照摘要改变；不能继续使用旧快照证据 |
| EVD-09 | APM 有页面、无探针/数据面；Agent 某模式未实测 | 分场景标注前提和未验证，不宣称全能力通过 |
| EVD-10 | 报告导出/权限回归（若改 HTTP/UI） | 无权者不能读取受限报告；错误和空状态正确 |
| EVD-11 | 按证据从干净环境重建、部署并重跑必测集 | 可复现；构建与结果绑定正确 |
| EVD-12 | 最终镜像、配置与必测结果齐全 | 才生成 RELEASE_VERIFIED，产物包含所有强制 ID |

工具单元测试至少覆盖 EVD-01～09；EVD-10 按实际变更范围执行；EVD-11～12 必须以真实环境证据完成。

## 8. 回退与交付

工具只读源数据并生成产物，默认不操作运行中的系统。清单 schema 升级前保留旧版解析或转换器，转换不得把旧未验证状态升为 PASS。若扩展交付接口，新字段可空且旧客户端继续工作。

交付物：机器清单、schema、校验/生成工具与测试、生成 Markdown、离线证据目录说明、现有交付文档更新、WORKLOG。S1 可以交付工具与未验证清单；只有 S6 满足条件后才能交付正式版本能力证明。
