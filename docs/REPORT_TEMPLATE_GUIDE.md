# 报告模板使用指南（阶段6）

模板定义见 `docs/REPORTING_DESIGN.md`；实现：`server/internal/reports/`（store.go 模板 CRUD 与校验、render.go/pdf.go 渲染、reportno.go 编号）。
模板控制报告的页眉页脚、署名、编号格式与 21 个章节的显示开关；模板是纯数据，不包含也不执行任何代码。

## 模板字段

| 字段 | 类型 | 上限 | 说明 |
|------|------|------|------|
| `name` | string | 100 | 模板名称（必填） |
| `company_name` | string | 200 | 公司名（封面副标题） |
| `product_name` | string | 200 | 产品名（标题/页脚，默认「九章WEB应用智能防护系统」） |
| `logo_text` | string | 50 | 封面标志文字（默认「九章」） |
| `header_text` | string | 200 | 页眉文字（非空时显示，附报告编号） |
| `footer_text` | string | 200 | 页脚文字（非空时显示） |
| `report_no_format` | string | 50 | 报告编号格式（默认 `JZ-{YYYYMM}-{SEQ}`） |
| `prepared_by` / `reviewed_by` | string | 100 | 编制/审核人署名 |
| `description` | string | 500 | 模板说明 |
| `sections` | object | - | 章节开关 `{"章节键": true/false}` |
| `is_builtin` | bool | - | 内置模板标记（系统维护，不可修改/删除） |
| `version` | int | - | 乐观锁版本号（每次更新 +1） |

校验（`ValidateTemplateInput`）：名称必填、各字段长度如上、`sections` 只允许已知章节键，违反返回 400。

## 章节开关（21 个章节键）

`cover` 封面、`period` 报告周期、`scope` 报告范围、`summary` 管理摘要、`traffic` 请求流量、`events_overview` 安全事件总览、`risk_level` 风险等级、`attack_types` 攻击类型分布、`attack_trend` 攻击趋势、`source_ips` 攻击源IP TOP10、`applications` 被攻击应用 TOP10、`rule_hits` 命中规则 TOP10、`cc_protection` CC防护、`ip_lists` 黑白名单、`disposition` 事件处置、`false_positives` 误报和例外、`upstream_health` 源站健康、`certificates` 证书状态、`publish_tasks` 策略发布、`system_health` 系统运行、`conclusions` 结论和建议。

规则：`sections` 中未出现的键视为开启（`Show`：未显式关闭即启用）；创建时不传 `sections` 则等价于全部开启。

## 报告编号格式变量

| 变量 | 含义 | 示例 |
|------|------|------|
| `{YYYYMM}` | 报告请求时间所属年月（UTC） | `202607` |
| `{SEQ}` | 该月内报告序号（至少 4 位，不足补零；按当月已生成编号数 +1） | `0007` |

其余字符原样保留；格式为空时回退默认 `JZ-{YYYYMM}-{SEQ}`。示例：`JZ-202607-0007`、自定义 `SEC-{YYYYMM}-{SEQ}` → `SEC-202607-0003`。

## 内置模板与默认模板

- 内置模板（`is_builtin=true`）：名称「默认报告模板」，包含全部 21 个章节，编号格式 `JZ-{YYYYMM}-{SEQ}`；服务启动与报告 Worker 启动时自动确保存在（幂等），不可修改、不可删除。
- 默认模板选择规则：创建报告任务未指定 `template_id` 时，取内置模板；内置缺失时取最早创建的模板（`DefaultTemplate`：`is_builtin` 优先、其次 `created_at` 最旧）。

## 接口速览

| 接口 | 说明 |
|------|------|
| GET /api/v1/report-templates?page=&page_size= | 列表（内置排最前；page_size 默认 20、上限 100） |
| POST /api/v1/report-templates | 创建（请求体 JSON，上限 16KB） |
| GET /api/v1/report-templates/{id} | 详情 |
| PUT /api/v1/report-templates/{id} | 全量更新（内置模板返回 400） |
| DELETE /api/v1/report-templates/{id} | 软删除（内置模板返回 400） |

读接口需 `report_templates.manage` / `reports.read` / `reports.create` 任一权限；写接口需 `report_templates.manage`。

## 自定义模板步骤

1. 以持 `report_templates.manage` 权限的账号调用 `POST /api/v1/report-templates`，提交模板 JSON（见下例）。
2. `GET /api/v1/report-templates` 确认模板已创建（内置模板始终排最前）。
3. 创建报告任务时在 `POST /api/v1/reports` 请求体带 `template_id`；不传则使用默认模板（内置优先）。
4. 需要调整时 `PUT /api/v1/report-templates/{id}`（全量更新，`version` 自动 +1）；不再使用时 `DELETE /api/v1/report-templates/{id}`（软删除）。
5. 内置「默认报告模板」不可修改/删除（返回 400「内置模板不允许修改或删除」）；需要变体请新建模板。

## 示例 JSON

```json
{
  "name": "月度运营报告模板",
  "company_name": "某某科技有限公司",
  "product_name": "九章WEB应用智能防护系统",
  "logo_text": "九章",
  "header_text": "某某科技安全运营中心",
  "footer_text": "内部资料，请勿外传",
  "report_no_format": "OPS-{YYYYMM}-{SEQ}",
  "prepared_by": "张三",
  "reviewed_by": "李四",
  "description": "面向月度安全运营例会，隐藏证书与发布细节",
  "sections": {
    "cover": true,
    "period": true,
    "scope": true,
    "summary": true,
    "traffic": true,
    "events_overview": true,
    "risk_level": true,
    "attack_types": true,
    "attack_trend": true,
    "source_ips": true,
    "applications": true,
    "rule_hits": true,
    "cc_protection": true,
    "ip_lists": true,
    "disposition": true,
    "false_positives": true,
    "upstream_health": true,
    "certificates": false,
    "publish_tasks": false,
    "system_health": true,
    "conclusions": true
  }
}
```

## 注意事项

- 模板不执行代码：HTML 报告使用固定内置 Go 模板渲染，模板字段仅作为数据传入并由 `html/template` 自动转义；不存在脚本执行、模板注入或外部请求面。
- HTML 报告为单文件：CSS 全部内联，无外部图片/字体/脚本引用，可离线打开；预览接口附带严格 CSP 头。
- PDF 报告使用同一组模板字段；中文字体缺失时自动降级为 ASCII 摘要页（详见 REPORTING_DESIGN）。
- 章节开关影响 HTML 与 PDF 两种格式，且章节顺序固定（不随模板调整）。
- 模板写操作（创建/更新/删除）均记录操作审计。
- 报告数据内容由报告任务的时间范围与应用范围决定，模板只控制呈现，不影响统计口径。
