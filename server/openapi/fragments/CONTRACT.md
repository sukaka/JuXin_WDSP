# WDSP OpenAPI 片段编写契约（所有子任务必读并严格遵守）

目标：为「九章WEB动态安全管理平台（WDSP）管理后端」编写一份完整、详细的 Swagger / OpenAPI 3.0.3 文档。
每个子任务只负责一个域，输出一个 YAML 片段文件，最后由编排者合并为 `server/openapi/wdsp-api.yaml`。

## 输出文件格式（硬性要求）

- 每个片段是一个合法 YAML 文件，**只允许两个顶层键**：`paths:` 和 `components:`（`components:` 下只允许 `schemas:`）。
- 禁止输出 `openapi/info/servers/tags/security` 等顶层键（由最终骨架统一提供）。
- 2 空格缩进，禁止 Tab；含冒号的字符串要加引号；中文描述直接写。
- 路径**不带** `/api/v1` 前缀（最终文档 `servers: [{url: /api/v1}]`），例如 `/auth/login`。
- 路径模板用 `{id}` 风格，与 Go 路由注册一致。

## 每个 operation 必须包含

- `operationId`：全局唯一，camelCase，建议带域前缀（如 `authLogin`、`appList`、`apiSecEndpointConfirm`）。
- `tags`：使用任务指定的 tag 名。
- `summary`：简洁中文摘要。
- `description`：补充说明，**必须注明所需权限点**（形如「权限：`users.read`」；无需权限的写「权限：登录即可访问」或「权限：无（公开）」），以及限流、导出、幂等等特殊行为。
- `parameters`：路径参数（`required: true`）与查询参数，含 `name/in/required/schema/description`。分页参数统一为 `page`（默认 1）、`page_size`（默认 20）。
- `requestBody`：POST/PUT/PATCH 必填（无体时省略）；`application/json`；文件上传用 `multipart/form-data`。
- `responses`：至少含成功响应 + 适用的错误响应引用。

## 可复用的公共组件（最终骨架提供，片段直接 `$ref`，不要重复定义）

- 响应引用：
  - `$ref: '#/components/responses/BadRequest'`（400 参数/校验错误）
  - `$ref: '#/components/responses/Unauthorized'`（401 未登录/会话失效）
  - `$ref: '#/components/responses/Forbidden'`（403 无权限/CSRF 校验失败）
  - `$ref: '#/components/responses/NotFound'`（404 资源不存在）
  - `$ref: '#/components/responses/InternalError'`（500 服务内部错误）
- 模式引用：
  - `$ref: '#/components/schemas/Error'`（统一错误体 `{error: {code, message, details?}}`）
  - `$ref: '#/components/schemas/MessageResponse'`（`{message: string}` 简单成功响应）

## 模式（schema）编写规则

- schema 名 PascalCase，**必须带域前缀**避免跨片段冲突（如 `AuthLoginRequest`、`AppUpstream`、`ApiSecEndpoint`、`AiSession`）。
- 字段类型必须与代码一致：`string`/`integer`/`number`/`boolean`/`array`/`object`；时间戳 `type: string, format: date-time`；可空字段加 `nullable: true`；枚举给出 `enum`。
- 列表分页响应统一结构：`{items: array, page: integer, page_size: integer, total: integer}`，命名为 `<域><资源>ListResponse`。
- 关键字段补 `description`（中文），特别是状态枚举、单位（如 bytes、秒）。
- **数据源优先级**：服务端 Go 代码（handler/请求响应结构体）为准；`web/src/api/*.ts` 与 `web/src/types/index.ts` 用于交叉核对字段名与可空性；`server/openapi/openapi.yaml` 中已有的同路径内容可改写复用。
- 禁止虚构路由或字段；拿不准的字段以 Go 结构体 json tag 为准。

## 已有参考

- `server/openapi/openapi.yaml` 是阶段2+阶段8 的部分文档，风格可参照（但不必照搬其顶层结构）。
- 路由注册源：各 handler.go / routes.go 中的 `mux.Handle("METHOD /api/v1/...")` 行，其中 `middleware.RequirePermission("x.y")` 即权限点；`requireAnyPerm("a","b")` 表示任一权限。
