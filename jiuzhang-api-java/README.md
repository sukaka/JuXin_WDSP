# 九章API安全系统（Java 原生核心）

这是独立目录中的 Java 21 API 安全核心实现。程序使用 JDK 自带的 HTTP 服务和 HTTP 客户端，直接构建为可执行 JAR；不需要 Docker、Go、Maven、数据库或前端构建工具。

## 已实现能力

- REST JSON、表单、GraphQL、SOAP/XML、gRPC 与 SSE 识别；
- 数字、UUID、长十六进制和日期路径段归一化；
- JSON、表单与安全 XML 请求解析，共享一次解析结果；
- 参数候选模型：样本数、出现率、类型、长度和数值范围；
- 人工提供的正式模型：必填、类型、长度、数值和枚举校验；
- API Key、Bearer、Cookie Session 与 JWT 结构信号；
- 可选 HS256 JWT 验签，未验签声明不作为可信主体或角色；
- HMAC-SHA256 身份、来源与对象指纹，不落凭据明文；
- 敏感字段和值级信号，Query 敏感信息在 PROTECT 下阻断；
- 匿名对象访问、角色基线和已确认所有者关系辅助检测；
- 有容量上限的客户端限速与对象枚举观察；
- OFF、OBSERVE、PROTECT 统一决策；
- JSON 响应敏感字段检测与固定值遮盖，实际脱敏结果为 `***`；
- JSON Lines 安全事件、只读资产/事件/学习/指标接口。

## 明确边界

这是可运行的 API 安全核心，不是原 API 平台的完整平移。当前仅支持单源站、HTTP 客户端接入和单进程内存状态；不包含完整管理控制台、用户权限、数据库、集群、主动扫描、AI、Kafka、多节点发布或全部协议深度解析。候选模型不会自动转为正式模型。

管理接口没有认证，因此配置校验强制管理监听地址为回环地址。生产部署若需远程管理，应在外部受控通道中提供认证与访问控制，而不是直接暴露该端口。

## 构建与测试

要求 Java 21，包含 `javac` 和 `jar`：

```bash
cd jiuzhang-api-java
scripts/test.sh
scripts/build.sh
```

构建产物为 `dist/jiuzhang-api-security.jar`。

## 本地启动

```bash
cp config.example.properties config.local.properties
export JIUZHANG_IDENTITY_SALT='replace-with-at-least-32-random-bytes'
scripts/run.sh config.local.properties
```

默认源站为 `127.0.0.1:23090`，代理端口为 `18090`，只读管理端口为 `19091`。如果源站使用 JWT HS256，可另外设置 `JIUZHANG_JWT_HMAC_SECRET`；未配置时只检查 JWT 结构，不把声明当作可信身份。

配置检查：

```bash
java -jar dist/jiuzhang-api-security.jar --check-config config.local.properties
```

## 只读接口

```bash
curl http://127.0.0.1:19091/health
curl http://127.0.0.1:19091/metrics
curl http://127.0.0.1:19091/apis
curl http://127.0.0.1:19091/events
curl http://127.0.0.1:19091/learning
curl http://127.0.0.1:19091/policies
```

`/events` 支持 `endpoint`、`action` 和 `limit=1..200` 过滤。`/learning` 支持按 `endpoint` 查询，例如 `GET /api/list` 需要 URL 编码。

## 模型与授权配置

`schemas.location` 指向正式模型 JSON。字段使用 `body:`、`query:`、`header:`、`path:` 前缀，支持 `type`、`required`、`min_length`、`max_length`、`minimum`、`maximum` 和 `enum`。示例见 `schemas.example.json`。

授权配置从模型文件同目录的 `authz.example.json` 加载，支持 `role_baselines` 和 `ownership`。所有者关系只在明确登记后产生辅助信号；未知关系不会被当成越权结论。

## 60 页源码材料

`dist/九章API安全系统.pdf` 为恰好 60 页，每页 50 行，按排序后的项目源码序列取前 30 页和末尾 30 页。HTML 可检索版本与 SHA-256 清单位于同一目录，中间省略范围在清单中标注。

重新生成：

```bash
python3 -m venv .venv-source-book
.venv-source-book/bin/pip install --requirement tools/requirements-source-book.txt
.venv-source-book/bin/python tools/render_source_book.py
.venv-source-book/bin/python tools/render_source_book.py --check
```

默认排版字体使用仓库已有 Noto CJK TTF，可通过 `--font` 指定其他可嵌入 Unicode TTF。
