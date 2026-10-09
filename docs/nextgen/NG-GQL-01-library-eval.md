# NG-GQL-01 GraphQL 解析库评估（S2，阶段 0 冻结稿）

> 日期：2026-10-03。依据：RD_PLAN §7.1「解析库先评估许可证、维护状态、恶意输入耗时与依赖体积，再锁版本」。
> 结论：**选用 `github.com/vektah/gqlparser/v2 @ v2.5.60`（MIT），配自建硬边界包装层（字节上限 + 词法深度/别名预扫 + 节点预算 + fragment 循环检测），不以库默认值充当资源防护。**

## 1. 候选与裁决

| 项 | vektah/gqlparser v2.5.60 | 裁决依据 |
|---|---|---|
| 许可证 | MIT（(c) 2018 Adam Scarr，LICENSE 原文已核） | 合规（Apache/MIT/BSD 白名单）；NOTICE 归档 licenses/gqlparser/ |
| 维护状态 | 最新 release v2.5.60（go 1.25），持续维护，gqlgen 同系主解析库 | 活跃可依赖 |
| 依赖体积 | 源码 2.5MB；传递依赖仅 agnivade/levenshtein、stretchr/testify（测试）、go.yaml.in/yaml/v3 | 体积小、供应链面窄 |
| 恶意输入耗时 | **库自身不提供资源上限**：validator/rules 为规范规则集（无 MaxDepth/MaxComplexity；grep 实证）；parser 为递归下降，深嵌套文档有栈放大风险；fragment 循环在规范规则层检测（NoFragmentCycles），但**成本预算（深度×宽度×列表上界）库不实现** | 必须自建包装层（见 §2），危险边界全部显式处理 |
| 生态兼容 | 标准 ast.QueryDocument/Operation API，校验/遍历设施齐全 | 适配成本低 |

## 2. 必选后的工程边界（包装层契约，NG-BASE-02 §4.2-9 资源限额与业务处置分离）

| 边界 | 初始值（RD_PLAN §14.1 隔离实验候选，非生产默认） | 实现 |
|---|---|---|
| 文档字节 | 64 KiB | 解析前硬拒（`COV_INPUT_TRUNCATED` 覆盖语义，非解析成功） |
| 词法深度 | 20 | 预扫 `selection` 嵌套（无正则、O(n) 单趟） |
| 展开选择集节点 | 10,000 | AST walk 计数（含 fragment 展开后） |
| alias | 100 | 预扫 + AST 复核 |
| HTTP JSON 数组批处理 | 10 | 传输层（本批不实现，GQL-02 成本模型并入） |
| fragment 循环/膨胀 | 循环检测 + 展开节点并入预算 | 自建（不依赖库规范规则执行序） |

## 3. 锁版本

`github.com/vektah/gqlparser/v2 v2.5.60`（go.mod require 精确版本；go.sum 摘要钉死；升级路径：docs/DEPENDENCIES.md 登记 + licenses/ NOTICE + 全量回归）。digest 查询：`go mod download -x` / `docker buildx imagetools inspect` 不适用（Go module，以 go.sum 为准）。

## 4. 黄金样本规划（NG-T-G01~G05 映射）

- GQ-N01：批准预算内正常深查询（深度≈8）与合法 fragment/变量 → 通过不误拒（本批 AST/选择层）；
- GQ-A01：fragment 自引用循环 + alias 膨胀（>100）→ 有界终止、如实 LIMIT_EXCEEDED；
- GQ-A02：单文档多 operation 未指定 operationName / 指定不存在 operation → 分别按协议错误处理（本批操作选择层）；
- GQ-A03：HTTP batch=50 → GQL-02 并入；
- GQ-U01：含未知指令/自定义标量的合法文档 → 保守上界或标未知，不误判。

## 5. 本批不实现（如实标注）

- Schema 校验与字段权重（GQL-02 成本模型输入；本批只做文档层 AST 与操作选择）；
- 可信操作文档（APQ 白名单）、订阅/WebSocket、multipart 增量结果、联邦内部调用（RD_PLAN §7.3 边界外）；
- 变量求值与默认值（成本模型阶段再做；本批仅结构化读取 variables 顶层键名——沿用 parse_graphql.go 现有口径）。
