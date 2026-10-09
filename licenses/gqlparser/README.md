# licenses/gqlparser — vektah/gqlparser 许可证归档

本目录归档 `github.com/vektah/gqlparser/v2` 的 MIT 许可证文本（LICENSE 取自
v2.5.60 模块缓存原样拷贝，(c) 2018 Adam Scarr）。

## 覆盖组件与使用位置

| 组件 | 版本 | 使用位置 | 用途 |
|------|------|----------|------|
| vektah/gqlparser/v2 | v2.5.60（go.mod 精确锁定，go.sum 钉死摘要） | `gateway/dynamic_security/gqlast/` | GraphQL 文档 AST 解析（NG-GQL-01；解析资源硬边界由本仓库自建的包装层实现，不依赖库默认值） |

传递依赖（agnivade/levenshtein、go.yaml.in/yaml/v3）的许可证见其各自归档或
docs/DEPENDENCY_LICENSES.md 登记。设计依据：docs/nextgen/NG-GQL-01-library-eval.md。
