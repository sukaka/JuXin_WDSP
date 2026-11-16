# 第三方组件说明

## 运行时

Java 主程序仅使用 JDK 21 标准模块，没有 Maven/npm 依赖，也不包含原 Go 系统或 Rust WAF 的依赖。部署时需要自行核验所选 JDK 发行版的许可证与更新策略。

## 离线源码排版工具

PDF/HTML 排版工具使用 reportlab 4.2.5、pypdf 5.1.0、fonttools 4.59.2 及其锁定依赖，完整版本见 `tools/requirements-source-book.txt`。这些 Python 组件不参与 JAR 构建或运行。

PDF 嵌入项目已有 Noto Sans CJK SC 字体的所需字形，字体授权为 SIL Open Font License 1.1。分发独立排版环境时，应保留各组件及字体的许可证文本。
