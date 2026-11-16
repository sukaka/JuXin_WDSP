# 第三方组件说明

直接依赖均在 `Cargo.toml` 中使用精确版本，传递依赖及其校验值见 `Cargo.lock`。

| 组件 | 版本 | 常用许可证标识 |
|---|---:|---|
| axum | 0.8.4 | MIT |
| chrono | 0.4.41 | MIT OR Apache-2.0 |
| clap | 4.5.41 | MIT OR Apache-2.0 |
| ipnet | 2.11.0 | MIT OR Apache-2.0 |
| percent-encoding | 2.3.1 | MIT OR Apache-2.0 |
| regex | 1.11.1 | MIT OR Apache-2.0 |
| reqwest | 0.12.22 | MIT OR Apache-2.0 |
| serde | 1.0.219 | MIT OR Apache-2.0 |
| serde_json | 1.0.140 | MIT OR Apache-2.0 |
| thiserror | 2.0.12 | MIT OR Apache-2.0 |
| tokio | 1.47.1 | MIT |
| toml | 0.8.23 | MIT OR Apache-2.0 |
| tracing | 0.1.41 | MIT |
| tracing-subscriber | 0.3.19 | MIT |
| uuid | 1.17.0 | MIT OR Apache-2.0 |
| tempfile（仅测试） | 3.20.0 | MIT OR Apache-2.0 |

本表用于记录直接依赖，不替代完整依赖许可证审计。交付前应使用 Cargo 元数据和实际依赖包中的许可证文本生成完整 notices；如升级任何版本，必须同步更新锁文件和本表。

## 源码材料排版工具

排版工具仅用于生成离线 PDF/HTML，不是 WAF 运行时依赖。Python 工具的完整直接及传递依赖版本锁定在 `tools/requirements-source-book.txt`。

| 组件 | 版本 | 许可证标识 |
|---|---:|---|
| reportlab | 4.2.5 | BSD-3-Clause |
| pypdf | 5.1.0 | BSD-3-Clause |
| fonttools | 4.59.2 | MIT |
| pillow | 11.3.0 | MIT-CMU |
| chardet | 5.2.0 | LGPL-2.1-or-later |
| typing_extensions | 4.16.0 | PSF-2.0 |

PDF 使用项目已有的 Noto Sans CJK SC 字体并嵌入所需字形，字体授权为 SIL Open Font License 1.1。chardet 由 reportlab 的依赖关系引入，仅用于本地文档工具；其 LGPL 授权不应用于改写 WAF 运行代码。正式分发排版工具或字体文件时，应同时附上对应许可证文本。
