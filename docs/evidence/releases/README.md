# 版本证据包目录说明（docs/evidence/releases/）

本目录按构建存放版本能力证据包，供 `tools/capability_evidence.py` 校验与生成报告（见 docs/tasks/wdsp-p0/P0-01_CAPABILITY_EVIDENCE.md）。

## 结构

```text
docs/evidence/releases/<build-id>/manifest.json   # 构建身份、源码快照、镜像 digest、配置指纹、测试记录
docs/evidence/releases/<build-id>/artifacts/      # 经脱敏的结果、日志及索引（manifest 中记录路径+sha256）
```

## 规则

- `<build-id>` 与 manifest 的 `build_id` 一致；同版本多次构建不得混用目录。
- 工件路径一律相对证据包根（manifest 所在目录），校验器拒绝越界 `..`、外部绝对路径、越界符号链接与远程 URL。
- 工件写入前必须脱敏：不得包含真实 Token、请求敏感正文、私钥、密码或完整业务身份声明；不要把 secret 的哈希当作脱敏。
- 较大的原始报告可留在本地离线证据包；仓库只保留可定位的索引与校验和，不默认提交海量文件。
- `draft-local/` 是任务书 §4.2 的草稿最小示例，用于工具自检；它不是任何构建的证据，`check --release` 必须拒绝它。
- 正式发布证据（S6）必须绑定干净构建输入与锁定镜像，且强制验收范围无 FAIL/BLOCKED/NOT_RUN。
