# WDSP 诊断包与私有调试归档契约

本文档落实 `WDSP_IP_PROTECTION_DESIGN.md` 的 IP-07 诊断、调试归档和恢复边界。它描述的是可交付的支持包契约，不把客户支持包误认为源码或私有调试归档。

## 1. 客户诊断包

入口脚本为 `ops/diagnostics/collect.sh`。脚本只采集 allowlist 内的文本信息：版本、脱敏环境配置、容器状态、有限行数的容器日志、管理 API 健康响应和磁盘摘要。所有配置、日志和健康响应都经过同一条防御性脱敏管线。

客户诊断包默认不包含：

- 私钥、会话文件、访问令牌、Cookie、密码和连接串中的口令；
- 内存转储、core dump、进程私有文件和调试符号；
- 客户请求体、响应体或完整业务 payload；
- 源码、source map、构建缓存和发布侧私有调试归档。

包内 `diagnostic-manifest.txt` 是可复核清单，至少包含：

- `policy_version=wdsp-diagnostics-v1`；
- `release_id`（由调用方通过 `WDSP_RELEASE_ID` 提供，缺省为 `unavailable`，只保留安全字符）；
- `repository_commit`；
- `package_scope=customer_support_allowlist`；
- `private_debug_archive=not_in_customer_package`；
- 每个包内文件的相对路径、字节数和 SHA-256。

清单自身不纳入自己的文件哈希列表，避免生成后自引用。脚本不上传数据；向外部支持方转交前，必须使用组织批准的加密通道，并由客户或授权运维人员明确发起。

回归证据：

```bash
bash test/wdsp-ip/diagnostics-collect.sh
```

该测试使用隔离的伪造 Docker/API 输出，验证原始口令、Bearer、Cookie、JSON token、请求/响应体和 PEM 私钥不会出现在归档中，同时验证发布标识和包边界字段存在。

## 2. 私有调试归档

私有调试归档只在受控构建环境按精确 `release_id`、Git commit、构建平台和构建产物摘要生成。它可供发布侧故障定位使用，但不进入客户离线包，也不由客户诊断脚本递归收集。归档访问应沿用发布系统的最小权限、审批和保留周期；本仓库不保存生产私钥、客户密钥或未授权上传凭据。

发布侧需要保留的关联关系是：

`release_id → commit → artifact digest → scan report digest → package manifest → delivery/signature record`

如果其中任一项缺失，支持人员只能把归档标记为“无法完成发布追溯”，不得凭文件名或时间戳推断其对应版本。

## 3. 恢复演练边界

诊断包用于定位问题，不用于恢复授权或恢复业务配置。恢复授权必须重新导入签名许可证并执行完整校验；恢复配置必须使用已审计的配置发布/回滚流程。诊断包中不存在可以绕过签名、设备绑定或权限校验的材料。

当许可证原文件缺失、密文不可解、签名失败、已过期或设备不匹配时，界面和支持记录必须分别保留这些状态，不能统一显示为“系统异常”或“授权有效”。

