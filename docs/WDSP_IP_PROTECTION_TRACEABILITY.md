# WDSP 发布追溯与状态边界

本文档落实 IP-08、IP-09 的发布追溯要求，并与 `WDSP_IP_PROTECTION_ACCEPTANCE.md` 的证据状态配套使用。

截至 2026-09-07，构建脚本已生成 traceability sidecar，并把 release/build/package/scan/protection 字段写入构建输出。当前已验证的是开发包和临时签名机制；没有厂家生产签名私钥、合法授权文件或正式 tag，因此不能把本地输出标为正式发行记录。

## 1. 最小发布记录

每个可交付版本都应能从发布记录定位到以下字段：

| 字段 | 说明 |
| --- | --- |
| `release_id` | 对外可读、不可含凭据的唯一发布标识 |
| `product_line` | WAF、WDSP 或其他明确产品线 |
| `version` | 与 CHANGELOG 和 tag 对应的版本号 |
| `build_commit` | 构建使用的 Git commit |
| `artifact_digest` | 最终镜像/归档的 SHA-256 或等价摘要 |
| `scan_report_digest` | 递归交付扫描报告摘要 |
| `policy_version` | 交付 allowlist 和扫描规则版本 |
| `protection_form` | 标准离线交付或经过真实证据验证的其他保护形态 |
| `hardware_requirements` | 需要的硬件/TEE 能力；未知时不得填写为已满足 |
| `delivery_id` | 本次交付记录标识 |
| `signature_algorithm` / `key_id` | 签名算法和签名公钥标识 |

`artifact_digest`、`scan_report_digest` 和签名记录必须绑定到同一个 manifest。只存在数据库缓存、日志文本或人工截图而没有原始记录时，状态只能是待验证。

构建侧的最小可复现入口为：

```text
bash test/wdsp-ip/offline-delivery-gates.sh
bash test/wdsp-ip/signed-delivery-gates.sh
```

第一条确认正式模式没有签名能力时 fail-closed，第二条使用每次测试临时生成的 Ed25519 密钥确认归档签名、manifest、扫描报告和 traceability sidecar 的摘要绑定。临时密钥只证明实现链路，不能证明生产信任根；正式记录还必须绑定 CHANGELOG、`wdsp-vX.Y.Z` tag、发布 commit 和受控签名密钥。

## 2. 诊断包关联

`ops/diagnostics/collect.sh` 通过 `WDSP_RELEASE_ID` 接收非敏感发布标识，并在 `diagnostic-manifest.txt` 中记录它和当前仓库 commit。标识会经过字符白名单和长度限制；脚本不接受它作为路径、命令或凭据。

诊断包的边界字段为：

```text
package_scope=customer_support_allowlist
private_debug_archive=not_in_customer_package
```

这两个字段用于防止支持人员把客户包误当成含源码、source map、私有符号或内存材料的发布侧归档。

## 3. 状态不能越权推断

以下维度必须分别记录：

1. 商业授权：许可证是否存在、是否可解密、签名是否有效、是否过期、设备是否匹配；
2. 产物/许可证完整性：原始文件、manifest、摘要和签名链是否可复核；
3. 实际网关防护：当前配置是否已加载、是否处于旁路、保护能力是否可用；
4. 机密计算：是否有真实平台支持、远程证明是否有效、密钥是否按证明释放。

其中一项为 `unknown`、`unavailable`、`blocked` 或未提供证据时，不能用另一项的“有效”覆盖它。例如，许可证有效不等于 TEE 已启用，软件 fingerprint 不等于 TPM/TEE 证明，扫描通过不等于网关正在拦截攻击流量。

## 4. 证据与恢复

恢复或迁移操作必须生成可定位的审计记录，并保留原始输入摘要。失败原因应至少区分：原文件缺失、加密材料不可用、解密失败、签名失败、许可证过期、设备不匹配、产物摘要不匹配和当前平台不支持。

本机没有 TPM、TDX、SEV-SNP 或等价真实证明证据时，IP-10～IP-13 的硬件/TEE 验收状态应记录为 `BLOCKED` 或 `NOT_APPLICABLE`，并写明解锁条件；不得用 Docker 隔离、软件哈希或 Apple 平台通用安全能力替代项目要求的证据。

标准离线版可以记录 `protection_form=STANDARD_OFFLINE`，并明确 `confidential_computing=DISABLED`；这只说明产品形态和边界，不代表实际网关防护、商业授权、产物完整性和机密计算四个维度互相替代。
