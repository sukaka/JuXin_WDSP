# 高危漏洞发现登记表（VULN_KNOWN_HIGH）

本表登记交付物漏洞扫描发现的**高危/严重（HIGH/CRITICAL）且尚未修复**的问题，是交付检查项
`vulnerability_scan`（server/internal/delivery/checks.go）的数据源。

## 扫描流程（交付前必须执行）

1. `scripts/generate-sbom.sh` 重新生成 `docs/SBOM.spdx.json` / `docs/SBOM.cyclonedx.json`；
2. 以 SBOM 为输入执行依赖漏洞扫描（如 govulncheck / trivy / osv-scanner，扫描工具不随仓库分发，由交付环境提供）；
3. `scripts/license-audit.sh` 复核许可证合规（GPL/AGPL/SSPL 红线）；
4. 将扫描结论登记到本表并更新本文件（登记文件的更新时间即扫描时效依据，超过 90 天交付检查判 WARNING）。

## 登记约定

- 每条未修复发现占一行，格式为任务列表项：行首 `- [ ]`，内容含 CVE/GHSA 编号、受影响组件与版本、处置说明；
- 修复并复扫确认后将该行标记改为 `- [x]`（保留记录备查）；
- 交付检查语义：存在任意 `- [ ]` 行 → FAIL（关键项，阻止正式交付）；无 `- [ ]` 行 → PASS；本文件缺失或超过 90 天未更新 → WARNING。

## 当前登记

当前无未修复的高危/严重漏洞发现。

### 已修复归档

（暂无）
