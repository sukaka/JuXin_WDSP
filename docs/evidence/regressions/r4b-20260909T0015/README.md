# R4b 演练证据目录（r4b-20260909T0015）

P1-04 R4b 发布门禁与回退演练的原始证据。终验报告：../P1-04-R4B-DRILL-REPORT.md。

## 文件映射

- `pub-a-success.json` ①a 证据匹配发布 SUCCESS
- `pub-b-missing.json` / `pub-b-expired.json` ①b 缺失/过期拒绝
- `pub-c-unavailable.json` ①c 证据存储不可用 UNAVAILABLE
- `pub-fp-live.json` ② 误伤规则上线发布；`pub-fp-rejected.json` ENFORCE 拒发误报配置
- `restore-resp.json` GuardOverride 快照重放恢复
- `exempt-a-expired.json`（过期→ALLOW）/ `exempt-b-revoked.json`（撤销→BLOCK）/ `exempt-c-missing.json`（缺失→BLOCK）/ `exempt-d-incomplete.json`（不完整→BLOCK）/ `exempt-final-restore.json`
- `pub-gwdown*.json` / `pub-gwrecover.json` ③a 网关停止期发布失败与恢复重发
- `pub-node-partial.json` ③b 次要节点部分生效（主 SUCCESS）
- `pub-fp-clean.json` / `cfgver-rollback-clean.json` / `pub-run4-*.json` ②卡点清理链
- `pub-modelA-*.json` / `pub-modelB-*.json` / `policyB-rollback-resp.json` / `policies-after-*.json` / `modelA-*.json` / `modelB-*.json` ④模型门禁
- `import-*-resp.json` / `import-run*.json` 证据导入请求与响应
- `gate-decisions-export.csv`（31 行门禁决策全量）/ `runs-export.csv` / `audit-export.csv`（90 行相关操作审计）
- `audit-edge.json` EDGE-001 flake 审计行；`fp-rule.json` 误伤规则定义
- `pubkey-enrollment.json` / `seed-node.sql` / `revoke-key.sql` / `restore-key.sql` 播种与恢复脚本
- `run4-clean.log` / `run5-modelA.log` / `run6-modelB.log` / `run6b-modelB.log` 回归执行日志
