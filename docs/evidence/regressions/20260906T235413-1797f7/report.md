# P1-04 规则/模型回归运行报告

- run 目录: `/Users/zhanglei/Documents/JiuZhang_WAF/docs/evidence/regressions/20260906T235413-1797f7`
- run_id: `20260906T235413-1797f7`
- 语料: `p1-regression-corpus-v1`（manifest.sha256 `53cfe68c299c9599…`）
- 回放种子: `20260906`

## 完整性检查

- ✅ 必需原始文件完整（plan/manifest/status/replay-plan/cases）

## 验收状态记录（status.json）

| ID | 状态 | 强制 | 说明 |
|---|---|---|---|
| corpus-validation | PASS | 是 | 语料 schema v1 与内容哈希一致: 53cfe68c299c9599… |
| regression-execution | BLOCKED | 是 | ENVIRONMENT_UNAVAILABLE：S1 工具层交付，真实网关执行待隔离环境接线（P1-04 R2）；未执行任何请求（0/36），不做假 PASS |
| regression-plan | PASS | 是 | 回归 run-plan 结构校验通过 |
| replay-plan | PASS | 是 | 确定性回放计划已生成（计划样本数 36） |

## 分 profile 汇总（检测/处置分离，零分母 N/A）

| Profile | 计划 | 执行 | 有效 | 缺失 | BLOCKED | NOT_RUN | 检测误报 | 拦截误报 | 检测漏报 | 拦截漏报 |
|---|---|---|---|---|---|---|---|---|---|---|
| OBSERVE | 18 | 0 | 0 | 18 | 0 | 18 | 0/0 (N/A) | 0/0 (N/A) | 0/0 (N/A) | 0/0 (N/A) |
| PROTECT | 18 | 0 | 0 | 18 | 0 | 18 | 0/0 (N/A) | 0/0 (N/A) | 0/0 (N/A) | 0/0 (N/A) |

说明：分母=适用且实际执行有效且 truth≠UNKNOWN 的样本；OBSERVE 下正确放行攻击不计拦截漏报；UNKNOWN/deferred/执行无效均排除出分母并单列计数。

## 逐例结果

| case_id | profile | truth | criticality | partition | 状态 | 原因 |
|---|---|---|---|---|---|---|
| WAF-ATK-ENC-001 | OBSERVE | ATTACK | STANDARD | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-ENC-001 | PROTECT | ATTACK | STANDARD | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-PATH-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-PATH-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-PROTO-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-PROTO-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-RCE-001 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-RCE-001 | PROTECT | ATTACK | MANDATORY | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-SQLI-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-SQLI-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-SQLI-002 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-SQLI-002 | PROTECT | ATTACK | MANDATORY | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-SSRF-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-SSRF-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-SSTI-001 | OBSERVE | ATTACK | STANDARD | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-SSTI-001 | PROTECT | ATTACK | STANDARD | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-WEBSHELL-001 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-WEBSHELL-001 | PROTECT | ATTACK | MANDATORY | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-XSS-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-XSS-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-XXE-001 | OBSERVE | ATTACK | STANDARD | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-ATK-XXE-001 | PROTECT | ATTACK | STANDARD | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-EDGE-001 | OBSERVE | BENIGN | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-EDGE-001 | PROTECT | BENIGN | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-FORM-001 | OBSERVE | BENIGN | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-FORM-001 | PROTECT | BENIGN | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-JSON-001 | OBSERVE | BENIGN | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-JSON-001 | PROTECT | BENIGN | MANDATORY | VALIDATION | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-QUERY-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-QUERY-001 | PROTECT | BENIGN | MANDATORY | TRAIN | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-SQL-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-SQL-001 | PROTECT | BENIGN | MANDATORY | TRAIN | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-UNI-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-UNI-001 | PROTECT | BENIGN | MANDATORY | TRAIN | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-UPLOAD-001 | OBSERVE | BENIGN | MANDATORY | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |
| WAF-BEN-UPLOAD-001 | PROTECT | BENIGN | MANDATORY | HOLDOUT | NOT_RUN | NOT_ATTEMPTED: 执行层未运行（隔离环境不可用时保持 NOT_RUN，不造假） |

## 总判定

**NOT_PASSED**
- regression-execution: 强制项未通过（BLOCKED：ENVIRONMENT_UNAVAILABLE：S1 工具层交付，真实网关执行待隔离环境接线（P1-04 R2）；未执行任何请求（0/36），不做假 PASS）
- 执行数量不足：计划 36，实际执行 0
