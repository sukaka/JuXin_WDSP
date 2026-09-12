# P1-04 规则/模型回归运行报告

- run 目录: `/Users/zhanglei/Documents/JiuZhang_WAF/docs/evidence/regressions/20260908T203034-c88b80`
- run_id: `20260908T203034-c88b80`
- 语料: `p1-regression-corpus-v1`（manifest.sha256 `cfdaf27c0af9c370…`）
- 回放种子: `20260908`

## 完整性检查

- ✅ 必需原始文件完整（plan/manifest/status/replay-plan/cases）

## 验收状态记录（status.json）

| ID | 状态 | 强制 | 说明 |
|---|---|---|---|
| corpus-validation | PASS | 是 | 语料 schema v1 与内容哈希一致: cfdaf27c0af9c370… |
| regression-execution | FAIL | 是 | 真实栈回放存在 FAIL 用例（明细 cases.jsonl / report.md） |
| regression-plan | PASS | 是 | 回归 run-plan 结构校验通过 |
| replay-plan | PASS | 是 | 确定性回放计划已生成（计划样本数 48） |

## 分 profile 汇总（检测/处置分离，零分母 N/A）

| Profile | 计划 | 执行 | 有效 | 缺失 | BLOCKED | NOT_RUN | 检测误报 | 拦截误报 | 检测漏报 | 拦截漏报 |
|---|---|---|---|---|---|---|---|---|---|---|
| OBSERVE | 24 | 24 | 24 | 0 | 0 | 0 | 2/9 (22.222%) | 0/9 (0.000%) | 1/13 (7.692%) | 0/1 (0.000%) |
| PROTECT | 24 | 24 | 24 | 0 | 0 | 0 | 1/9 (11.111%) | 1/9 (11.111%) | 1/13 (7.692%) | 1/13 (7.692%) |

说明：分母=适用且实际执行有效且 truth≠UNKNOWN 的样本；OBSERVE 下正确放行攻击不计拦截漏报；UNKNOWN/deferred/执行无效均排除出分母并单列计数。

## 逐例结果

| case_id | profile | truth | criticality | partition | 状态 | 原因 |
|---|---|---|---|---|---|---|
| BOT-ATK-FORGE-001 | OBSERVE | ATTACK | STANDARD | VALIDATION | PASS | - |
| BOT-ATK-FORGE-001 | PROTECT | ATTACK | STANDARD | VALIDATION | PASS | - |
| BOT-ATK-WAFSTILL-001 | OBSERVE | ATTACK | STANDARD | VALIDATION | PASS | - |
| BOT-ATK-WAFSTILL-001 | PROTECT | ATTACK | STANDARD | VALIDATION | PASS | - |
| BOT-BEN-INELIG-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | PASS | - |
| BOT-BEN-INELIG-001 | PROTECT | BENIGN | MANDATORY | TRAIN | PASS | - |
| BOT-BEN-NAV-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | FAIL | EXPECTATION_MISMATCH: 正常样本被误报检测（module='bot' family='challenge'）；EXPECTATION_MISMATCH: 最终动作不符（期望 PASS，实际 DETECT_PASS） |
| BOT-BEN-NAV-001 | PROTECT | BENIGN | MANDATORY | TRAIN | PASS | - |
| BOT-UNK-SCRIPT-001 | OBSERVE | UNKNOWN | STANDARD | VALIDATION | PASS | - |
| BOT-UNK-SCRIPT-001 | PROTECT | UNKNOWN | STANDARD | VALIDATION | PASS | - |
| BOT-UNK-TOMB-001 | OBSERVE | UNKNOWN | STANDARD | VALIDATION | PASS | - |
| BOT-UNK-TOMB-001 | PROTECT | UNKNOWN | STANDARD | VALIDATION | PASS | - |
| WAF-ATK-ENC-001 | OBSERVE | ATTACK | STANDARD | HOLDOUT | PASS | - |
| WAF-ATK-ENC-001 | PROTECT | ATTACK | STANDARD | HOLDOUT | PASS | - |
| WAF-ATK-PATH-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 规则族不符（期望 path_traversal，实际 'protocol'） |
| WAF-ATK-PATH-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 规则族不符（期望 path_traversal，实际 None） |
| WAF-ATK-PROTO-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | PASS | - |
| WAF-ATK-PROTO-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 规则族不符（期望 protocol，实际 None） |
| WAF-ATK-RCE-001 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | PASS | - |
| WAF-ATK-RCE-001 | PROTECT | ATTACK | MANDATORY | HOLDOUT | PASS | - |
| WAF-ATK-SQLI-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | PASS | - |
| WAF-ATK-SQLI-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 规则族不符（期望 sqli，实际 'protocol'） |
| WAF-ATK-SQLI-002 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | PASS | - |
| WAF-ATK-SQLI-002 | PROTECT | ATTACK | MANDATORY | HOLDOUT | PASS | - |
| WAF-ATK-SSRF-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 检出模块不符（期望 custom_pack，实际 'coraza_crs'）——HTTP 结果或无关模块命中不能冒充目标模块正确检测 |
| WAF-ATK-SSRF-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 检出模块不符（期望 custom_pack，实际 'coraza_crs'）——HTTP 结果或无关模块命中不能冒充目标模块正确检测 |
| WAF-ATK-SSTI-001 | OBSERVE | ATTACK | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 检出模块不符（期望 custom_pack，实际 'coraza_crs'）——HTTP 结果或无关模块命中不能冒充目标模块正确检测 |
| WAF-ATK-SSTI-001 | PROTECT | ATTACK | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 检出模块不符（期望 custom_pack，实际 'coraza_crs'）——HTTP 结果或无关模块命中不能冒充目标模块正确检测 |
| WAF-ATK-WEBSHELL-001 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 检出模块不符（期望 custom_pack，实际 'coraza_crs'）——HTTP 结果或无关模块命中不能冒充目标模块正确检测 |
| WAF-ATK-WEBSHELL-001 | PROTECT | ATTACK | MANDATORY | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 检出模块不符（期望 custom_pack，实际 'coraza_crs'）——HTTP 结果或无关模块命中不能冒充目标模块正确检测 |
| WAF-ATK-XSS-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | PASS | - |
| WAF-ATK-XSS-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | PASS | - |
| WAF-ATK-XXE-001 | OBSERVE | ATTACK | STANDARD | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-XXE-001 | PROTECT | ATTACK | STANDARD | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 BLOCK_403，实际 PASS）；EXPECTATION_MISMATCH: 源站到达性不符（期望 not_reached，实际 reached） |
| WAF-BEN-EDGE-001 | OBSERVE | BENIGN | MANDATORY | VALIDATION | PASS | - |
| WAF-BEN-EDGE-001 | PROTECT | BENIGN | MANDATORY | VALIDATION | PASS | - |
| WAF-BEN-FORM-001 | OBSERVE | BENIGN | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 正常样本被误报检测（module='coraza_crs' family='protocol'）；EXPECTATION_MISMATCH: 最终动作不符（期望 PASS，实际 DETECT_PASS） |
| WAF-BEN-FORM-001 | PROTECT | BENIGN | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 正常样本被误报检测（module='coraza_crs' family='sqli'）；EXPECTATION_MISMATCH: 最终动作不符（期望 PASS，实际 BLOCK_403）；EXPECTATION_MISMATCH: 源站到达性不符（期望 reached，实际 not_reached）；EXPECTATION_MISMATCH: 步骤断言未满足 s2/http_status_in（status=403）；EXPECTATION_MISMATCH: 步骤断言未满足 s2/origin_marker_present（x-wdsp-origin-mark absent） |
| WAF-BEN-JSON-001 | OBSERVE | BENIGN | MANDATORY | VALIDATION | PASS | - |
| WAF-BEN-JSON-001 | PROTECT | BENIGN | MANDATORY | VALIDATION | PASS | - |
| WAF-BEN-QUERY-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | PASS | - |
| WAF-BEN-QUERY-001 | PROTECT | BENIGN | MANDATORY | TRAIN | PASS | - |
| WAF-BEN-SQL-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | PASS | - |
| WAF-BEN-SQL-001 | PROTECT | BENIGN | MANDATORY | TRAIN | PASS | - |
| WAF-BEN-UNI-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | PASS | - |
| WAF-BEN-UNI-001 | PROTECT | BENIGN | MANDATORY | TRAIN | PASS | - |
| WAF-BEN-UPLOAD-001 | OBSERVE | BENIGN | MANDATORY | HOLDOUT | PASS | - |
| WAF-BEN-UPLOAD-001 | PROTECT | BENIGN | MANDATORY | HOLDOUT | PASS | - |

## 总判定

**FAIL**
- regression-execution: FAIL（真实栈回放存在 FAIL 用例（明细 cases.jsonl / report.md））
- 存在 FAIL 用例（逐例明细见下表）
