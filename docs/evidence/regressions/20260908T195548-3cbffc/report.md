# P1-04 规则/模型回归运行报告

- run 目录: `/Users/zhanglei/Documents/JiuZhang_WAF/docs/evidence/regressions/20260908T195548-3cbffc`
- run_id: `20260908T195548-3cbffc`
- 语料: `p1-regression-corpus-v1`（manifest.sha256 `cfdaf27c0af9c370…`）
- 回放种子: `20260908`

## 完整性检查

- ✅ 必需原始文件完整（plan/manifest/status/replay-plan/cases）

## 验收状态记录（status.json）

| ID | 状态 | 强制 | 说明 |
|---|---|---|---|
| corpus-validation | PASS | 是 | 语料 schema v1 与内容哈希一致: cfdaf27c0af9c370… |
| regression-execution | BLOCKED | 是 | 执行不完整（存在 BLOCKED/NOT_RUN/执行无效），不授予完整通过 |
| regression-plan | PASS | 是 | 回归 run-plan 结构校验通过 |
| replay-plan | PASS | 是 | 确定性回放计划已生成（计划样本数 48） |

## 分 profile 汇总（检测/处置分离，零分母 N/A）

| Profile | 计划 | 执行 | 有效 | 缺失 | BLOCKED | NOT_RUN | 检测误报 | 拦截误报 | 检测漏报 | 拦截漏报 |
|---|---|---|---|---|---|---|---|---|---|---|
| OBSERVE | 24 | 24 | 21 | 0 | 0 | 0 | 0/9 (0.000%) | 0/9 (0.000%) | 10/10 (100.000%) | 1/1 (100.000%) |
| PROTECT | 24 | 24 | 23 | 0 | 0 | 0 | 0/9 (0.000%) | 0/9 (0.000%) | 12/12 (100.000%) | 12/12 (100.000%) |

说明：分母=适用且实际执行有效且 truth≠UNKNOWN 的样本；OBSERVE 下正确放行攻击不计拦截漏报；UNKNOWN/deferred/执行无效均排除出分母并单列计数。

## 逐例结果

| case_id | profile | truth | criticality | partition | 状态 | 原因 |
|---|---|---|---|---|---|---|
| BOT-ATK-FORGE-001 | OBSERVE | ATTACK | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 bot 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| BOT-ATK-FORGE-001 | PROTECT | ATTACK | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 bot 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| BOT-ATK-WAFSTILL-001 | OBSERVE | ATTACK | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| BOT-ATK-WAFSTILL-001 | PROTECT | ATTACK | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| BOT-BEN-INELIG-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | PASS | - |
| BOT-BEN-INELIG-001 | PROTECT | BENIGN | MANDATORY | TRAIN | PASS | - |
| BOT-BEN-NAV-001 | OBSERVE | BENIGN | MANDATORY | TRAIN | PASS | - |
| BOT-BEN-NAV-001 | PROTECT | BENIGN | MANDATORY | TRAIN | PASS | - |
| BOT-UNK-SCRIPT-001 | OBSERVE | UNKNOWN | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 bot 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| BOT-UNK-SCRIPT-001 | PROTECT | UNKNOWN | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 bot 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| BOT-UNK-TOMB-001 | OBSERVE | UNKNOWN | STANDARD | VALIDATION | PASS | - |
| BOT-UNK-TOMB-001 | PROTECT | UNKNOWN | STANDARD | VALIDATION | PASS | - |
| WAF-ATK-ENC-001 | OBSERVE | ATTACK | STANDARD | HOLDOUT | FAIL | 执行状态 ERROR 不得默认转通过；等待结束仍缺证据按不通过处理（§5.2） |
| WAF-ATK-ENC-001 | PROTECT | ATTACK | STANDARD | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-PATH-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-PATH-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-PROTO-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-PROTO-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-RCE-001 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | FAIL | 执行状态 ERROR 不得默认转通过；等待结束仍缺证据按不通过处理（§5.2） |
| WAF-ATK-RCE-001 | PROTECT | ATTACK | MANDATORY | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-SQLI-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | FAIL | 执行状态 ERROR 不得默认转通过；等待结束仍缺证据按不通过处理（§5.2） |
| WAF-ATK-SQLI-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-SQLI-002 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-SQLI-002 | PROTECT | ATTACK | MANDATORY | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-SSRF-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-SSRF-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-SSTI-001 | OBSERVE | ATTACK | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-SSTI-001 | PROTECT | ATTACK | STANDARD | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-WEBSHELL-001 | OBSERVE | ATTACK | MANDATORY | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-WEBSHELL-001 | PROTECT | ATTACK | MANDATORY | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理） |
| WAF-ATK-XSS-001 | OBSERVE | ATTACK | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 期望模块 coraza_crs 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-XSS-001 | PROTECT | ATTACK | MANDATORY | VALIDATION | FAIL | 执行状态 ERROR 不得默认转通过；等待结束仍缺证据按不通过处理（§5.2） |
| WAF-ATK-XXE-001 | OBSERVE | ATTACK | STANDARD | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 DETECT_PASS，实际 PASS） |
| WAF-ATK-XXE-001 | PROTECT | ATTACK | STANDARD | HOLDOUT | FAIL | EXPECTATION_MISMATCH: 期望模块 custom_pack 检出但未检出；EXPECTATION_MISMATCH: 最终动作不符（期望 BLOCK_403，实际 PASS）；EXPECTATION_MISMATCH: 源站到达性不符（期望 not_reached，实际 reached） |
| WAF-BEN-EDGE-001 | OBSERVE | BENIGN | MANDATORY | VALIDATION | PASS | - |
| WAF-BEN-EDGE-001 | PROTECT | BENIGN | MANDATORY | VALIDATION | PASS | - |
| WAF-BEN-FORM-001 | OBSERVE | BENIGN | MANDATORY | VALIDATION | PASS | - |
| WAF-BEN-FORM-001 | PROTECT | BENIGN | MANDATORY | VALIDATION | FAIL | EXPECTATION_MISMATCH: 请求产生非预期错误（不得按安全通过处理）；EXPECTATION_MISMATCH: 源站到达性不符（期望 reached，实际 not_reached）；EXPECTATION_MISMATCH: 步骤断言未满足 s2/http_status_in（status=403）；EXPECTATION_MISMATCH: 步骤断言未满足 s2/origin_marker_present（x-wdsp-origin-mark absent） |
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
- regression-execution: 强制项未通过（BLOCKED：执行不完整（存在 BLOCKED/NOT_RUN/执行无效），不授予完整通过）
- 存在 FAIL 用例（逐例明细见下表）
