# P0-02 同配置安全与性能基准报告

- run 目录: `/Users/zhanglei/Documents/JiuZhang_WAF/docs/evidence/benchmarks/20260908T083935-e58633`
- run_id: `20260908T083935-e58633`
- plan_id: `plan-20260906T000000-exampl` / purpose: `BEFORE`
- 环境标识: `p0bench-dedicated-host-EXAMPLE-0001`
- 构建: `3c73774`（worktree_dirty=False）
- 压测器: `ab` 登记版本 `EXAMPLE 运行时由 run.sh 采集（ab -V / curl --version），此处为预登记预期值`；运行采集版本见 manifest（loadgen_versions）

## 完整性检查

- ✅ 计划、语料哈希与必需原始文件完整

## 七模式性能矩阵

| Profile | 重复数 | offered | completed | P50(ms) | P95(ms) | P99(ms) | 预期403/429 | 非预期错误率 |
|---|---|---|---|---|---|---|---|---|
| proxy | NOT_RUN | - | - | - | - | - | - | - |
| waf_observe | NOT_RUN | - | - | - | - | - | - | - |
| waf_protect | NOT_RUN | - | - | - | - | - | - | - |
| api_observe | NOT_RUN | - | - | - | - | - | - | - |
| api_protect | NOT_RUN | - | - | - | - | - | - | - |
| combined_observe | NOT_RUN | - | - | - | - | - | - | - |
| combined_protect | NOT_RUN | - | - | - | - | - | - | - |

说明：分位数为各重复原始样本连接后的最近秩重算（或同 bin 直方图合并），不做跨运行平均；闭环并发工具（ab）的结果不伪称固定到达率。

## 安全正确性（检测/处置分离，BENCH-05）

| Profile | 检测误报 | 拦截误报 | 检测漏报 | 拦截漏报 | TP/FP/TN/FN | 断言不符样本 |
|---|---|---|---|---|---|---|
| proxy | NOT_RUN | - | - | - | - | - |
| waf_observe | NOT_RUN | - | - | - | - | - |
| waf_protect | NOT_RUN | - | - | - | - | - |
| api_observe | NOT_RUN | - | - | - | - | - |
| api_protect | NOT_RUN | - | - | - | - | - |
| combined_observe | NOT_RUN | - | - | - | - | - |
| combined_protect | NOT_RUN | - | - | - | - | - |

说明：检测与处置分开计算；零分母显示 N/A；OBSERVE 下正确放行攻击不计拦截漏报。

## 事件可见性与完整性对账（§6.2）

NOT_RUN（无 reconciliation.json）

## 长稳与恢复（§6.3）

- 长稳: NOT_RUN（无 soak/ 记录；72 小时 combined_protect 不得以短测顶替）
- 恢复: NOT_RUN（无 recovery.json）

## 验收状态

| ID | 状态 | 强制 | 说明 |
|---|---|---|---|
| preflight | PASS | 否 | 隔离与预检通过 |

## 总判定

**PASS**
