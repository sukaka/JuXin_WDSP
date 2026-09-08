// Package apiops API 域 AI 定时运营任务（P1-02 续，设计稿 docs/API_AI_OPERATIONS.md §六 Schedules）。
//
// 定位：把 API 安全域的例行运营巡检（资产梳理/Shadow 运营/弱点催办/风险摘要/涉敏概览）
// 例行化为「定时计划 + 执行记录」：计划经 cron 表达式驱动，调度器每分钟比对到期游标
// （next_run_at）触发，产物为结构化报告（report_json）+ 中文摘要（summary）。
//
// 安全边界（设计稿 §八，结构性保障而非提示词约束）：
//   - 五种内置任务全部为确定性只读查询 + 模板化摘要，只产出报告，
//     不执行任何业务变更（无自动确认/发布/封禁/状态流转代码路径）；
//   - LLM 仅经 Summarizer 小接口做语言润色（装配时可选接入现有 AI 服务）；
//     nil 或润色失败一律回退纯模板摘要——降级而非失败，AI 链路故障不影响产出；
//   - 全局开关 api_ai_ops.schedules_enabled（settings，默认关）门控调度与立即执行；
//   - 接口全部登录 + 权限点（api_ai.read / api_ai.execute，种子见迁移 000063）+ 参数校验。
//
// 模块边界：调度结构对齐 learningjobs janitor（SweepOnce 可独立单测 + ticker Run）；
// cron 为包内最小五段解析器（server/go.mod 无 robfig/cron，不新增第三方依赖）；
// 数据源为 api_endpoints / api_runtime_findings / api_weaknesses / api_sensitive_fields
// 的只读直查（任务不经过 aitools Registry——v1 无 Tool 调用，设计稿 §6.3 属主权限
// 衰减针对 Tool 驱动工作流，本包不适用；created_by 留痕计划属主）。
package apiops
