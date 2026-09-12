# 前端任务：<task-id>

## 目标

用一句话描述用户可见结果。

## 背景与现状

- 相关页面或组件：
- 当前问题：
- 期望行为：

## 允许修改

- `web/` 下与本任务直接相关的源码、样式和测试。

## 禁止修改

- `server/`、`gateway/`、`deployment/`、`docs/`、`.github/`、`.agent/`、`tools/`。
- Git 历史、分支、标签、提交和远端。
- `.env`、密钥、Token、证书、真实账号或其他敏感数据。
- 无关重构、依赖升级、遥测和新网络调用。

## 实现约束

- 遵循现有 React、TypeScript、Ant Design、TanStack Query 和测试模式。
- 优先复用现有组件、设计令牌和 API 类型。
- 行为变更必须补充或更新测试。
- 不得用 Mock 数据或占位接口冒充功能完成。

## 验收命令

在 `web/` 目录执行与任务相关的最小集合，并写明预期结果：

```bash
npm run typecheck
npm run lint
npm test -- --run
npm run build
```

如需 E2E，请列出具体测试文件和前置服务，不能只写“运行 E2E”。

## 完成输出

- 修改文件列表及每个文件的目的。
- 实际运行的命令和结果。
- 未解决问题、风险或需要 Codex 决策的事项。
- 不执行 `git commit` 或 `git push`。
