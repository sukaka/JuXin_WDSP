# Kimi CLI 前端协作流程

本目录用于 Codex 编排 Kimi CLI 完成九章 WAF 前端任务。Kimi 是受限实现者，不负责分支、版本、提交、推送或发布决策。

## 前置条件

- 本机已安装并登录 Kimi Code CLI。
- Git 工作区属于九章 WAF 仓库。
- 任务范围仅限 `web/`；跨后端、网关、部署或发布的改动由 Codex 处理。

可用以下命令检查本机能力：

```bash
kimi --version
kimi doctor
kimi provider list
```

当前 CLI 不提供 `kimi info` 命令。

## 使用流程

1. 从模板创建活动任务：

   ```bash
   cp .agent/tasks/frontend-task-template.md .agent/tasks/active/<task-id>.md
   ```

2. 补全目标、允许路径、禁止事项和可执行验收命令。
3. 从明确基线启动隔离工作树：

   ```bash
   tools/kimi-frontend.sh .agent/tasks/active/<task-id>.md origin/main
   ```

4. 查看终端输出和 `.agent/runs/<run-id>/` 中的本地记录。
5. Codex 审查工作树差异并重新执行任务书中的验收命令。
6. 只有范围和验收全部通过后，Codex 才能决定是否提交、推送和创建 PR。

`.agent/tasks/active/` 与 `.agent/runs/` 的运行内容默认不进入 Git。运行日志可能包含代码片段或本地路径，应按敏感开发数据管理。

## 环境变量

| 变量 | 用途 | 默认值 |
|------|------|--------|
| `KIMI_BASE_REF` | 未传第二个参数时使用的 Git 基线 | `HEAD` |
| `KIMI_MODEL` | 可选 Kimi 模型别名 | CLI 默认模型 |
| `KIMI_WORKTREE_PARENT` | 隔离工作树父目录 | 仓库同级隐藏目录 |

## 安全与停止条件

- 启动器固定以 `web/` 作为允许范围，不接受任务书自行扩大权限。
- 范围检查会拒绝 Kimi 修改 Git HEAD、共享 Git refs、其他工作树、`web/` 外文件，或使用相似路径和符号链接越界。
- Kimi 退出失败或范围检查失败时，工作树和本地记录都会保留，供 Codex 审查；不得直接提交。
- 需要第二轮修复时，使用 `.agent/prompts/kimi-repair-template.md` 提供明确失败证据，仍需重复范围检查和独立验收。

## 维护验证

```bash
bash -n tools/kimi-frontend.sh
bash -n tools/check-kimi-scope.sh
bash scripts/tests/kimi-frontend-harness.sh
```
