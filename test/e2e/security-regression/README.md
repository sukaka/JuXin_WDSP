# 安全回归管理界面 E2E（P1-04 R4a）

真实 stage5 栈 + 真实签名证据的页面级 E2E，不 mock。

## 运行

```bash
bash test/e2e/security-regression/run.sh
```

依赖：docker（compose 插件）、curl、openssl、python3、node/npx（复用 `web/` 的
Playwright 与 vite）、`tools/regsign`（预编译二进制；缺失时用本机 go 工具链
`go run` 兜底）。任一缺失如实输出 `BLOCKED/ENVIRONMENT_UNAVAILABLE`。

## 流程

1. 起 `deployment/docker-compose.stage5.yml + docker-compose.wdsp.yml +
   docker-compose.test-license.yml`（每轮随机口令/密钥，CI 临时授权），
   构建当前工作树的 api/gateway 镜像。
2. `tools/regsign genkey` 生成 Ed25519 验签密钥（私钥仅存 mktemp），公钥经 psql
   播种 `system_settings security_regression:trusted_verify_keys`。
3. 构造两份回归证据（run1 全过 / run2 声明 FAIL 且强制用例失败、差异摘要含恶意
   HTML 样本），用例分块经 `POST /security/regression-objects?kind=CASES_CHUNK`
   上传（服务端计算 sha256/size），manifest 回填后 `canonicalize` + `sign`，
   再经 `POST /security/regressions/imports` 登记（服务端真实验签 + 计数对账）。
4. 启动 vite dev（5173，`/api/v1` 代理到本轮栈 18081），Playwright Chromium 跑
   `specs/regression-console.spec.ts`：
   - 链路1：列表（门禁策略卡 OFF 明示、可用性预判）→ run1 详情（可用于发布）
     → 用例差异（无差异如实标注）→ run2 详情（不可用 + 逐项理由/恢复动作）
     → 用例差异（status=FAIL 服务端过滤、丢失检测/新增误报分类、恶意样本纯文本
     不产生可执行标记）→ 配置发布页 OFF 门禁状态。
   - 链路2：API 置 ENFORCE（乐观锁 + 审计理由）→ 发布页显示 ENFORCE →
     UI 发起真实发布 → `REGRESSION_GATE_REJECTED` → 缺失项原文展示 →
     按候选指纹深链回列表（如实空态）。

## 证据

每轮输出到 `runs/<run_id>/`：`playwright.json`、`status.json`、
`run1/run2-import-resp.json`、`vite-dev.log`；失败时附 `stack-dump/`。
词表 PASS / FAIL / BLOCKED / NOT_RUN 与 `test/e2e/bot-challenge` 一致。
