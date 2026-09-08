# WDSP 离线交付保护 S1（IP-01 / IP-02）

## 状态与范围

本阶段交付 IP-01（可审查的最小交付清单）和 IP-02（构建侧离线内容扫描与签名绑定），并把 IP-05 的正式签名门禁接入构建路径。实现只影响离线包构建、构建侧扫描器、安装/升级前置验签、扫描测试和本说明，不改变运行时服务的请求处理顺序。

交付清单是 `ops/offline-package/allowlist.v1`，采用版本化、逐文件的 allowlist 格式。构建脚本只复制清单中的运行时安装、升级、恢复、健康检查和诊断脚本；不再递归复制整个 `ops/`。离线构建器、发布公钥、patch 构建器、测试目录、开发目录、源码映射和凭据不属于交付清单。

## 构建门禁

`ops/offline-package/scan.py` 只使用 Python 标准库，属于构建机工具，不复制到客户包，也不是客户侧运行时依赖。扫描器不执行被扫描文件，不解压到宿主机；目录、tar/zip 及可识别的嵌套归档都在受限内存流中检查。

扫描规则覆盖：

- allowlist 缺失、额外文件、符号链接和清单语法错误；
- tar/zip 路径穿越、符号链接/硬链接逃逸；
- 嵌套归档、镜像归档中的历史层内容；
- Go/TypeScript/调试产物、开发目录、JavaScript source map、`sourceMappingURL`、`sourcesContent`；
- AWS 风格访问密钥、私钥和配置中的疑似凭据；
- 不支持的归档格式、解析失败、归档深度/数量/成员大小/总扫描量和超时预算。

任何发现、解析失败、能力不足或预算不足都会生成 `REJECT` 报告并以非零退出；报告输出失败同样非零。诊断输出只包含规则和位置，不打印匹配到的敏感值。

## 摘要与签名绑定

构建顺序固定为：

1. 按 `allowlist.v1` 复制文件并把 allowlist SHA-256 写入 `manifest.json`；
2. 生成 manifest，其中包含 `files_manifest_sha256` 和 `security_scan` 的构建侧声明；
3. 扫描未压缩包目录，要求报告 PASS、allowlist 名称和 allowlist 摘要匹配，并记录 manifest 内容摘要；
4. 生成正式 tar.gz；
5. 再扫描最终归档，递归覆盖其中的镜像/历史层/嵌套归档，要求 allowlist 摘要、manifest 内容摘要和 `files_manifest_sha256` 与目录扫描报告一致；
6. 将最终归档摘要与扫描报告的 `input.sha256` 比较；
7. 仅在上述门禁通过后执行正式 Ed25519 签名；签名完成后再次计算归档摘要，变化即拒绝交付。

裸机网关子包也在其自身 Ed25519 签名之前完成同一构建侧扫描和摘要复核。

因此扫描报告绑定的是签名对象本身，而不是一个可被替换的临时目录。报告作为输出目录中的旁车 JSON 保存；归档本体的旁车 `.sha256`、`.sig` 及 traceability sidecar 仍遵循既有安装流程。构建脚本只有显式 `--development` 才允许无签名密钥的本地包；正式模式缺少 `WDSP_SIGNING_KEY` 直接失败，安装端对未签包默认拒绝。

## 验证记录

在当前 dirty worktree 执行并通过：

```text
python3 -m unittest discover -s test/offline-package -p 'test_*.py' -v
```

7 项测试覆盖：恶意嵌套归档/source map、假凭据脱敏、路径穿越、符号链接逃逸、不支持格式、成员预算、超时、allowlist 额外文件、摘要报告和构建顺序。

```text
bash -n ops/offline-package/build.sh
python3 -m py_compile ops/offline-package/scan.py
bash ops/offline-package/build.sh --version 1.0.0 --product wdsp --arch amd64 --skip-images --output /tmp/wdsp-ip-build-out
```

开发模式构建成功，最终扫描报告为 `PASS`，扫描覆盖 2 个归档、748 个归档成员，且 allowlist/manifest/归档摘要校验通过。

签名门禁与 fail-closed 回归：

```text
bash test/wdsp-ip/offline-delivery-gates.sh
bash test/wdsp-ip/signed-delivery-gates.sh
```

两者均通过：前者验证正式模式缺少签名密钥时拒绝、开发模式必须显式声明并留下 traceability；后者使用每次测试临时生成的 Ed25519 密钥验证签名、扫描报告、manifest 和 sidecar 摘要绑定。临时密钥不是厂家生产信任根，因此不能替代正式发布证据。

## 剩余边界

- 扫描器对未知或未实现的归档格式采取拒绝策略；当前支持 tar/zip 及嵌套内容，不依赖外部 `zstd`/镜像解析器。`.tar.zst` 等格式会因能力不足拒绝，而不是假设“没有发现”。
- 当前构建验证使用 `--skip-images`，未在本环境执行需本地镜像缓存的多架构镜像构建；镜像归档文件一旦出现在包内仍会被递归扫描。
- 未提供真实 `WDSP_SIGNING_KEY`，所以没有生成可进入正式渠道的生产签名包；仓库只保留发布公钥和机制测试用临时密钥。
- 尚未在 amd64/arm64 完整镜像输入、裸机安装、在线升级和恢复流程上完成逐项回归；对应 AT 项保持 `NOT_RUN` 或 `BLOCKED`。
- 扫描器是构建期门禁，不替代客户主机上的签名、整包摘要和 manifest 校验；客户侧仍按既有安装脚本的 fail-closed 逻辑执行。
- 规则文件中合法的 shell 变量引用会被排除为凭据，但疑似硬编码秘密仍拒绝；如第三方内容需要例外，必须修改版本化策略并补充测试，不能通过关闭扫描绕过。
