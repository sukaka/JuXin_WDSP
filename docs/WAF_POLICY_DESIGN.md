# WAF防护策略设计（阶段4）

## 策略模型

三套内置模板（不可修改/删除）+ 自定义策略。

| 策略 | 模式 | 执行等级 | 入站阈值 | 出站阈值 | 适用 |
|------|------|---------|---------|---------|------|
| relaxed 宽松 | OBSERVE | PL1 | 10 | 5 | 首次上线/复杂旧系统 |
| standard 标准 | PROTECT | PL1 | 5 | 4 | 常规生产系统 |
| strict 严格 | PROTECT | PL2 | 5 | 4 | 高安全要求（需误报测试） |

## 策略字段

模式（OFF/OBSERVE/PROTECT）、执行等级（PL1-4）、入站/出站异常阈值、请求体/响应体检查、请求体限制、JSON/XML/Multipart 解析、审计日志、阻断状态码、阻断页面。

## 防护模式

- OFF：正常代理 + 协议校验 + Request ID + 访问日志，不加载 CRS 业务检测
- OBSERVE：执行 Coraza+CRS 检测不阻断，生成 OBSERVE 事件
- PROTECT：检测 + 阈值阻断，返回九章阻断页面，生成 BLOCK 事件

## 策略绑定

- 应用通过 application_policies 绑定一个活动策略
- 策略模式优先于应用自身的 protection_mode 字段
- 发布时读取绑定策略参数（模式/PL/阈值）注入网关配置

## 策略发布

```text
应用绑定策略
  ↓
buildSnapshot 读取策略参数（GetApplicationPolicyParams）
  ↓
配置生成器注入：SecRuleEngine + 900001(paranoia_level, inbound/outbound threshold)
  ↓
发布到网关（Unix Socket）
  ↓
网关按策略模式与阈值执行
```

生成的策略参数指令：
```
SecAction "id:900001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=<PL>,setvar:tx.inbound_anomaly_score_threshold=<入站>,setvar:tx.outbound_anomaly_score_threshold=<出站>"
```

## CRS 规则管理

- 元数据同步：解析 CRS 4.28.0 规则文件 → 提取 rule_id/file/name/message/severity/phase/tags/attack_type/内容哈希 → 入库（622 条）
- 不修改 CRS 原始文件（只读挂载）
- 攻击类型从标签映射（attack-sqli/xss/rce/lfi/rfi/php/java/protocol/fixation/scanner/disclosure）
- 变更检测：内容哈希比对（新增/更新/未变/缺失）
- 规则查询：按 ID/关键词/攻击类型/风险/来源/标签筛选

## 规则覆盖

- 策略级/应用级启用停用（rule_overrides 表）
- 优先级：应用级 > 策略级 > 默认状态
- 不修改上游规则表达式

## 自定义规则

- ID 范围：7000000-7099999（九章内置）、7100000-7199999（用户自定义）
- 结构化编辑：检测变量 + 操作符 + 匹配内容 + 阶段 + 动作 + 风险 + 范围
- 白名单校验：操作符（rx/streq/contains/beginsWith/endsWith/eq/detectSQLi/detectXSS/ipMatch 等，禁止 pmFromFile）、变量（ARGS/URI/HEADERS/COOKIES/REMOTE_ADDR 等）、动作（LOG/OBSERVE/BLOCK）
- 危险内容拦截：exec/命令替换/文件读取//etc/passwd
- 正则语法预编译校验
- 安全转义生成 SecLang（防注入）

## 例外策略

- 精确例外（推荐）：应用+路径+规则+参数（ctl:ruleRemoveTargetById=942100;ARGS:content）
- 临时例外：1h/4h/1d/7d/自定义，到期自动失效（EXPIRED）
- 宽泛例外受控：对全部 SQLi/XSS/CMDi 且无具体限定 → 必须勾选风险确认（risk_acknowledged），高风险审计
- 例外 ID 段：8000000+
- 下发：启用例外生成 ctl 规则，放 CRS 规则之前（运行时例外）

## 策略版本

- 发布生成不可变版本（版本号+配置快照+哈希+业务快照）
- 回滚到历史 SUCCESS 版本
- 发布失败保持当前策略生效
