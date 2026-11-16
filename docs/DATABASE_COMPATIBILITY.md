# 数据库兼容性

## 当前支持矩阵

| 数据库 | 状态 | 驱动 | 说明 |
|--------|------|------|------|
| PostgreSQL 16.4 | 已支持 | `github.com/jackc/pgx/v5` | 现有默认主业务库 |
| 人大金仓 KingbaseES V8R6（PostgreSQL 兼容模式） | 适配中，尚不可用于生产 | 厂家 Gokb | 需接入正式交付驱动并完成真实实例验收 |
| 达梦 DM8 | 适配中，尚不可用于生产 | 厂家 `dm-go-driver` | 需接入正式交付驱动并完成真实实例验收 |

当前代码仅完成方言配置和 SQL 位置参数重绑定基础。`DB_DIALECT=kingbase` 或 `dameng` 在厂家驱动尚未接入的构建中会被连接层明确拒绝，不会静默回退到 PostgreSQL，也不代表已经获得国产数据库支持。

## 驱动与测试前置条件

- 金仓驱动按[厂家 Gokb 文档](https://help.kingbase.com.cn/v8/development/client-interfaces/go/go-1.html)从正式交付包获取，锁定版本并审查许可证。
- 达梦驱动按[厂家 Go 编程指南](https://eco.dameng.com/document/dm/zh-cn/pm/go-rogramming-guide.html)从正式交付包获取，锁定版本并审查许可证。
- 准备相互隔离的 KingbaseES、DM8 测试实例或测试模式；不得对现有生产库执行迁移测试、清库或重建。

## 支持声明的验收门槛

每种数据库都必须通过：空库初始化、重复迁移、up/down/up、双实例并发迁移、全量 Go 测试、全量 API 集成测试、应用接入与策略发布、正常/攻击流量及事件采集、WDSP API 安全流程、逻辑备份恢复和升级回滚。未完成真实实例验收前，状态只能标记为“适配中”。
