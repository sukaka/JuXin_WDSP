// dbtx.go 最小数据库句柄抽象（W22 采集器事务批量化）。
// *pgxpool.Pool 与 pgx.Tx 均满足 DBTX：各 Store 默认绑定连接池（逐语句 autocommit），
// 采集器批次事务窗口内经 WithDB 浅拷贝切换到该批次的 pgx.Tx，把整批写入
// （主事件 + 端点发现 + 样本 + 违例 + findings + 参数/响应/文件/LLM 观测 + 流量桶）
// 并入同一个 DB 事务，消除逐语句 commit 开销（§11.8 入库瓶颈）。
package apiruntime

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX 仓储方法依赖的最小查询接口（Exec/Query/QueryRow）。
// 采集链路各 Store 无自管理事务（Begin），故可整体抽象到 DBTX。
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
