// dbtx.go 最小数据库句柄抽象（W22 采集器事务批量化）。
// *pgxpool.Pool 与 pgx.Tx 均满足 DBTX：Store 默认绑定连接池（逐行 autocommit），
// 采集器批次事务窗口内经 WithDB 浅拷贝切换到该批次的 pgx.Tx，把整批行插入
// 与失败队列写入并入同一个 DB 事务（与 apiruntime 采集器同一手法）。
package accesslogs

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX 仓储方法依赖的最小查询接口（Exec/Query/QueryRow）。
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
