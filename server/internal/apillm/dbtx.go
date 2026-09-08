// dbtx.go 最小数据库句柄抽象（W22 采集器事务批量化）。
// *pgxpool.Pool 与 pgx.Tx 均满足 DBTX：ObsStore 默认绑定连接池（逐语句 autocommit），
// 采集器批次事务窗口内经 WithDB 浅拷贝切换到该批次的 pgx.Tx，
// 观测写入并入外层批次事务（提交权归采集器，重放由 request_id 派生幂等键兜底）。
package apillm

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
