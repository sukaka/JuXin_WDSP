// dbtx.go 最小数据库句柄抽象（与 accesslogs 同构：*pgxpool.Pool 与 pgx.Tx 均满足 DBTX）。
package tlssessions

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
