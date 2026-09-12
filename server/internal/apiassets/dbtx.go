// dbtx.go 最小数据库句柄抽象（W22 采集器事务批量化）。
// *pgxpool.Pool 与 pgx.Tx 均满足 DBTX：Store 默认绑定连接池（逐语句 autocommit），
// 采集器批次事务窗口内经 WithDB 浅拷贝切换到事务句柄，把整批写入并入同一个
// DB 事务（提交权归外层批次事务），消除逐语句 commit 开销。
package apiassets

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX 仓储方法依赖的最小查询接口（Exec/Query/QueryRow）。
// 刻意不含 Begin：pgx.Tx 不支持嵌套开启事务，自管理事务的方法走 Store.pool。
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}
