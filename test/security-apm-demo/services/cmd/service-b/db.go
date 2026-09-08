// db.go service-b 的测试库访问层：SQL 语句全部为包内常量，database/sql 参数化传值；
// DB span 用 OTel SDK 显式埋点（Client kind + db.system + db.statement 常量语句），
// 绑定值绝不写入 span 属性（与产品 SQL 指纹口径对齐：hex(MD5(db.statement))，
// 见 deployment/apm/clickhouse/002_aggregates.sql apm_sql_minutes_mv）。
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql 驱动 pgx（纯 Go，MIT）
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// 固定 SQL 语句（常量；任何外部输入只能作为 $1 绑定值，绝不拼接进语句）。
const (
	stmtSelectItem = "SELECT id, name, price_cents FROM demo_items WHERE id = $1"
	// stmtBoundedDelay 调用测试库内预定义的有界延迟函数；参数在服务端 clamp 到 [0,3.0] 秒。
	stmtBoundedDelay = "SELECT demo_sleep_bounded($1)"
	// stmtSyntheticError 调用测试库内预定义函数，抛出固定合成错误（SQLSTATE P0001）。
	stmtSyntheticError = "SELECT demo_raise_synthetic_error()"
)

var (
	tracer          = otel.Tracer("security-apm-demo/service-b")
	attrDBSystem    = attribute.String("db.system", "postgresql")
	attrDBNamespace = attribute.String("db.name", "demo")
)

type item struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	PriceCents int    `json:"price_cents"`
}

func openDemoDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	// 有界连接池：演示业务量极小，防止异常场景下连接堆积
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return db, nil
}

// withDBSpan 为一次 DB 调用建立 Client span：db.statement 只记录常量语句文本，
// 绑定值（args）仅传给 database/sql，不进入任何属性/事件。
func withDBSpan(ctx context.Context, stmt string) (context.Context, trace.Span) {
	return tracer.Start(ctx, spanName(stmt),
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrDBSystem, attrDBNamespace,
			attribute.String("db.statement", stmt)))
}

func spanName(stmt string) string {
	// 取首动词作为 span 名前缀，避免把完整语句重复进 SpanName 低基数列
	if len(stmt) >= 6 {
		return "db." + stmt[:6] + " const-stmt"
	}
	return "db.const-stmt"
}

func recordErr(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, "db call failed")
}

func queryItem(ctx context.Context, db *sql.DB, id int) (item, error) {
	var it item
	ctx, span := withDBSpan(ctx, stmtSelectItem)
	defer span.End()
	err := db.QueryRowContext(ctx, stmtSelectItem, id).Scan(&it.ID, &it.Name, &it.PriceCents)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return it, fmt.Errorf("item %d not found", id)
		}
		recordErr(span, err)
		return it, fmt.Errorf("query item: %w", err)
	}
	return it, nil
}

// execBoundedDelay 执行测试库内预定义有界延迟（seconds 由库内函数 clamp 到 [0,3.0]）。
func execBoundedDelay(ctx context.Context, db *sql.DB, seconds float64) error {
	ctx, span := withDBSpan(ctx, stmtBoundedDelay)
	defer span.End()
	if _, err := db.ExecContext(ctx, stmtBoundedDelay, seconds); err != nil {
		recordErr(span, err)
		return fmt.Errorf("bounded delay: %w", err)
	}
	return nil
}

// execSyntheticError 执行测试库内预定义函数，返回固定合成错误（真实 DB 错误路径）。
func execSyntheticError(ctx context.Context, db *sql.DB) error {
	ctx, span := withDBSpan(ctx, stmtSyntheticError)
	defer span.End()
	if _, err := db.ExecContext(ctx, stmtSyntheticError); err != nil {
		recordErr(span, err)
		return err
	}
	return errors.New("demo_raise_synthetic_error 未按预期返回错误（测试库函数缺失？）")
}
