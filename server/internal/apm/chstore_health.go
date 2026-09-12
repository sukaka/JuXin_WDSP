// chstore_health.go APM 数据面健康与采集滞后读数（APM 阶段2 数据面容量/健康告警配套，
// 设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §18.1 数据质量 / §20 降级行为）。
//
// 供给两方消费（均为 duck-type 收窄接口，本包不反向依赖）：
//   - runtimehealth.ClickHouseProber：APM_CLICKHOUSE 组件探针（Ping/TracesTableExists）；
//   - systemalerts.IngestLagStatsStore：采集滞后评估（LatestIngestAt）。
//
// 纪律同 chstore.go：SQL 只出自本文件常量、withCHSettings 查询级护栏、查询全部
// 参数化无拼接；本文件不吞错——判级/降级口径归调用方（探针判 DOWN/DEGRADED，
// 告警评估读数失败中止不动既有告警）。
package apm

import (
	"context"
	"time"
)

// CHHealth ClickHouse 数据面健康/滞后读数适配器（生产包 OpenClickHouse 返回的
// CHQuerier；单测 fake）。
type CHHealth struct{ ch CHQuerier }

// NewCHHealth 创建数据面健康读数适配器。
func NewCHHealth(ch CHQuerier) *CHHealth { return &CHHealth{ch: ch} }

// Ping 数据面连通性轻探测（SELECT 1；CHQuerier 收窄抽象不含 driver.Conn.Ping，
// 轻查询等价）。行内容不消费，成败即口径。
func (h *CHHealth) Ping(ctx context.Context) error {
	rows, err := h.ch.Query(withCHSettings(ctx), "SELECT 1")
	if err != nil {
		return err
	}
	defer rows.Close()
	return rows.Err()
}

// TracesTableExists 核心表 apm.otel_traces 存在性检查（EXISTS 走元数据，不扫数据）。
func (h *CHHealth) TracesTableExists(ctx context.Context) (bool, error) {
	rows, err := h.ch.Query(withCHSettings(ctx), "EXISTS TABLE apm.otel_traces")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var n uint8
	if rows.Next() {
		if err := rows.Scan(&n); err != nil {
			return false, err
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return n == 1, nil
}

// LatestIngestAt 数据面最新遥测时间（otel_traces max(Timestamp)，UTC）；
// 表空无数据（max 为 NULL）ok=false——无数据非故障，判级口径归调用方。
// max(Timestamp) 为单列表式聚合，配合 max_execution_time 护栏与 30s 评估周期，
// 开销有界（TTL 分层保留外的数据不参与扫描）。
func (h *CHHealth) LatestIngestAt(ctx context.Context) (time.Time, bool, error) {
	rows, err := h.ch.Query(withCHSettings(ctx), "SELECT max(Timestamp) FROM apm.otel_traces")
	if err != nil {
		return time.Time{}, false, err
	}
	defer rows.Close()
	var ts *time.Time
	if rows.Next() {
		if err := rows.Scan(&ts); err != nil {
			return time.Time{}, false, err
		}
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, false, err
	}
	if ts == nil || ts.IsZero() {
		return time.Time{}, false, nil
	}
	return ts.UTC(), true, nil
}
