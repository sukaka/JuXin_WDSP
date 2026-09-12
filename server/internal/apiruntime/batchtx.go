// batchtx.go W22 采集器事务批量化：每个 flush 批次一个 DB 事务（pgx.Tx）。
//
// 背景（docs/evidence/api-security-performance-baseline.md §11.8）：入库瓶颈在
// 逐行 SavePrimary 幂等插入 + handleRecord 逐行副作用（发现 upsert 自带单行事务、
// 样本落库自带单行事务、流量桶/违例/findings/观测逐语句 autocommit），每行多次
// commit（fsync）实测 ~300 行/s。本文件把「上次 flush 之后、本次 flush 之前」的
// 批次窗口内全部写入并入一个 DB 事务，整批一次 COMMIT：
//
//   - 事务边界：批次窗口首条业务记录懒开启（beginBatch），flush 时 COMMIT；
//     COMMIT 成功才前移断点——断点与持久化数据严格同节奏（比 autocommit 更强：
//     副作用与主事件原子可见，不再有「副作用已提交、主事件未落」的中间态）。
//   - 失败语义：SavePrimary/Commit 任一失败 → 整体 Rollback，断点不前移，
//     下轮从断点重放；重放安全由各幂等键兜底（request_id WHERE NOT EXISTS、
//     各 ON CONFLICT/upsert），与 autocommit 路径纪律一致。
//   - 副作用错误纪律：handleRecord 各副作用「错误仅记日志、不中断采集」在事务内
//     由记录级 SAVEPOINT 保持（PG 失败语句会令全事务 aborted，必须 ROLLBACK TO
//     恢复）；失败记录的副作用按记录原子回滚——这是对 autocommit 错误容忍路径的
//     收紧（原语义下失败前已写的副作用留存，现同记录副作用同生同灭），
//     错误仍逐条 slog.Error，不静默吞错。
//   - 未接线（SetBatchTxFactory 未调用）时保持逐语句 autocommit，行为与 W20 完全一致。
//
// 计数口径：savedCount 在 COMMIT 成功后按批次计入（autocommit 路径按语句计入；
// 批次回滚时不计数，比旧口径更贴近「已持久化」语义）。
package apiruntime

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apillm"
)

// BatchTxFactory 开启一个批次事务（装配层以 db.Begin 接线；pgx.Tx 同时满足
// 提交/回滚与各 Store 的 DBTX 查询接口）。
type BatchTxFactory func(ctx context.Context) (pgx.Tx, error)

// recordSavepoint 批次事务内包裹单条记录副作用的子事务名（固定复用，
// RELEASE 后子事务销毁，逐记录重新建立）。
const recordSavepoint = "apiruntime_rec"

// SetBatchTxFactory 设置批次事务工厂（应用装配时使用；未设置时保持 autocommit，
// 采集行为与 W20 完全一致）。factory 返回的事务必须来自与各 Store 同一个数据库。
func (c *Collector) SetBatchTxFactory(f BatchTxFactory) { c.batchTxFactory = f }

// recorderSnapshot 批次事务开启前的 recorder 引用快照（flush 提交/回滚后恢复，
// 保证 collector 跨批次复用时 autocommit 装配引用不被污染）。
type recorderSnapshot struct {
	saver       PrimarySaver
	discovery   DiscoveryUpserter
	samples     SampleRecorder
	violations  ViolationSaver
	findings    FindingSaver
	paramObs    ParamObsRecorder
	respSchemas RespSchemaRecorder
	fileObs     FileObsRecorder
	llmObs      apillm.ObsRecorder
	traffic     TrafficRecorder
}

// enterBatchTx 快照当前 recorders 并切换为 tx 作用域浅拷贝（WithDB）。
// 不支持 WithDB 的 recorder（单测内存假实现等）原样保留——其写入维持 autocommit，
// 幂等键兜底使其在批次回滚重放下仍安全（仅失去该 recorder 的批次原子性，语义不退化）。
func (c *Collector) enterBatchTx(tx pgx.Tx) *recorderSnapshot {
	snap := &recorderSnapshot{
		saver: c.saver, discovery: c.discovery, samples: c.samples,
		violations: c.violations, findings: c.findings, paramObs: c.paramObs,
		respSchemas: c.respSchemas, fileObs: c.fileObs, llmObs: c.llmObs, traffic: c.traffic,
	}
	c.saver = scopedPrimarySaver(c.saver, tx)
	c.discovery = scopedDiscovery(c.discovery, tx)
	c.samples = scopedSamples(c.samples, tx)
	c.violations = scopedViolations(c.violations, tx)
	c.findings = scopedFindings(c.findings, tx)
	c.paramObs = scopedParamObs(c.paramObs, tx)
	c.respSchemas = scopedRespSchemas(c.respSchemas, tx)
	c.fileObs = scopedFileObs(c.fileObs, tx)
	c.llmObs = scopedLLMObs(c.llmObs, tx)
	c.traffic = scopedTraffic(c.traffic, tx)
	return snap
}

// exitBatchTx 恢复快照中的 recorder 引用。
func (c *Collector) exitBatchTx(snap *recorderSnapshot) {
	c.saver, c.discovery, c.samples = snap.saver, snap.discovery, snap.samples
	c.violations, c.findings, c.paramObs = snap.violations, snap.findings, snap.paramObs
	c.respSchemas, c.fileObs, c.llmObs = snap.respSchemas, snap.fileObs, snap.llmObs
	c.traffic = snap.traffic
}

// handleRecordInTx 在批次事务内处理一条记录的副作用（记录级 SAVEPOINT 包裹）。
// 副作用失败仅回滚本记录已写副作用并记日志，事务恢复后继续后续记录；
// 主事件不受影响（pending 由 flush 在同一事务保存，与「副作用失败不阻断主事件」一致）。
func (c *Collector) handleRecordInTx(ctx context.Context, tx pgx.Tx, rec *Record) {
	if _, err := tx.Exec(ctx, "SAVEPOINT "+recordSavepoint); err != nil {
		// 事务本身已不可用（连接断开等）：仍走一遍 handleRecord 让各副作用错误
		// 逐条记日志（不静默）；flush 的 SavePrimary/Commit 会如实失败并回滚。
		slog.Error("batch tx savepoint failed",
			"collector", c.collectorID, "request_id", rec.RequestID, "error", err)
		c.handleRecord(ctx, rec)
		return
	}
	c.handleRecord(ctx, rec)
	if _, err := tx.Exec(ctx, "RELEASE SAVEPOINT "+recordSavepoint); err != nil {
		// 本记录某条副作用语句失败（具体错误已在内层 slog.Error）：回滚到记录级
		// 子事务恢复事务状态，RELEASE 销毁子事务（ROLLBACK TO 后 RELEASE 不回撤销回滚）。
		if _, rerr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+recordSavepoint); rerr != nil {
			slog.Error("rollback record savepoint failed",
				"collector", c.collectorID, "request_id", rec.RequestID, "error", rerr)
		}
		if _, rerr := tx.Exec(ctx, "RELEASE SAVEPOINT "+recordSavepoint); rerr != nil {
			slog.Error("release record savepoint failed",
				"collector", c.collectorID, "request_id", rec.RequestID, "error", rerr)
		}
		slog.Warn("record side effects rolled back to savepoint in batch tx",
			"collector", c.collectorID, "request_id", rec.RequestID, "endpoint_key", rec.EndpointKey)
	}
}

// scopedXxx 把采集链路 recorder 切换为 tx 作用域浅拷贝；recorder 未实现对应
// WithDB 时原样返回（见 enterBatchTx 注释）。各包 DBTX 形参类型不同，pgx.Tx
// 在结构上全部满足。

func scopedPrimarySaver(s PrimarySaver, tx pgx.Tx) PrimarySaver {
	if w, ok := s.(interface{ WithDB(DBTX) *Store }); ok {
		return w.WithDB(tx)
	}
	return s
}

func scopedViolations(s ViolationSaver, tx pgx.Tx) ViolationSaver {
	if w, ok := s.(interface{ WithDB(DBTX) *Store }); ok {
		return w.WithDB(tx)
	}
	return s
}

func scopedFindings(s FindingSaver, tx pgx.Tx) FindingSaver {
	if w, ok := s.(interface{ WithDB(DBTX) *Store }); ok {
		return w.WithDB(tx)
	}
	return s
}

func scopedParamObs(r ParamObsRecorder, tx pgx.Tx) ParamObsRecorder {
	if w, ok := r.(interface{ WithDB(DBTX) *ParamObsStore }); ok {
		return w.WithDB(tx)
	}
	return r
}

func scopedRespSchemas(r RespSchemaRecorder, tx pgx.Tx) RespSchemaRecorder {
	if w, ok := r.(interface{ WithDB(DBTX) *RespSchemaStore }); ok {
		return w.WithDB(tx)
	}
	return r
}

func scopedFileObs(r FileObsRecorder, tx pgx.Tx) FileObsRecorder {
	if w, ok := r.(interface{ WithDB(DBTX) *FileObsStore }); ok {
		return w.WithDB(tx)
	}
	return r
}

func scopedDiscovery(u DiscoveryUpserter, tx pgx.Tx) DiscoveryUpserter {
	if w, ok := u.(interface {
		WithDB(apiassets.DBTX) *apiassets.Store
	}); ok {
		return w.WithDB(tx)
	}
	return u
}

func scopedSamples(r SampleRecorder, tx pgx.Tx) SampleRecorder {
	if w, ok := r.(interface {
		WithDB(apiassets.DBTX) *apiassets.Store
	}); ok {
		return w.WithDB(tx)
	}
	return r
}

func scopedTraffic(r TrafficRecorder, tx pgx.Tx) TrafficRecorder {
	if w, ok := r.(interface {
		WithDB(apiassets.DBTX) *apiassets.Store
	}); ok {
		return w.WithDB(tx)
	}
	return r
}

func scopedLLMObs(r apillm.ObsRecorder, tx pgx.Tx) apillm.ObsRecorder {
	if w, ok := r.(interface {
		WithDB(apillm.DBTX) *apillm.ObsStore
	}); ok {
		return w.WithDB(tx)
	}
	return r
}
