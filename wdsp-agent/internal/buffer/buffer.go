// Package buffer 磁盘事件缓存（契约 §6 / 设计 §17 本地缓存）。
//
//   - 目录 /var/lib/wdsp-agent/buffer/，段文件 16MB 滚动；
//   - 总上限默认 512MB，超限 FIFO 删除最旧段（P1-03 起为含当前写入段的
//     严格硬上限：活动段不豁免大小/年龄淘汰，淘汰按原因计数）；
//   - 单事件最长保存 30 分钟（按段 mtime 粒度清理，含停止写入的活动段）；
//   - 断线期间写入，恢复后优先补传（Replay），整段补传成功才删段（at-least-once）；
//   - 所有上限为硬上限（设计 §68：不允许无限 Buffer）。
package buffer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 默认参数（契约 §6）。
const (
	DefaultSegmentBytes = 16 << 20 // 16MB
	DefaultMaxBytes     = 512 << 20
	DefaultMaxAge       = 30 * time.Minute
	// maxRecordBytes 单条记录上限（防御畸形）。须覆盖合法最大 HTTP 记录：
	// 请求+响应 Body 各可达 config.HardMaxBodySize（10MB），加 JSON 序列化
	// 开销取 2×10MB+1MB——否则断网期大 Body 记录被静默丢弃。
	maxRecordBytes = 21 << 20
)

// ErrDisabled 缓存关闭时写入返回此错（调用方按丢弃计数处理）。
var ErrDisabled = errors.New("buffer: 磁盘缓存已关闭")

// 淘汰/丢弃原因词表（dropped_by_reason 指标标签，P1-03 冻结）。
const (
	ReasonSizeEvict = "size_evicted" // 总字节硬上限 FIFO 淘汰（含活动段）
	ReasonAgeEvict  = "age_evicted"  // 超龄淘汰（含活动段）
	ReasonCorrupt   = "corrupt"      // 补传发现段截断/畸形，损坏尾部丢弃
)

// Stats 缓存淘汰/损坏计数快照（全部单调递增）。
type Stats struct {
	DroppedSegments map[string]int64 // 按原因淘汰的段数（size_evicted/age_evicted）
	DroppedBytes    map[string]int64 // 按原因丢弃的字节（含 corrupt 丢失的尾部字节）
	CorruptSegments int64            // 补传中发现截断/畸形的段数
}

// stats 内部计数状态（Buffer.mu 保护，与段索引同锁）。
type stats struct {
	seg     map[string]int64
	bytes   map[string]int64
	corrupt int64
}

func (s *stats) note(reason string, bytes int64) {
	if s.seg == nil {
		s.seg = make(map[string]int64)
		s.bytes = make(map[string]int64)
	}
	s.seg[reason]++
	s.bytes[reason] += bytes
}

func (s *stats) noteCorrupt(bytes int64) {
	if s.bytes == nil {
		s.seg = make(map[string]int64)
		s.bytes = make(map[string]int64)
	}
	s.corrupt++
	s.bytes[ReasonCorrupt] += bytes
}

func (s *stats) snapshot() Stats {
	out := Stats{
		DroppedSegments: make(map[string]int64, len(s.seg)),
		DroppedBytes:    make(map[string]int64, len(s.bytes)),
		CorruptSegments: s.corrupt,
	}
	for k, v := range s.seg {
		out.DroppedSegments[k] = v
	}
	for k, v := range s.bytes {
		out.DroppedBytes[k] = v
	}
	return out
}

type segment struct {
	seq     int
	size    int64
	modTime time.Time
}

// Buffer 段式磁盘缓存（并发安全）。
type Buffer struct {
	mu       sync.Mutex
	dir      string
	segBytes int64
	maxBytes int64
	maxAge   time.Duration
	enabled  bool

	segments []segment // 按 seq 升序（最旧在前）
	cur      *os.File
	total    int64
	stats    stats
}

// Open 打开（或创建）缓存目录并重建段索引；enabled=false 返回禁用态 Buffer。
func Open(dir string, segBytes, maxBytes int64, maxAge time.Duration, enabled bool) (*Buffer, error) {
	if segBytes <= 0 {
		segBytes = DefaultSegmentBytes
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	b := &Buffer{dir: dir, segBytes: segBytes, maxBytes: maxBytes, maxAge: maxAge, enabled: enabled}
	if !enabled {
		return b, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建缓存目录 %s: %w", dir, err)
	}
	if err := b.scan(); err != nil {
		return nil, err
	}
	return b, nil
}

// scan 重建段索引（启动恢复路径）。
func (b *Buffer) scan() error {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return fmt.Errorf("扫描缓存目录: %w", err)
	}
	for _, e := range entries {
		seq, ok := parseSegName(e.Name())
		if !ok {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		b.segments = append(b.segments, segment{seq: seq, size: fi.Size(), modTime: fi.ModTime()})
		b.total += fi.Size()
	}
	sort.Slice(b.segments, func(i, j int) bool { return b.segments[i].seq < b.segments[j].seq })
	b.enforceAgeLocked(time.Now())
	b.enforceSizeLocked()
	return nil
}

func parseSegName(name string) (int, bool) {
	if !strings.HasPrefix(name, "seg-") || !strings.HasSuffix(name, ".log") {
		return 0, false
	}
	n, err := strconv.Atoi(name[4 : len(name)-4])
	if err != nil {
		return 0, false
	}
	return n, true
}

func segName(seq int) string { return fmt.Sprintf("seg-%08d.log", seq) }

// Write 追加一条记录（通常为事件 JSON）。段满滚动；总字节硬上限含当前写入段。
//
// P1-03 严格限额语义（任务书 §5.3）：
//   - 写入中的当前段允许超出 segBytes 至多 maxRecordBytes（单条大记录），
//     但总量硬上限 maxBytes 必须含当前段——超限 FIFO 淘汰最旧段，活动段
//     不豁免（淘汰活动段时关闭句柄，下次写入滚新段）；
//   - 单条记录本身超过 maxBytes 直接拒绝（永远无法保留，防御配置错误）；
//   - 所有淘汰/丢弃按原因计数（Stats）。
func (b *Buffer) Write(rec []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled {
		return ErrDisabled
	}
	if len(rec) == 0 || len(rec) > maxRecordBytes {
		return fmt.Errorf("记录长度非法: %d", len(rec))
	}
	if int64(len(rec))+4 > b.maxBytes {
		return fmt.Errorf("记录超过缓存总上限: %d > %d", len(rec)+4, b.maxBytes)
	}
	if b.cur == nil || b.segments[len(b.segments)-1].size+int64(len(rec))+4 > b.segBytes {
		if err := b.rollLocked(); err != nil {
			return err
		}
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(rec)))
	if _, err := b.cur.Write(hdr[:]); err != nil {
		return fmt.Errorf("写缓存段: %w", err)
	}
	if _, err := b.cur.Write(rec); err != nil {
		return fmt.Errorf("写缓存段: %w", err)
	}
	n := int64(len(rec)) + 4
	b.segments[len(b.segments)-1].size += n
	b.segments[len(b.segments)-1].modTime = time.Now()
	b.total += n
	b.enforceSizeLocked()
	return nil
}

// rollLocked 滚动到新段。
func (b *Buffer) rollLocked() error {
	if b.cur != nil {
		_ = b.cur.Sync()
		_ = b.cur.Close()
		b.cur = nil
	}
	seq := 1
	if len(b.segments) > 0 {
		seq = b.segments[len(b.segments)-1].seq + 1
	}
	f, err := os.OpenFile(filepath.Join(b.dir, segName(seq)), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("创建缓存段: %w", err)
	}
	b.cur = f
	b.segments = append(b.segments, segment{seq: seq, modTime: time.Now()})
	return nil
}

// enforceSizeLocked 总字节超硬上限 → FIFO 淘汰最旧段（P1-03：活动段不豁免；
// 淘汰活动段时关闭句柄，下次写入滚新段。循环至总量回到上限内或缓存清空）。
func (b *Buffer) enforceSizeLocked() {
	for b.total > b.maxBytes && len(b.segments) > 0 {
		b.removeSegmentLocked(0, ReasonSizeEvict)
	}
}

// enforceAgeLocked 超龄段淘汰（P1-03：含活动段，按冻结口径与封存段同等处理——
// 活动段持续写入会刷新 modTime，只有停止写入超 maxAge 的活动段才会被淘汰）。
func (b *Buffer) enforceAgeLocked(now time.Time) {
	for len(b.segments) > 0 {
		if now.Sub(b.segments[0].modTime) < b.maxAge {
			break
		}
		b.removeSegmentLocked(0, ReasonAgeEvict)
	}
}

// removeSegmentLocked 删除索引第 i 段并按原因计数（若是最新段则关闭句柄，
// 段游标状态由下次写入滚动重建）。
func (b *Buffer) removeSegmentLocked(i int, reason string) {
	seg := b.segments[i]
	if i == len(b.segments)-1 && b.cur != nil {
		_ = b.cur.Close()
		b.cur = nil
	}
	_ = os.Remove(filepath.Join(b.dir, segName(seg.seq)))
	b.total -= seg.size
	if b.total < 0 {
		b.total = 0
	}
	b.segments = append(b.segments[:i], b.segments[i+1:]...)
	b.stats.note(reason, seg.size)
}

// Bytes 当前缓存总字节（metrics.buffer_bytes / spool_bytes）。
func (b *Buffer) Bytes() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.total
}

// Segments 当前段数。
func (b *Buffer) Segments() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.segments)
}

// OldestAge 最旧段年龄（无段为 0；metrics oldest_age）。
func (b *Buffer) OldestAge(now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.segments) == 0 {
		return 0
	}
	d := now.Sub(b.segments[0].modTime)
	if d < 0 {
		return 0
	}
	return d
}

// Stats 淘汰/损坏计数快照（metrics dropped_by_reason 的缓存侧分账）。
func (b *Buffer) Stats() Stats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats.snapshot()
}

// deleteSegmentLocked 删除已完整补传成功的段（正常路径，不计入淘汰统计）。
func (b *Buffer) deleteSegmentLocked(i int) {
	seg := b.segments[i]
	if i == len(b.segments)-1 && b.cur != nil {
		_ = b.cur.Close()
		b.cur = nil
	}
	_ = os.Remove(filepath.Join(b.dir, segName(seg.seq)))
	b.total -= seg.size
	if b.total < 0 {
		b.total = 0
	}
	b.segments = append(b.segments[:i], b.segments[i+1:]...)
}

// Replay 按从最旧到最新顺序补传：每段读出全部记录按 batchSize 分批交付 fn，
// 整段交付成功才删除该段；任一批失败即停止（保留剩余数据下次再传）。
// 返回完全补传成功的段数。
func (b *Buffer) Replay(batchSize int, fn func(batch [][]byte) error) (int, error) {
	if batchSize <= 0 {
		batchSize = 500
	}
	b.mu.Lock()
	if !b.enabled || len(b.segments) == 0 {
		b.mu.Unlock()
		return 0, nil
	}
	// 快照段列表（补传期间允许并发 Write 新段，不影响本次快照）
	segs := make([]segment, len(b.segments))
	copy(segs, b.segments)
	// 仅当本进程当前持有活动写入段时（b.cur != nil），补传与并发写入可能竞态，
	// 其尾部截断属正常（未删段下轮重读），不计损坏；其余段的截断/畸形按
	// corrupt 计数（重启恢复场景下所有段均为封存段，损坏必须可见）。
	activeSeq := -1
	if b.cur != nil && len(segs) > 0 {
		activeSeq = segs[len(segs)-1].seq
	}
	b.mu.Unlock()

	done := 0
	for _, seg := range segs {
		recs, corruptBytes, err := b.readSegment(seg.seq)
		if err != nil {
			return done, err
		}
		if corruptBytes > 0 && seg.seq != activeSeq {
			b.mu.Lock()
			b.stats.noteCorrupt(corruptBytes)
			b.mu.Unlock()
		}
		ok := true
		for i := 0; i < len(recs); i += batchSize {
			end := i + batchSize
			if end > len(recs) {
				end = len(recs)
			}
			if err := fn(recs[i:end]); err != nil {
				ok = false
				break
			}
		}
		if !ok {
			return done, nil // 发送失败：保留该段及后续段
		}
		b.mu.Lock()
		// 段可能已被清理或重写，确认仍存在再删
		if idx := b.indexOfLocked(seg.seq); idx >= 0 && b.segments[idx].size == seg.size {
			b.deleteSegmentLocked(idx)
		}
		b.mu.Unlock()
		done++
	}
	return done, nil
}

func (b *Buffer) indexOfLocked(seq int) int {
	for i, s := range b.segments {
		if s.seq == seq {
			return i
		}
	}
	return -1
}

// readSegment 读出整段记录。corruptBytes > 0 表示段尾存在截断/畸形内容
// （半条记录、非法长度头），其值为未能读出的字节数——可读前缀仍按序交付，
// 损坏尾部随段删除丢弃（调用方按 corrupt 原因计数）。
func (b *Buffer) readSegment(seq int) (recs [][]byte, corruptBytes int64, err error) {
	f, err := os.Open(filepath.Join(b.dir, segName(seq)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil
		}
		return nil, 0, fmt.Errorf("打开缓存段: %w", err)
	}
	defer f.Close()
	var lastGood int64 // 最后一条完好记录的结束偏移
	// 损坏丢弃字节 = 自最后完好记录边界起的全部字节（坏长度头/截断体均计入）。
	markCorrupt := func() {
		if fi, ferr := f.Stat(); ferr == nil && fi.Size() > lastGood {
			corruptBytes = fi.Size() - lastGood
		}
	}
	var hdr [4]byte
	for {
		nr, err := io.ReadFull(f, hdr[:])
		if err == io.EOF && nr == 0 {
			break // 干净结束于记录边界
		}
		if err != nil {
			markCorrupt() // 半个长度头（崩溃截断）
			return recs, corruptBytes, nil
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 || n > maxRecordBytes {
			markCorrupt() // 畸形长度头：其后内容不可信，整段截断
			return recs, corruptBytes, nil
		}
		rec := make([]byte, n)
		if _, err = io.ReadFull(f, rec); err != nil {
			markCorrupt() // 半条记录
			return recs, corruptBytes, nil
		}
		recs = append(recs, rec)
		lastGood += 4 + int64(n)
	}
	return recs, 0, nil
}

// UpdateLimits 热更新缓存上限与开关（策略下发路径）。
// 关闭时关闭当前写入句柄；重新开启后 Write 按需滚动新段。
func (b *Buffer) UpdateLimits(maxBytes int64, maxAge time.Duration, enabled bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if maxBytes > 0 {
		b.maxBytes = maxBytes
	}
	if maxAge > 0 {
		b.maxAge = maxAge
	}
	if b.enabled && !enabled && b.cur != nil {
		_ = b.cur.Close()
		b.cur = nil
	}
	b.enabled = enabled
	if enabled {
		b.enforceAgeLocked(time.Now())
		b.enforceSizeLocked()
	}
}

// Enforce 周期清理（超龄/超限），由上层定时调用。
func (b *Buffer) Enforce() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.enabled {
		return
	}
	b.enforceAgeLocked(time.Now())
	b.enforceSizeLocked()
}

// Close 关闭当前写入段。
func (b *Buffer) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cur != nil {
		err := b.cur.Close()
		b.cur = nil
		return err
	}
	return nil
}
