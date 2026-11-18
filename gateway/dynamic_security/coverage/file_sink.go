// file_sink.go 执行覆盖观测文件落地（NG-COV-01 摄入段网关侧出口）：
// 把一批 Observation 以每行一个 JSON 追加写入 <dir>/coverage-observations.jsonl，
// 由 server 侧 coverage 采集器断点续传入库（与 identity-events.log 同一通道形态）。
//
// 语义与纪律：
//   - 单写调用非阻塞语义：仅磁盘 append，无网络、无回调请求路径；
//     写入失败只记丢弃计数（Dropped）与日志，绝不 panic/阻断 Emitter 消费 goroutine；
//   - 文件名/目录经 NewFileSink(dir) 注入（装配默认 /var/log/caddy，测试用临时目录）；
//   - 目录不存在时创建（0o755）；写入加进程内互斥锁（本进程内唯一写者，
//     跨进程追加由 O_APPEND 保证行内顺序，行不交错的前提是单行一次 write 调用）；
//   - 单条记录 json.Marshal 一次、单行一次 Write（JSON 不含内嵌换行，保证一行一记录）。
package coverage

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// FileSinkName 固定输出文件名（server 采集侧与 logrotator 轮转清单共用此名）。
const FileSinkName = "coverage-observations.jsonl"

// FileSink 是落盘 Sink：JSONL 追加写固定文件。
type FileSink struct {
	path    string
	mu      sync.Mutex
	f       *os.File
	dropped atomic.Uint64
}

// NewFileSink 创建文件 Sink。dir 为空时回退默认 /var/log/caddy（装配默认；
// 测试务必传 t.TempDir()，避免污染真实日志目录）。
func NewFileSink(dir string) *FileSink {
	if dir == "" {
		dir = "/var/log/caddy"
	}
	return &FileSink{path: filepath.Join(dir, FileSinkName)}
}

// Path 实际输出文件绝对/相对路径（装配与诊断用）。
func (s *FileSink) Path() string { return s.path }

// Dropped 累计写失败丢弃的观测条数（打开/写入失败均计入，与 Emitter.Dropped 同口径）。
func (s *FileSink) Dropped() uint64 { return s.dropped.Load() }

// Store 实现 Sink：批量追加为 JSONL。任何失败只记计数与日志后返回（非阻断）。
func (s *FileSink) Store(obs []Observation) {
	if len(obs) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		s.dropped.Add(uint64(len(obs)))
		slog.Error("coverage file sink open failed, batch dropped",
			"path", s.path, "batch", len(obs), "error", err)
		return
	}
	buf := make([]byte, 0, 512*len(obs))
	for _, o := range obs {
		line, err := json.Marshal(o)
		if err != nil { // Observation 全字段可序列化，理论上不可达；按丢弃计数不中断
			s.dropped.Add(1)
			slog.Error("coverage observation marshal failed", "path", s.path, "error", err)
			continue
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if len(buf) == 0 {
		return
	}
	if _, err := s.f.Write(buf); err != nil {
		s.dropped.Add(uint64(len(obs)))
		slog.Error("coverage file sink write failed, batch dropped",
			"path", s.path, "batch", len(obs), "error", err)
		// 写失败后关闭 fd，下个批次重新打开（覆盖 fd 损坏/轮转后句柄异常场景）
		_ = s.f.Close()
		s.f = nil
	}
}

// WriteRaw 以同一把锁追加一行原始 JSON（用于节点计数快照等非 Observation 记录；
// line 不得含内嵌换行，调用方保证是完整一行 JSON；行尾自动补 \n）。
// 失败语义与 Store 一致：只记计数与日志，非阻断。
func (s *FileSink) WriteRaw(line []byte) {
	if len(line) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ensureOpen(); err != nil {
		s.dropped.Add(1)
		slog.Error("coverage file sink open failed, raw line dropped", "path", s.path, "error", err)
		return
	}
	buf := append(append([]byte{}, line...), '\n')
	if _, err := s.f.Write(buf); err != nil {
		s.dropped.Add(1)
		slog.Error("coverage file sink write failed, raw line dropped", "path", s.path, "error", err)
		_ = s.f.Close()
		s.f = nil
	}
}

// ensureOpen 惰性打开输出文件（首次或上次写失败重开时；目录不存在时创建）。
// 调用方必须持锁。
func (s *FileSink) ensureOpen() error {
	if s.f != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	s.f = f
	return nil
}

// Close 关闭底层文件（装配退出时调用；幂等，关闭后 Store 会在下批惰性重开）。
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
