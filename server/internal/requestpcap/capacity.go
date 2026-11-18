package requestpcap

import (
	"context"
	"fmt"
	"io"
	"time"

	"golang.org/x/sys/unix"
)

func (m *StorageManager) checkWarmCapacity(required int64) error {
	percent := m.MinWarmFreePercent
	if percent <= 0 {
		percent = 10
	}
	var stat unix.Statfs_t
	if err := unix.Statfs(m.warmRoot, &stat); err != nil {
		return fmt.Errorf("check warm evidence storage capacity: %w", err)
	}
	available := int64(stat.Bavail) * int64(stat.Bsize)
	reserve := int64(stat.Blocks) * int64(stat.Bsize) * int64(percent) / 100
	if available < reserve+required {
		return fmt.Errorf("warm evidence storage free space is below the migration watermark (available=%d required=%d)", available, reserve+required)
	}
	return nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(data)
}

type throttledWriter struct {
	writer  io.Writer
	rate    int64
	written int64
	started time.Time
}

func (w *throttledWriter) Write(data []byte) (int, error) {
	if w.rate > 0 {
		if w.started.IsZero() {
			w.started = time.Now()
		}
		w.written += int64(len(data))
		delay := time.Duration(w.written*int64(time.Second)/w.rate) - time.Since(w.started)
		if delay > 0 {
			time.Sleep(delay)
		}
	}
	return w.writer.Write(data)
}
