// service.go 交付检查执行器。
package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Service 交付检查执行器。
type Service struct {
	store *Store
	rc    *RunContext
}

// NewService 创建执行器。rc 中的 Ctx 在执行时按请求覆盖。
func NewService(store *Store, rc *RunContext) *Service {
	if rc.HTTPStatus == nil {
		rc.HTTPStatus = httpGetStatus
	}
	return &Service{store: store, rc: rc}
}

// Run 执行全部交付检查项并落库，返回检查记录与明细。
func (s *Service) Run(ctx context.Context, requestedBy uuid.UUID) (*CheckRun, []ItemResult, error) {
	run, err := s.store.CreateRun(ctx, &requestedBy)
	if err != nil {
		return nil, nil, err
	}
	rc := *s.rc
	rc.Ctx = ctx
	rc.Now = time.Now().UTC()

	items := make([]ItemResult, 0, len(Registry()))
	for _, check := range Registry() {
		items = append(items, s.runOne(&rc, check))
	}
	overall := Overall(items)
	if err := s.store.FinishRun(ctx, run.ID, overall, items); err != nil {
		return nil, nil, fmt.Errorf("保存交付检查结果失败: %w", err)
	}
	finished, err := s.store.GetRun(ctx, run.ID)
	if err != nil {
		return nil, nil, err
	}
	return finished, items, nil
}

// runOne 执行单项检查；panic 恢复为 FAIL（不静默吞错）。
func (s *Service) runOne(rc *RunContext, check Check) (item ItemResult) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("delivery check panicked", "key", check.Key, "panic", r)
			item = check.item(ResultFail, fmt.Sprintf("检查执行异常：%v", r), nil)
		}
	}()
	return check.Run(rc)
}

// httpGetStatus 探测本机 URL 状态码（仅回环地址，超时 3 秒）。
func httpGetStatus(url string) (int, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, nil
}
