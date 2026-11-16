// aiops_summarizer_test.go apiops LLM 润色适配器测试（AI 能力增强第一波）：
// 低复杂度档位路由、成功返回润色文本、失败/空输出返回 error（由 apiops 回退模板）。
package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/aimodel"
)

// fakeChatGateway 测试模型网关。
type fakeChatGateway struct {
	res           *aimodel.ChatResult
	err           error
	gotComplexity aimodel.TaskComplexity
	gotReq        aimodel.ChatRequest
	calls         int
}

func (f *fakeChatGateway) Chat(_ context.Context, complexity aimodel.TaskComplexity, req aimodel.ChatRequest) (*aimodel.ChatResult, error) {
	f.calls++
	f.gotComplexity = complexity
	f.gotReq = req
	return f.res, f.err
}

// TestAIOpsSummarizerPolishSuccess 成功润色：低复杂度档位，提示词携带草稿与报告事实。
func TestAIOpsSummarizerPolishSuccess(t *testing.T) {
	gw := &fakeChatGateway{res: &aimodel.ChatResult{Content: "  润色后的运营摘要  ", FinishReason: "stop"}}
	s := newAIOpsSummarizer(gw)
	out, err := s.Polish(context.Background(), "RISK_DIGEST",
		reportFixture, "高风险发现摘要：未闭环 HIGH/CRITICAL 发现共 2 项。")
	if err != nil {
		t.Fatalf("Polish err = %v", err)
	}
	if out != "润色后的运营摘要" {
		t.Errorf("Polish = %q, want 去除首尾空白后的润色文本", out)
	}
	if gw.gotComplexity != aimodel.ComplexitySimple {
		t.Errorf("复杂度档位 = %s, want %s", gw.gotComplexity, aimodel.ComplexitySimple)
	}
	if len(gw.gotReq.Messages) != 2 {
		t.Fatalf("消息数 = %d, want 2", len(gw.gotReq.Messages))
	}
	user := gw.gotReq.Messages[1].Content
	if !strings.Contains(user, "RISK_DIGEST") || !strings.Contains(user, "高风险发现摘要") || !strings.Contains(user, `"open_high_total"`) {
		t.Errorf("提示词应携带任务类型、模板草稿与报告原文\n%s", user)
	}
	if gw.gotReq.MaxTokens <= 0 {
		t.Errorf("MaxTokens 应显式设置, got %d", gw.gotReq.MaxTokens)
	}
}

// reportFixture 结构化报告事实夹具。
var reportFixture = []byte(`{"open_high_total":2,"open_critical":1}`)

// TestAIOpsSummarizerPolishFailure 网关失败与空输出均返回 error（调用方回退模板草稿）。
func TestAIOpsSummarizerPolishFailure(t *testing.T) {
	cases := []struct {
		name string
		gw   *fakeChatGateway
	}{
		{"网关错误", &fakeChatGateway{err: errors.New("model down")}},
		{"空输出", &fakeChatGateway{res: &aimodel.ChatResult{Content: "   "}}},
		{"空结果", &fakeChatGateway{res: &aimodel.ChatResult{}}},
		{"空指针结果", &fakeChatGateway{res: nil}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := newAIOpsSummarizer(c.gw).Polish(context.Background(), "RISK_DIGEST", reportFixture, "草稿")
			if err == nil {
				t.Errorf("Polish 应返回 error, got out=%q", out)
			}
		})
	}
}

// TestAIOpsSummarizerNilGateway 未装配网关返回 error 而非 panic。
func TestAIOpsSummarizerNilGateway(t *testing.T) {
	if _, err := newAIOpsSummarizer(nil).Polish(context.Background(), "RISK_DIGEST", nil, "草稿"); err == nil {
		t.Error("nil 网关应返回 error")
	}
	var s *aiOpsSummarizer
	if _, err := s.Polish(context.Background(), "RISK_DIGEST", nil, "草稿"); err == nil {
		t.Error("nil 接收器应返回 error")
	}
}

// TestAIOpsSummarizerReportTruncated 超长报告截断注入（防输入膨胀）。
func TestAIOpsSummarizerReportTruncated(t *testing.T) {
	gw := &fakeChatGateway{res: &aimodel.ChatResult{Content: "ok"}}
	s := newAIOpsSummarizer(gw)
	long := []byte(`{"data":"` + strings.Repeat("x", aiOpsSummarizerMaxReportRunes*2) + `"}`)
	if _, err := s.Polish(context.Background(), "ASSET_DIGEST", long, "草稿"); err != nil {
		t.Fatalf("Polish err = %v", err)
	}
	user := gw.gotReq.Messages[1].Content
	if len([]rune(user)) > aiOpsSummarizerMaxReportRunes*2 {
		t.Errorf("注入提示词的报告应被截断, len=%d runes", len([]rune(user)))
	}
}
