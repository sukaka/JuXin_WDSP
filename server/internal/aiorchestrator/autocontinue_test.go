package aiorchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aimodel"
)

// fakeContinueCost 实现 CostRecorder + ContinueQuotaChecker 的测试桩。
type fakeContinueCost struct {
	checkErr   error
	checkCalls int
}

func (f *fakeContinueCost) RecordUsage(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID, *uuid.UUID, int, int, int, float64) error {
	return nil
}

func (f *fakeContinueCost) CheckQuota(context.Context, uuid.UUID, string, int) error {
	f.checkCalls++
	return f.checkErr
}

// continueTestGateway 假模型服务与网关：第 n 次呼叫返回 responses[min(n, len-1)]。
func continueTestGateway(t *testing.T, responses []struct{ content, finish string }, hits *int32, bodies *[][]aimodel.ChatMessage) *aimodel.Gateway {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(hits, 1)) - 1
		var body struct {
			Messages []aimodel.ChatMessage `json:"messages"`
		}
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		*bodies = append(*bodies, body.Messages)
		if n >= len(responses) {
			n = len(responses) - 1
		}
		resp := responses[n]
		w.Header().Set("Content-Type", "application/json")
		out, _ := json.Marshal(map[string]interface{}{
			"choices": []map[string]interface{}{{
				"message":       map[string]string{"content": resp.content},
				"finish_reason": resp.finish,
			}},
			"usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1},
		})
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)

	gw := aimodel.NewGateway(nil)
	m := &aimodel.Model{ID: uuid.New(), Code: "test-model", TimeoutSeconds: 5, Status: "ACTIVE"}
	p := &aimodel.Provider{ID: uuid.New(), Name: "test", Type: aimodel.ProviderOpenAICompatible, BaseURL: srv.URL, AllowedTargets: []string{"127.0.0.1/32"}}
	gw.SetRoutes(map[aimodel.TaskComplexity][]struct {
		Model    *aimodel.Model
		Provider *aimodel.Provider
	}{
		aimodel.ComplexityStandard: {{Model: m, Provider: p}},
	})
	return gw
}

func resp(content, finish string) struct{ content, finish string } {
	return struct{ content, finish string }{content, finish}
}

// TestComposeAnswerAutoContinueOnLength finish_reason=length 时自动续写，内容拼接进同一条回答。
func TestComposeAnswerAutoContinueOnLength(t *testing.T) {
	var hits int32
	var bodies [][]aimodel.ChatMessage
	gw := continueTestGateway(t, []struct{ content, finish string }{
		resp("前半部分", "length"),
		resp("后半部分", "stop"),
	}, &hits, &bodies)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute})

	answer, finish, continues, err := o.composeAnswer(context.Background(),
		Plan{TaskType: TaskStatistics}, "统计攻击趋势", "已核实事实", nil, "", nil, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("composeAnswer err = %v", err)
	}
	if finish != "stop" {
		t.Errorf("finish = %q, want stop（续写成功后透传最终 finish_reason）", finish)
	}
	if continues != 1 {
		t.Errorf("continues = %d, want 1", continues)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Errorf("hits = %d, want 2（首次 + 1 次续写）", got)
	}
	want := "前半部分后半部分\n\n已核实事实"
	if answer != want {
		t.Errorf("answer = %q, want %q（续写内容应拼接进同一条回答）", answer, want)
	}
	// 续写请求须携带已生成摘要与续写指令
	if len(bodies) != 2 {
		t.Fatalf("recorded bodies = %d, want 2", len(bodies))
	}
	cont := bodies[1]
	if len(cont) != 4 || cont[2].Role != "assistant" || cont[2].Content != "前半部分" || cont[3].Role != "user" || cont[3].Content != continueInstruction {
		t.Errorf("continuation messages = %+v, want [system, user, assistant(前半部分), user(续写指令)]", cont)
	}
}

// TestComposeAnswerAutoContinueCap 持续 length 时达到默认上限（2 次）停止，保留 length 交手动继续。
func TestComposeAnswerAutoContinueCap(t *testing.T) {
	var hits int32
	var bodies [][]aimodel.ChatMessage
	gw := continueTestGateway(t, []struct{ content, finish string }{resp("片段", "length")}, &hits, &bodies)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute})

	answer, finish, continues, err := o.composeAnswer(context.Background(),
		Plan{TaskType: TaskStatistics}, "统计攻击趋势", "已核实事实", nil, "", nil, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("composeAnswer err = %v", err)
	}
	if finish != "length" {
		t.Errorf("finish = %q, want length（达上限仍截断，由前端「继续」接管）", finish)
	}
	if continues != defaultMaxAutoContinues {
		t.Errorf("continues = %d, want %d（默认上限）", continues, defaultMaxAutoContinues)
	}
	if got := atomic.LoadInt32(&hits); got != int32(1+defaultMaxAutoContinues) {
		t.Errorf("hits = %d, want %d（首次 + %d 次续写）", got, 1+defaultMaxAutoContinues, defaultMaxAutoContinues)
	}
	want := "片段片段片段\n\n已核实事实"
	if answer != want {
		t.Errorf("answer = %q, want %q", answer, want)
	}
}

// TestComposeAnswerAutoContinueDisabled MaxAutoContinues<0 时关闭自动续写。
func TestComposeAnswerAutoContinueDisabled(t *testing.T) {
	var hits int32
	var bodies [][]aimodel.ChatMessage
	gw := continueTestGateway(t, []struct{ content, finish string }{resp("片段", "length")}, &hits, &bodies)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute, MaxAutoContinues: -1})

	_, finish, continues, err := o.composeAnswer(context.Background(),
		Plan{TaskType: TaskStatistics}, "统计攻击趋势", "已核实事实", nil, "", nil, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("composeAnswer err = %v", err)
	}
	if finish != "length" || continues != 0 {
		t.Errorf("finish = %q, continues = %d, want length/0（关闭续写后原样透传）", finish, continues)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("hits = %d, want 1（不应发起续写呼叫）", got)
	}
}

// TestComposeAnswerNoContinueOnStop finish_reason=stop 时不续写。
func TestComposeAnswerNoContinueOnStop(t *testing.T) {
	var hits int32
	var bodies [][]aimodel.ChatMessage
	gw := continueTestGateway(t, []struct{ content, finish string }{resp("完整回答", "stop")}, &hits, &bodies)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute})

	answer, finish, continues, err := o.composeAnswer(context.Background(),
		Plan{TaskType: TaskStatistics}, "统计攻击趋势", "已核实事实", nil, "", nil, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("composeAnswer err = %v", err)
	}
	if finish != "stop" || continues != 0 {
		t.Errorf("finish = %q, continues = %d, want stop/0", finish, continues)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("hits = %d, want 1（非 length 不应续写）", got)
	}
	if want := "完整回答\n\n已核实事实"; answer != want {
		t.Errorf("answer = %q, want %q", answer, want)
	}
}

// TestComposeAnswerAutoContinueQuotaBlocked 续写受 aicost 配额约束：CheckQuota 拒绝即停止续写。
func TestComposeAnswerAutoContinueQuotaBlocked(t *testing.T) {
	var hits int32
	var bodies [][]aimodel.ChatMessage
	gw := continueTestGateway(t, []struct{ content, finish string }{resp("片段", "length")}, &hits, &bodies)
	cost := &fakeContinueCost{checkErr: errors.New("ai quota exceeded")}
	o := New(nil, gw, nil, nil, nil, cost, TaskLimits{MaxDuration: time.Minute})

	answer, finish, continues, err := o.composeAnswer(context.Background(),
		Plan{TaskType: TaskStatistics}, "统计攻击趋势", "已核实事实", nil, "", nil, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("composeAnswer err = %v", err)
	}
	if finish != "length" || continues != 0 {
		t.Errorf("finish = %q, continues = %d, want length/0（配额拦截不续写，保留已生成部分）", finish, continues)
	}
	if cost.checkCalls != 1 {
		t.Errorf("checkCalls = %d, want 1（续写前必须过配额检查）", cost.checkCalls)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Errorf("hits = %d, want 1（配额拦截后不得发起续写呼叫）", got)
	}
	if want := "片段\n\n已核实事实"; answer != want {
		t.Errorf("answer = %q, want %q（已生成部分保留）", answer, want)
	}
}

// TestComposeAnswerAutoContinueQuotaOptional 成本记录器不具备配额检查能力时不限制续写。
func TestComposeAnswerAutoContinueQuotaOptional(t *testing.T) {
	var hits int32
	var bodies [][]aimodel.ChatMessage
	gw := continueTestGateway(t, []struct{ content, finish string }{
		resp("前半", "length"),
		resp("后半", "stop"),
	}, &hits, &bodies)
	o := New(nil, gw, nil, nil, nil, plainCost{}, TaskLimits{MaxDuration: time.Minute})

	_, finish, continues, err := o.composeAnswer(context.Background(),
		Plan{TaskType: TaskStatistics}, "统计攻击趋势", "已核实事实", nil, "", nil, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("composeAnswer err = %v", err)
	}
	if finish != "stop" || continues != 1 {
		t.Errorf("finish = %q, continues = %d, want stop/1", finish, continues)
	}
}

// TestComposeAnswerAutoContinueModelError 续写呼叫失败时停止续写，保留已生成部分（降级不中断主流程）。
func TestComposeAnswerAutoContinueModelError(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"前半"},"finish_reason":"length"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
			return
		}
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(srv.Close)
	gw := aimodel.NewGateway(nil)
	m := &aimodel.Model{ID: uuid.New(), Code: "test-model", TimeoutSeconds: 5, Status: "ACTIVE"}
	p := &aimodel.Provider{ID: uuid.New(), Name: "test", Type: aimodel.ProviderOpenAICompatible, BaseURL: srv.URL, AllowedTargets: []string{"127.0.0.1/32"}}
	gw.SetRoutes(map[aimodel.TaskComplexity][]struct {
		Model    *aimodel.Model
		Provider *aimodel.Provider
	}{
		aimodel.ComplexityStandard: {{Model: m, Provider: p}},
	})
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute})

	answer, finish, continues, err := o.composeAnswer(context.Background(),
		Plan{TaskType: TaskStatistics}, "统计攻击趋势", "已核实事实", nil, "", nil, uuid.New(), "admin")
	if err != nil {
		t.Fatalf("composeAnswer err = %v（续写失败应降级保留已生成部分，不向主流程抛错）", err)
	}
	if finish != "length" || continues != 0 {
		t.Errorf("finish = %q, continues = %d, want length/0", finish, continues)
	}
	if want := "前半\n\n已核实事实"; answer != want {
		t.Errorf("answer = %q, want %q", answer, want)
	}
}
