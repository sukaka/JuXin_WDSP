// evaluate_test.go BOLA 五档评估矩阵测试（判定阶梯纯函数 + 内存仓储端到端）。
package apiauthz

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestDecideVerdict 判定阶梯纯函数矩阵（规则见 evaluate.go 文件头注释）。
func TestDecideVerdict(t *testing.T) {
	cases := []struct {
		name        string
		identity    string
		sig         evalSignals
		wantVerdict string
		wantAllowed *bool // nil = 无法判定
	}{
		{"权属匹配→POLICY_CONFIRMED", "fp-a",
			evalSignals{ownMatch: true, objectOwnerCount: 1, identityObjectCount: 1, endpointOwnershipRows: 1},
			VerdictPolicyConfirmed, boolPtr(true)},
		{"对象有属主且身份有自身权属→HIGH_CONFIDENCE", "fp-b",
			evalSignals{objectOwnerCount: 1, identityObjectCount: 3, endpointOwnershipRows: 4},
			VerdictHighConfidence, boolPtr(false)},
		{"对象有属主、身份无记录→HIGH_CONFIDENCE", "fp-new",
			evalSignals{objectOwnerCount: 2, endpointOwnershipRows: 5},
			VerdictHighConfidence, boolPtr(false)},
		{"匿名访问有属主对象→HIGH_CONFIDENCE", "",
			evalSignals{objectOwnerCount: 1, endpointOwnershipRows: 1},
			VerdictHighConfidence, boolPtr(false)},
		{"无对象权属、身份有权属基线→LIKELY", "fp-a",
			evalSignals{identityObjectCount: 2, endpointOwnershipRows: 2},
			VerdictLikely, boolPtr(true)},
		{"无对象权属、身份仅有历史访问→LIKELY", "fp-a",
			evalSignals{identityEventCount: 7, endpointOwnershipRows: 0},
			VerdictLikely, boolPtr(true)},
		{"端点有权属画像但双方无记录→POSSIBLE", "fp-new",
			evalSignals{endpointOwnershipRows: 9},
			VerdictPossible, boolPtr(false)},
		{"匿名且端点有权属画像→POSSIBLE", "",
			evalSignals{endpointOwnershipRows: 3},
			VerdictPossible, boolPtr(false)},
		{"无任何数据→INSUFFICIENT_EVIDENCE", "fp-a",
			evalSignals{},
			VerdictInsufficientEvidence, nil},
		{"匿名且无任何数据→INSUFFICIENT_EVIDENCE", "",
			evalSignals{},
			VerdictInsufficientEvidence, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, allowed, _, _ := decideVerdict(tc.identity, tc.sig)
			if verdict != tc.wantVerdict {
				t.Fatalf("verdict=%s want %s", verdict, tc.wantVerdict)
			}
			if tc.wantAllowed == nil {
				if allowed != nil {
					t.Fatalf("allowed=%v want nil", *allowed)
				}
				return
			}
			if allowed == nil || *allowed != *tc.wantAllowed {
				t.Fatalf("allowed=%v want %v", allowed, *tc.wantAllowed)
			}
		})
	}
}

// TestEvaluateBOLAMatrix 内存仓储端到端五档矩阵：权属由 SweepOnce 从运行时事件生产，
// 覆盖「权属生产 → 评估消费」全链路。
func TestEvaluateBOLAMatrix(t *testing.T) {
	ctx := context.Background()
	epKey := "GET /v1/users/{id}"

	t.Run("端点不存在→ErrNotFound", func(t *testing.T) {
		store := NewMemStore()
		_, err := store.EvaluateBOLA(ctx, EvaluateInput{EndpointID: uuid.New(), Identity: "fp-a", ObjectID: "1"})
		if err != ErrNotFound {
			t.Fatalf("err=%v want ErrNotFound", err)
		}
	})

	// POLICY_CONFIRMED：fp-a 访问自己权属内的对象 1001
	t.Run(VerdictPolicyConfirmed, func(t *testing.T) {
		store := NewMemStore()
		endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
		base := time.Now().UTC().Add(-time.Hour)
		store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base)
		if _, err := store.SweepOnce(ctx); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		res, err := store.EvaluateBOLA(ctx, EvaluateInput{EndpointID: endpointID, Identity: "fp-a", ObjectID: "1001"})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Verdict != VerdictPolicyConfirmed || res.Allowed == nil || !*res.Allowed {
			t.Fatalf("res=%+v", res)
		}
		if !res.Evidence.OwnMatch || res.Evidence.ObjectOwnerCount != 1 || res.Evidence.IdentityObjectCount != 1 {
			t.Fatalf("evidence=%+v", res.Evidence)
		}
	})

	// HIGH_CONFIDENCE：对象 1001 属主是 fp-a，fp-b 访问 → 越权
	t.Run(VerdictHighConfidence, func(t *testing.T) {
		store := NewMemStore()
		endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
		base := time.Now().UTC().Add(-time.Hour)
		store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base)
		store.addRuntimeEvent(epKey, "fp-b", "/v1/users/2002", base.Add(time.Minute)) // fp-b 有自己的权属
		if _, err := store.SweepOnce(ctx); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		res, err := store.EvaluateBOLA(ctx, EvaluateInput{EndpointID: endpointID, Identity: "fp-b", ObjectID: "1001"})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Verdict != VerdictHighConfidence || res.Allowed == nil || *res.Allowed {
			t.Fatalf("res=%+v", res)
		}
		if res.Evidence.OwnMatch || res.Evidence.ObjectOwnerCount != 1 || res.Evidence.IdentityObjectCount != 1 {
			t.Fatalf("evidence=%+v", res.Evidence)
		}
	})

	// LIKELY（有权属基线）：fp-a 访问从未出现过的对象 9999（疑似自己的新对象）
	t.Run(VerdictLikely+"_ownership", func(t *testing.T) {
		store := NewMemStore()
		endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
		base := time.Now().UTC().Add(-time.Hour)
		store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base)
		if _, err := store.SweepOnce(ctx); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		res, err := store.EvaluateBOLA(ctx, EvaluateInput{EndpointID: endpointID, Identity: "fp-a", ObjectID: "9999"})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Verdict != VerdictLikely || res.Allowed == nil || !*res.Allowed {
			t.Fatalf("res=%+v", res)
		}
		if res.Evidence.ObjectOwnerCount != 0 || res.Evidence.IdentityObjectCount != 1 {
			t.Fatalf("evidence=%+v", res.Evidence)
		}
	})

	// LIKELY（仅历史访问）：无权属数据（未清扫），但身份有历史运行时事件
	t.Run(VerdictLikely+"_events", func(t *testing.T) {
		store := NewMemStore()
		endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
		store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", time.Now().UTC())
		// 不跑 SweepOnce：无任何权属行，只有历史事件
		res, err := store.EvaluateBOLA(ctx, EvaluateInput{EndpointID: endpointID, Identity: "fp-a", ObjectID: "1001"})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Verdict != VerdictLikely || res.Allowed == nil || !*res.Allowed {
			t.Fatalf("res=%+v", res)
		}
		if res.Evidence.IdentityEventCount != 1 || res.Evidence.EndpointOwnershipRows != 0 {
			t.Fatalf("evidence=%+v", res.Evidence)
		}
	})

	// POSSIBLE：端点已有权属画像，但 fp-new 与对象 8888 均无记录（仅对象枚举信号）
	t.Run(VerdictPossible, func(t *testing.T) {
		store := NewMemStore()
		endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
		store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", time.Now().UTC())
		if _, err := store.SweepOnce(ctx); err != nil {
			t.Fatalf("sweep: %v", err)
		}
		res, err := store.EvaluateBOLA(ctx, EvaluateInput{EndpointID: endpointID, Identity: "fp-new", ObjectID: "8888"})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Verdict != VerdictPossible || res.Allowed == nil || *res.Allowed {
			t.Fatalf("res=%+v", res)
		}
	})

	// INSUFFICIENT_EVIDENCE：端点存在但无任何权属与历史
	t.Run(VerdictInsufficientEvidence, func(t *testing.T) {
		store := NewMemStore()
		endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
		res, err := store.EvaluateBOLA(ctx, EvaluateInput{EndpointID: endpointID, Identity: "fp-a", ObjectID: "1001"})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Verdict != VerdictInsufficientEvidence || res.Allowed != nil || res.Confidence != 0 {
			t.Fatalf("res=%+v", res)
		}
	})
}
