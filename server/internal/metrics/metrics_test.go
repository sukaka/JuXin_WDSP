package metrics

import "testing"

func TestBucketIndex(t *testing.T) {
	cases := map[float64]int{1: 0, 5: 0, 6: 1, 50: 3, 99: 4, 5000: 9, 99999: 10}
	for d, want := range cases {
		if got := BucketIndex(d); got != want {
			t.Errorf("BucketIndex(%v) = %d, want %d", d, got, want)
		}
	}
}

func TestPercentileFromBuckets(t *testing.T) {
	// 100 个请求：90 个落在 5ms，10 个落在 100ms
	counts := []int{90, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0}
	if p := PercentileFromBuckets(counts, 0.5); p > 5 {
		t.Errorf("p50 = %v, want <=5", p)
	}
	if p := PercentileFromBuckets(counts, 0.95); p < 50 || p > 100 {
		t.Errorf("p95 = %v, want in (50,100]", p)
	}
	if p := PercentileFromBuckets([]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0.95); p != 0 {
		t.Errorf("empty p95 = %v, want 0", p)
	}
}

func TestValidateLabels(t *testing.T) {
	if !ValidateLabels(map[string]string{"app": "shop", "attack_type": "SQL_INJECTION"}) {
		t.Error("valid labels rejected")
	}
	if !ValidateLabels(map[string]string{"app": "shop", "endpoint": "GET /api/users/{id}"}) {
		t.Error("endpoint label must be accepted (APM 阶段1 端点级 RED)")
	}
	if ValidateLabels(map[string]string{"uri": "/a?x=1"}) {
		t.Error("uri label key must be rejected (高基数)")
	}
	if ValidateLabels(map[string]string{"app": string(make([]byte, 200))}) {
		t.Error("oversize label value must be rejected")
	}
	if !ValidateLabels(nil) {
		t.Error("nil labels should pass")
	}
}
