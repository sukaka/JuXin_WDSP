package xdpguard

import (
	"fmt"
	"testing"
)

// TestSyncMapDiffCapacityAwareOrdering 验证：
// 1) 当 len(current)+newCount > maxEntries（满载轮换）时，先删陈旧键再插新键，绝不突破容量上限 E2BIG；
// 2) 当容量充裕时，先插新键再删陈旧键，保持实时 XDP 查询零空窗。
func TestSyncMapDiffCapacityAwareOrdering(t *testing.T) {
	// 场景 A：容量 4 已满，替换为 4 个全新键 → 必须先删后插，峰值永不超 4
	const capLimit = 4
	kernel := map[int]struct{}{1: {}, 2: {}, 3: {}, 4: {}}
	current := map[int]struct{}{1: {}, 2: {}, 3: {}, 4: {}}
	desired := map[int]struct{}{5: {}, 6: {}, 7: {}, 8: {}}

	err := syncMapDiff(current, desired, capLimit,
		func(k int) error {
			if len(kernel) >= capLimit {
				return fmt.Errorf("E2BIG at key %d", k)
			}
			kernel[k] = struct{}{}
			return nil
		},
		func(k int) error {
			delete(kernel, k)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("full-capacity rotation failed (must delete stale before put): %v", err)
	}
	if len(kernel) != 4 || len(current) != 4 {
		t.Fatalf("unexpected final map size: kernel=%d current=%d", len(kernel), len(current))
	}
	for k := range desired {
		if _, ok := kernel[k]; !ok {
			t.Fatalf("missing desired key %d in kernel map", k)
		}
	}

	// 场景 B：容量充裕（cap=10，current=2，new=2）→ 先插新键再删旧键（零空窗）
	var ops []string
	current2 := map[int]struct{}{1: {}, 2: {}}
	desired2 := map[int]struct{}{2: {}, 3: {}}
	err = syncMapDiff(current2, desired2, 10,
		func(k int) error {
			ops = append(ops, fmt.Sprintf("put:%d", k))
			return nil
		},
		func(k int) error {
			ops = append(ops, fmt.Sprintf("del:%d", k))
			return nil
		},
	)
	if err != nil {
		t.Fatalf("under-capacity diff failed: %v", err)
	}
	if len(ops) != 2 || ops[0] != "put:3" || ops[1] != "del:1" {
		t.Fatalf("expected put-before-delete when headroom available, got %v", ops)
	}
}
