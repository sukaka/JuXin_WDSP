// MemoryMap.Get 只读访问器：不建键、键不存在 ok=false。
package counters

import "testing"

func TestMemoryMapGet(t *testing.T) {
	m := NewMemoryMap(10)
	if _, ok := m.Get("missing"); ok {
		t.Fatal("Get on empty map must return ok=false")
	}
	m.GetOrCreate("k", func() interface{} { return 42 })
	v, ok := m.Get("k")
	if !ok || v.(int) != 42 {
		t.Fatalf("Get = %v,%v, want 42,true", v, ok)
	}
	// Get 不得建键：反复 Get 缺失键后键数量不变
	for i := 0; i < 5; i++ {
		m.Get("missing")
	}
	if m.Len() != 1 {
		t.Fatalf("Len = %d, want 1（Get 不得建键）", m.Len())
	}
}
