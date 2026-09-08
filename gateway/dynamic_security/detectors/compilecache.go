package detectors

import "sync"

// compileCache 装配期配置编译产物的并发安全缓存（热路径正则预编译修复）。
// 配置经发布通道下发，同一内容逐请求重复传入：键为配置内容的规范化拼接，
// 值为编译结果（含错误——编译失败是内容的确定性函数，缓存不改变校验语义：
// 非法规则仍沿原路径返回错误或保守 OBSERVE）。产物只读共享（regexp.Regexp 并发安全）。
// 配置基数小且稳定，FIFO 定容仅防异常增长，非性能关键路径。
type compileCache struct {
	mu       sync.Mutex
	capacity int
	order    []string // FIFO 逐出顺序
	items    map[string]any
}

func newCompileCache(capacity int) *compileCache {
	return &compileCache{capacity: capacity, items: make(map[string]any)}
}

// load 读取缓存编译产物（未命中 ok=false）。
func (c *compileCache) load(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.items[key]
	return v, ok
}

// store 写入编译产物；超容按 FIFO 逐出最旧键。
func (c *compileCache) store(key string, v any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[key]; !ok {
		if len(c.order) >= c.capacity {
			delete(c.items, c.order[0])
			c.order = c.order[1:]
		}
		c.order = append(c.order, key)
	}
	c.items[key] = v
}
