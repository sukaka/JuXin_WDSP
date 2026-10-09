// registry.go 强流程定义装配产物（NG-FLOW-01 gateway 轨）：已校验定义按
// (id, version) 索引，供 FLOW-02 消费——实例行冻结 definition_version，
// 存量实例按创建时版本查定义（绝不强行换图，§1.1/NG-T-F06）。
package flowguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
)

// Registry 装配产物：已校验定义按 (id, version) 索引（Provision 后只读，
// 热加载经 Guard 实例整体替换生效；nil Registry = 未下发/空段，强流程零行为）。
type Registry struct {
	byKey map[string]Definition // 键：id + NUL + version
	order []Definition          // 稳定序（按 id、version 升序，供遍历与观测）
}

// BuildRegistry 校验并装配定义集（fail-closed：任一非法即整体拒载，不静默吞错）：
//  1. §1.1 校验规则逐条（ValidateDefinitions）；
//  2. 版本不可变断言：同 (id, version) 内容一致 → 重复同版本去重；内容冲突 →
//     拒载（激活版本不可变是「存量不换图」的唯一可靠承载，冲突即快照异常）；
//  3. 同 id 不同 version 并存合法（存量实例按创建时版本消费）。
//
// 缺省值归一：mode 缺省显式化为 OBSERVE、status 缺省显式化为 ACTIVE
// （发布通道恒显式；空为边缘容忍，归一后 FLOW-02 消费免判空）。
// nil/空输入返回 (nil, nil)：段缺失/空数组 = 零行为（NG-T-C01）。
func BuildRegistry(defs []Definition) (*Registry, error) {
	if len(defs) == 0 {
		return nil, nil
	}
	if err := ValidateDefinitions(defs); err != nil {
		return nil, err
	}
	r := &Registry{byKey: make(map[string]Definition, len(defs))}
	for i := range defs {
		d := defs[i]
		if d.Mode == "" {
			d.Mode = ModeObserve
		}
		if d.Status == "" {
			d.Status = StatusActive
		}
		k := registryKey(d.ID, d.Version)
		if prev, ok := r.byKey[k]; ok {
			same, err := definitionContentEqual(prev, d)
			if err != nil {
				return nil, err
			}
			if !same {
				return nil, &ConfigError{Index: i, Reason: fmt.Sprintf(
					"定义 %s version %d 内容冲突（版本不可变：同 id 同版本须内容一致；重复同版本仅内容一致时去重）", d.ID, d.Version)}
			}
			continue // 重复同版本去重
		}
		r.byKey[k] = d
		r.order = append(r.order, d)
	}
	sort.SliceStable(r.order, func(a, b int) bool {
		if r.order[a].ID != r.order[b].ID {
			return r.order[a].ID < r.order[b].ID
		}
		return r.order[a].Version < r.order[b].Version
	})
	return r, nil
}

// Get 按 id+version 取定义（FLOW-02 实例按冻结 definition_version 查定义入口）。
func (r *Registry) Get(id string, version int) (Definition, bool) {
	if r == nil {
		return Definition{}, false
	}
	d, ok := r.byKey[registryKey(id, version)]
	return d, ok
}

// Len 装配后定义数（重复同版本去重后）。
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.order)
}

// All 稳定序遍历（按 id、version 升序；返回切片副本，调用方不得改 Definition 内容）。
func (r *Registry) All() []Definition {
	if r == nil {
		return nil
	}
	return append([]Definition(nil), r.order...)
}

func registryKey(id string, version int) string {
	return id + "\x00" + strconv.Itoa(version)
}

// definitionContentEqual 版本不可变内容比对：JSON 规范化序列化后逐字节比较
// （struct 字段序确定，RawMessage 经编码器压缩空白归一；键序差异等语义一致但
// 字节不一致的形态按冲突拒载——保守 fail-closed，发布侧序列化器输出确定）。
func definitionContentEqual(a, b Definition) (bool, error) {
	ba, err := json.Marshal(a)
	if err != nil {
		return false, &ConfigError{Index: -1, Reason: fmt.Sprintf("定义 %s version %d 序列化失败: %s", a.ID, a.Version, err)}
	}
	bb, err := json.Marshal(b)
	if err != nil {
		return false, &ConfigError{Index: -1, Reason: fmt.Sprintf("定义 %s version %d 序列化失败: %s", b.ID, b.Version, err)}
	}
	return bytes.Equal(ba, bb), nil
}
