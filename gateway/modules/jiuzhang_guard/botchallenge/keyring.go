package botchallenge

import (
	"crypto/subtle"
	"fmt"
	"sort"
)

// Key 签名密钥（ID 仅引用名——本地允许列表选择；Secret 为密钥材料，
// 永不序列化/记录日志）。
type Key struct {
	ID     string
	Secret []byte
}

// Keyring Bot 挑战独立签名密钥环（任务书 §5.3）：
//   - 与 JWT/CSRF/管理会话/Agent CA 密钥完全隔离（独立注入，禁止共用）；
//   - Current 为当前签名密钥；Previous 为轮换窗口内的旧验签密钥
//     （旧通行按通行窗口保留——clearance_ttl 内仍可验签，过期自然失效；
//     紧急撤销经 policy_epoch（= 策略版本）生效，与密钥轮换正交）；
//   - key_id 仅本地允许列表选择：Lookup 只查内存表，禁止任何路径/URL 拼接。
type Keyring struct {
	current Key
	keys    map[string][]byte // key_id → 密钥材料（允许列表 = 配置的键集合）
}

// NewKeyring 构造密钥环（fail-closed：词形/长度/唯一性非法即拒绝）。
// current 必须提供（签名必需）；previous 可为空（无轮换窗口）。
func NewKeyring(current Key, previous ...Key) (*Keyring, error) {
	if err := validateKey(current); err != nil {
		return nil, fmt.Errorf("current key: %w", err)
	}
	keys := map[string][]byte{current.ID: current.Secret}
	for _, k := range previous {
		if err := validateKey(k); err != nil {
			return nil, fmt.Errorf("previous key %q: %w", k.ID, err)
		}
		if k.ID == current.ID {
			return nil, fmt.Errorf("previous key %q 与 current 重复（轮换须更换 key_id）", k.ID)
		}
		if _, dup := keys[k.ID]; dup {
			return nil, fmt.Errorf("previous key %q 重复", k.ID)
		}
		keys[k.ID] = k.Secret
	}
	return &Keyring{current: current, keys: keys}, nil
}

// validateKey 密钥合法性：key_id 词形（仅引用名，防路径拼接）+ 密钥材料最小长度
// （HMAC-SHA-256 密钥 ≥32 字节，防弱密钥）。
func validateKey(k Key) error {
	if !keyIDPattern.MatchString(k.ID) {
		return fmt.Errorf("非法 key_id %q（仅 [a-z0-9._-] 引用名，禁止路径/URL 形态）", k.ID)
	}
	if len(k.Secret) < 32 {
		return fmt.Errorf("key %q 密钥材料过短（%d < 32 字节）", k.ID, len(k.Secret))
	}
	return nil
}

// Current 当前签名密钥。
func (k *Keyring) Current() Key { return k.current }

// Lookup 按 key_id 取验签密钥（含轮换窗口内旧密钥；未知 key_id → false，
// 绝不回退默认密钥或加载外部材料）。
func (k *Keyring) Lookup(id string) ([]byte, bool) {
	sec, ok := k.keys[id]
	return sec, ok
}

// KeyIDs 允许列表快照（诊断/测试用；升序，不含密钥材料）。
func (k *Keyring) KeyIDs() []string {
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// zeroize 清零密钥材料（Cleanup/测试用；尽力而为——Go GC 不保证立即回收副本）。
func (k *Keyring) zeroize() {
	for id, sec := range k.keys {
		for i := range sec {
			sec[i] = 0
		}
		delete(k.keys, id)
	}
	for i := range k.current.Secret {
		k.current.Secret[i] = 0
	}
}

// equalSecret 恒定时间比较（防侧信道）。
func equalSecret(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

// bytesEqual 通用恒定时间比较包装。
func bytesEqual(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
