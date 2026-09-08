package botchallenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// 会话/通行 Cookie 线格式（B2 冻结）：
//
//	value = "v1." + base64url(json_payload) + "." + hex(HMAC-SHA256(key, purpose + "." + b64))
//	- 版本化用途标识 purpose 参与签名输入（域分隔：会话与通行签名互不混用，
//	  且与其他用途密钥天然隔离——任务书 §5.3「有版本的用途标识」）；
//	- 算法固定 HMAC-SHA-256（标准库；严格固定，不接受任何算法协商）；
//	- payload 长度校验、签名恒定时间比较、exp 强制；
//	- key_id 只用于 Lookup 允许列表选择验签密钥。
const (
	tokenVersion       = "v1"
	purposeSession     = "wdsp-bot-session-v1"
	purposeClearance   = "wdsp-bot-clearance-v1"
	maxTokenPayloadLen = 1024 // payload 长度上界（防超大 Cookie 解析开销）
	tokenSigHexLen     = sha256.Size * 2
)

// sessionPayload 会话 Cookie 载荷（sid 原文只存在 Cookie 中；服务端状态只存其摘要）。
type sessionPayload struct {
	V   int    `json:"v"`
	Sid string `json:"sid"` // 256 bit 随机会话 ID（hex）
	Exp int64  `json:"exp"`
	Kid string `json:"kid"`
}

// clearancePayload 通行 Cookie 载荷（任务书 §5.3：版本化用途标识（签名输入 purpose +
// payload v）、应用、Host（摘要）、policy_epoch、会话摘要、iat/exp、key_id）。
type clearancePayload struct {
	V   int    `json:"v"`
	App string `json:"app"` // 应用 ID
	Hh  string `json:"hh"`  // Host 摘要（counters.HashParts 材料，不落原始 Host 于服务端状态）
	Sd  string `json:"sd"`  // 会话摘要（SHA-256(sid) hex）
	Ep  int    `json:"ep"`  // policy_epoch（= 策略版本；撤销代次）
	Fl  string `json:"fl"`  // flow_id（挑战关联指纹，脱敏）
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Kid string `json:"kid"`
}

// signToken 签名（payload 先序列化再签；输出 "v1.<b64>.<hexsig>"）。
func signToken(key []byte, purpose string, payload interface{}) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	if len(raw) > maxTokenPayloadLen {
		return "", fmt.Errorf("token payload 超长（%d > %d）", len(raw), maxTokenPayloadLen)
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(purpose))
	mac.Write([]byte("."))
	mac.Write([]byte(b64))
	return tokenVersion + "." + b64 + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

// splitToken 拆分 "v1.<b64>.<sig>" 三段（仅结构检查，不验签）。
func splitToken(value string) []string {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return nil
	}
	return parts
}

// decodePayload 解码 payload 段（不验签——仅用于事件归因/节流键，不作信任依据）。
func decodePayload(b64 string, payload interface{}) error {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(raw) > maxTokenPayloadLen {
		return fmt.Errorf("token 载荷编码非法")
	}
	return json.Unmarshal(raw, payload)
}

// verifyToken 验签并解析载荷（长度校验 → 结构拆分 → key_id 允许列表 →
// 恒定时间比较 → exp 检查；任何一步失败即拒绝，不区分提示——防预言机）。
func verifyToken(kr *Keyring, purpose, value string, payload interface{}, now time.Time) error {
	if len(value) > len(tokenVersion)+1+base64.RawURLEncoding.EncodedLen(maxTokenPayloadLen)+1+tokenSigHexLen {
		return fmt.Errorf("token 超长")
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != tokenVersion {
		return fmt.Errorf("token 版本/结构非法")
	}
	if len(parts[2]) != tokenSigHexLen {
		return fmt.Errorf("token 签名长度非法")
	}
	sig, err := hex.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("token 签名编码非法")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(raw) > maxTokenPayloadLen {
		return fmt.Errorf("token 载荷编码非法")
	}
	// 先解析拿 kid（验签前解析是安全的：kid 仅作允许列表索引，不作信任依据）
	if err := json.Unmarshal(raw, payload); err != nil {
		return fmt.Errorf("token 载荷结构非法")
	}
	type kidCarrier struct{ Kid string }
	var kc kidCarrier
	if err := json.Unmarshal(raw, &kc); err != nil || !keyIDPattern.MatchString(kc.Kid) {
		return fmt.Errorf("token key_id 非法")
	}
	key, ok := kr.Lookup(kc.Kid)
	if !ok {
		return fmt.Errorf("未知 key_id（不在本地允许列表）")
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(purpose))
	mac.Write([]byte("."))
	mac.Write([]byte(parts[1]))
	if !bytesEqual(mac.Sum(nil), sig) {
		return fmt.Errorf("token 签名校验失败")
	}
	// 过期检查（iat/exp 在验签通过后才有意义）
	type expCarrier struct {
		V   int   `json:"v"`
		Exp int64 `json:"exp"`
	}
	var ec expCarrier
	if err := json.Unmarshal(raw, &ec); err != nil || ec.V != 1 || ec.Exp == 0 {
		return fmt.Errorf("token 载荷版本/过期字段非法")
	}
	if !now.Before(time.Unix(ec.Exp, 0).Add(clockSkew)) {
		return fmt.Errorf("token 已过期")
	}
	return nil
}

// ---------- 会话 ----------

// signingKey 当前签名密钥：策略 challenge.key_ref 非空时按引用名从允许列表选择
// （key_id 仅本地允许列表选择，禁止拼接路径/URL）；空引用名用密钥环当前密钥。
func (s *Service) signingKey() (Key, bool) {
	if ref := s.cfg.KeyRef; ref != "" {
		sec, ok := s.cfg.Keyring.Lookup(ref)
		if !ok {
			return Key{}, false
		}
		return Key{ID: ref, Secret: sec}, true
	}
	cur := s.cfg.Keyring.Current()
	return cur, cur.ID != "" && len(cur.Secret) >= 32
}

// mintSession 签发新会话（crypto/rand 256 bit）。
func (s *Service) mintSession() (sid string, cookieValue string, err error) {
	b := make([]byte, sessionIDBytes)
	if err := randRead(b); err != nil {
		return "", "", err
	}
	return s.signSession(hex.EncodeToString(b))
}

// signSession 签会话 Cookie。
func (s *Service) signSession(sid string) (string, string, error) {
	k, ok := s.signingKey()
	if !ok {
		return "", "", ErrKeyUnavailable
	}
	v, err := signToken(k.Secret, purposeSession, sessionPayload{
		V:   1,
		Sid: sid,
		Exp: s.now().Add(s.sessionTTL()).Unix(),
		Kid: k.ID,
	})
	if err != nil {
		return "", "", err
	}
	return sid, v, nil
}

// parseSession 校验会话 Cookie（签名 + 过期 + 结构）；返回 sid（hex）。
func (s *Service) parseSession(value string) (string, error) {
	var p sessionPayload
	if err := verifyToken(s.cfg.Keyring, purposeSession, value, &p, s.now()); err != nil {
		return "", err
	}
	sidRaw, err := hex.DecodeString(p.Sid)
	if err != nil || len(sidRaw) != sessionIDBytes {
		return "", fmt.Errorf("session sid 非法")
	}
	return p.Sid, nil
}

// sessionDigest 会话摘要（SHA-256(sid 字节) hex；服务端状态与通行载荷只存摘要）。
func sessionDigest(sid string) string {
	raw, err := hex.DecodeString(sid)
	if err != nil {
		// sid 经 parseSession/mintSession 产生，恒为合法 hex；防御性兜底按原文哈希
		raw = []byte(sid)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ---------- 通行（clearance） ----------

// Clearance 校验通过的通行信息（B3 消费；不含任何可回放的凭据材料）。
type Clearance struct {
	FlowID    string
	SessionID string // 绑定的会话摘要
	IssuedAt  time.Time
	ExpiresAt time.Time
	KeyID     string
}

// issueClearance 签发通行 Cookie 值（载荷含应用/Host 摘要/代次/会话摘要/iat/exp/kid）。
func (s *Service) issueClearance(hostDigest, sessDigest, flowID string, now time.Time) (string, error) {
	k, ok := s.signingKey()
	if !ok {
		return "", ErrKeyUnavailable
	}
	return signToken(k.Secret, purposeClearance, clearancePayload{
		V:   1,
		App: s.cfg.AppID,
		Hh:  hostDigest,
		Sd:  sessDigest,
		Ep:  s.policyEpoch(),
		Fl:  flowID,
		Iat: now.Unix(),
		Exp: now.Add(s.cfg.ClearanceTTL).Unix(),
		Kid: k.ID,
	})
}

// parseClearance 验签并结构校验通行 Cookie（签名/exp 由 verifyToken 保证；
// 应用/Host/代次/会话绑定由调用方逐项比对——返回载荷供比对）。
func (s *Service) parseClearance(value string, now time.Time) (*clearancePayload, error) {
	var p clearancePayload
	if err := verifyToken(s.cfg.Keyring, purposeClearance, value, &p, now); err != nil {
		return nil, err
	}
	return &p, nil
}
