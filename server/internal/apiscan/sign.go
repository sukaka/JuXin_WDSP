// sign.go 扫描流量隔离签名（设计稿 §8.1）：探针请求携带 X-JiuZhang-Scan 头，
// 值为 "{job_id}.{unix_ts}.{hex(HMAC-SHA256(key, job_id|unix_ts))}"（时效签名，
// ±signTimeWindow 时间窗），供网关识别扫描流量
// （学习样本排除 / 事件打标 / 决策隔离；网关侧校验实现见
// gateway/dynamic_security/detectors/scanner.go verifyScanSignature——两端构造
// 与窗口取值必须保持一致）。密钥由管理面生成并经加密落设置表（LoadOrCreateSigner）。
package apiscan

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ScanHeader 扫描隔离签名头名（设计稿 §8.1 规划名）。
const ScanHeader = "X-JiuZhang-Scan"

// signTimeWindow 签名时间窗（±5 分钟；与网关 detectors.scanSignatureTimeWindow 同一取值）：
// ts 与校验侧本地时钟偏差在窗口内才接受——无时窗的签名泄漏后可无限重放污染学习样本，
// 窗口取值容忍两端时钟偏差与在途时延。
const signTimeWindow = 5 * time.Minute

// 签名密钥在设置表的位置（api_scan.signing_key，值为加密后的 hex 密钥）。
const (
	signingKeySettingsGroup = "api_scan"
	signingKeySettingsKey   = "signing_key"
)

// ErrInvalidSigningKey 签名密钥长度非法（须 32 字节）。
var ErrInvalidSigningKey = errors.New("api scan signing key must be 32 bytes")

// Signer 扫描签名器（HMAC-SHA256）。
type Signer struct {
	key []byte
}

// NewSigner 用给定密钥创建签名器（密钥须 32 字节；拷贝持有）。
func NewSigner(key []byte) (*Signer, error) {
	if len(key) != 32 {
		return nil, ErrInvalidSigningKey
	}
	k := make([]byte, 32)
	copy(k, key)
	return &Signer{key: k}, nil
}

// GenerateSigningKey 生成随机签名密钥（32 字节）。
func GenerateSigningKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Sign 计算任务签名头值："{job_id}.{unix_ts}.{hex(HMAC-SHA256(key, job_id|unix_ts))}"
// （时效签名；unix_ts 为签名时刻 Unix 秒十进制，HMAC 消息为 "job_id|unix_ts"，
// pipe 分隔与网关侧校验同一构造）。
func (s *Signer) Sign(jobID uuid.UUID) string {
	return s.signAt(jobID, time.Now())
}

// signAt Sign 的可测实现（now 可注入，时间窗判定可复现）。
func (s *Signer) signAt(jobID uuid.UUID, now time.Time) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(jobID.String() + "|" + ts))
	return jobID.String() + "." + ts + "." + hex.EncodeToString(mac.Sum(nil))
}

// Verify 校验签名头值（时效签名：ts 须可解析且与本地时钟偏差在 ±signTimeWindow 内，
// 过期/未来超限即拒绝），返回其中的任务 ID 与校验结果（与网关侧
// detectors.verifyScanSignature 同一契约；job/ts 按原文参与 HMAC，不做归一化宽容）。
func (s *Signer) Verify(value string) (uuid.UUID, bool) {
	return s.verifyAt(value, time.Now())
}

// verifyAt Verify 的可测实现（now 可注入）。
func (s *Signer) verifyAt(value string, now time.Time) (uuid.UUID, bool) {
	// 形态 "{job_id}.{unix_ts}.{hex sig}"：job_id 为 uuid（无点），两段 Cut 依次拆出
	jobPart, rest, _ := strings.Cut(value, ".")
	tsPart, sigPart, _ := strings.Cut(rest, ".")
	if jobPart == "" || tsPart == "" || sigPart == "" {
		return uuid.Nil, false
	}
	jobID, err := uuid.Parse(jobPart)
	if err != nil {
		return uuid.Nil, false
	}
	ts, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return uuid.Nil, false
	}
	sig, err := hex.DecodeString(sigPart)
	if err != nil || len(sig) != sha256.Size {
		return uuid.Nil, false
	}
	if d := now.Sub(time.Unix(ts, 0)); d < -signTimeWindow || d > signTimeWindow {
		return uuid.Nil, false
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(jobPart + "|" + tsPart))
	return jobID, hmac.Equal(sig, mac.Sum(nil))
}

// SettingsKV 设置读写接口（*settings.Service 实现；密钥密文落系统设置）。
type SettingsKV interface {
	GetString(ctx context.Context, group, key, def string) string
	UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
}

// Encryptor 加解密接口（*encryption.Service 实现；密钥密文不落明文）。
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// LoadOrCreateSigner 从设置表加载签名密钥（密文存储，经 enc 解密）；不存在则生成并加密落库。
// 密钥本身不出现在任务、快照、审计正文与事件证据中（与凭据纪律同则）。
func LoadOrCreateSigner(ctx context.Context, kv SettingsKV, enc Encryptor) (*Signer, error) {
	if kv == nil || enc == nil {
		return nil, errors.New("apiscan: settings/encryption 未装配，无法加载扫描签名密钥")
	}
	if raw := strings.TrimSpace(kv.GetString(ctx, signingKeySettingsGroup, signingKeySettingsKey, "")); raw != "" {
		plain, err := enc.Decrypt(raw)
		if err != nil {
			return nil, fmt.Errorf("apiscan: 解密扫描签名密钥失败: %w", err)
		}
		key, err := hex.DecodeString(plain)
		if err != nil {
			return nil, fmt.Errorf("apiscan: 扫描签名密钥格式非法: %w", err)
		}
		return NewSigner(key)
	}
	key, err := GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	cipherText, err := enc.Encrypt(hex.EncodeToString(key))
	if err != nil {
		return nil, fmt.Errorf("apiscan: 加密扫描签名密钥失败: %w", err)
	}
	if err := kv.UpsertString(ctx, signingKeySettingsGroup, signingKeySettingsKey, cipherText,
		"API 主动扫描流量隔离签名密钥（HMAC，密文存储）", uuid.Nil); err != nil {
		return nil, fmt.Errorf("apiscan: 落库扫描签名密钥失败: %w", err)
	}
	return NewSigner(key)
}
