package identitybehavior

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// 事件记录类型（record_type 字段）。
const (
	RecordIdentityObservation = "identity_observation"
	RecordBehaviorSnapshot    = "behavior_snapshot"
	RecordReconSignal         = "recon_signal"
)

// 节流间隔（进程内 LRU，防扫描洪泛撑爆日志）：
//   - identity_observation 每 identity 5 分钟最多 1 条（IP 不在已知集或凭据变化立即发；
//     已知集 = 每 identity 最近 16 个发出 IP，超出淘汰最旧——已知 IP 回归不重复发，
//     防同身份多 IP 轮换（AI 自动化渗透典型特征）把「新 IP 立即发」打成观测洪泛）；
//   - behavior_snapshot 每 identity 60s 最多 1 条（1m 桶起点轮转时立即补发 1 条；
//     轮转补发的 1m 记录回放刚完成桶原始整数计数，window_start=上一桶，其余窗口保持
//     当前滑窗估值）；
//   - recon_signal 每 (identity,rule_code) 60s 最多 1 条。
const (
	observationThrottle = 5 * time.Minute
	snapshotThrottle    = time.Minute
	signalThrottle      = time.Minute
)

// throttleCap 各节流 LRU 容量（identity 键量级与内存存储一致）。
const throttleCap = 50000

// obsKnownIPsCap identity_observation 已知 IP 集上限（每 identity 记最近 N 个发出 IP，
// 超出淘汰最旧；16 覆盖常见代理池规模，内存有界：throttleCap × N 个短字符串）。
const obsKnownIPsCap = 16

// 字段长度上限（防超大输入撑爆日志；与 events/apievents 同一纪律）。
const (
	maxEventPathLen   = 512
	maxEventDomainLen = 255
	maxEventUALen     = 255
	maxEventMethodLen = 64
)

// CommonRecord 三种事件记录的公共字段（引擎按请求构建一次）。
type CommonRecord struct {
	RequestID          string
	OccurredAt         time.Time
	AppID              string
	AppCode            string
	Domain             string
	Method             string
	Path               string
	IdentityKey        string
	IdentityType       string
	IdentityConfidence uint8
	IdentityEvidence   []string
	ClientIP           string
	UserAgent          string
	TLSFingerprint     string
	BrowserFingerprint string
}

// commonJSON 公共字段 JSON 视图（snake_case；三种记录内嵌复用）。
type commonJSON struct {
	RecordType         string    `json:"record_type"`
	RequestID          string    `json:"request_id"`
	OccurredAt         time.Time `json:"occurred_at"`
	GatewayNode        string    `json:"gateway_node"`
	AppID              string    `json:"app_id,omitempty"`
	AppCode            string    `json:"app_code,omitempty"`
	Domain             string    `json:"domain,omitempty"`
	Method             string    `json:"method,omitempty"`
	Path               string    `json:"path,omitempty"`
	IdentityKey        string    `json:"identity_key"`
	IdentityType       string    `json:"identity_type"`
	IdentityConfidence uint8     `json:"identity_confidence"`
	IdentityEvidence   []string  `json:"identity_evidence,omitempty"`
	ClientIP           string    `json:"client_ip"`
	UserAgent          string    `json:"user_agent,omitempty"`
	TLSFingerprint     string    `json:"tls_fingerprint,omitempty"`
	BrowserFingerprint string    `json:"browser_fingerprint,omitempty"`
}

type identityObservationJSON struct {
	commonJSON
	Credentials []Credential `json:"credentials"`
}

// WindowRecord behavior_snapshot 单窗口 JSON 视图（计数四舍五入为整型呈现）。
type WindowRecord struct {
	WindowStart            time.Time `json:"window_start"`
	RequestCount           int64     `json:"request_count"`
	UniqueURICount         int64     `json:"unique_uri_count"`
	NewURICount            int64     `json:"new_uri_count"`
	Status401Count         int64     `json:"status_401_count"`
	Status403Count         int64     `json:"status_403_count"`
	Status404Count         int64     `json:"status_404_count"`
	Status405Count         int64     `json:"status_405_count"`
	Status500Count         int64     `json:"status_500_count"`
	AuthFailCount          int64     `json:"auth_fail_count"`
	ParameterMutationCount int64     `json:"parameter_mutation_count"`
	SensitivePathHits      int64     `json:"sensitive_path_hits"`
	AccountEnumCount       int64     `json:"account_enum_count"`
	ObjectEnumCount        int64     `json:"object_enum_count"`
}

type behaviorSnapshotJSON struct {
	commonJSON
	Windows map[string]WindowRecord `json:"windows"`
}

type reconSignalJSON struct {
	commonJSON
	RuleCode       string         `json:"rule_code"`
	RuleVersion    string         `json:"rule_version"`
	Signal         string         `json:"signal"`
	RiskScoreDelta int            `json:"risk_score_delta"`
	Mode           string         `json:"mode"`
	Reason         string         `json:"reason"`
	Window         string         `json:"window"`
	Metadata       map[string]any `json:"metadata"`
}

// obsThrottleEntry identity_observation 节流状态：上次发出时间、有界已知 IP 集
// （超出 obsKnownIPsCap 淘汰最旧）、凭据摘要（新 IP / 新凭据立即放行）。
type obsThrottleEntry struct {
	last time.Time
	ips  []string // 已知 IP（插入序即新旧序；再发移到最新位）
	cred string   // 凭据摘要（类型+指纹集）
}

// knownIP IP 是否已在已知集（已知 IP 回归不重复发——多 IP 轮换防洪泛核心判定）。
func (e *obsThrottleEntry) knownIP(ip string) bool {
	for _, k := range e.ips {
		if k == ip {
			return true
		}
	}
	return false
}

// rememberIP 发出时把 IP 记入已知集（已存在则移到最新位；超出上限淘汰最旧）。
func (e *obsThrottleEntry) rememberIP(ip string) {
	for i, k := range e.ips {
		if k == ip {
			e.ips = append(e.ips[:i], e.ips[i+1:]...)
			break
		}
	}
	e.ips = append(e.ips, ip)
	if len(e.ips) > obsKnownIPsCap {
		e.ips = e.ips[len(e.ips)-obsKnownIPsCap:]
	}
}

// snapshotThrottleEntry behavior_snapshot 节流状态：上次发出时间与当时的 1m 桶起点。
type snapshotThrottleEntry struct {
	last     time.Time
	bucket1m time.Time
}

// EventLogger 身份行为事件 JSONL 记录器（并发安全；写失败 zap Warn 不阻断请求；
// 记录类型与节流见包注释）。
type EventLogger struct {
	mu     sync.Mutex
	f      *os.File
	node   string
	logger *zap.Logger
	now    func() time.Time

	obs  *lru // identity -> *obsThrottleEntry
	snap *lru // identity -> *snapshotThrottleEntry
	sig  *lru // identity|rule_code -> time.Time
}

// NewEventLogger 打开身份事件日志文件（追加写入；node 写入 gateway_node 字段）。
func NewEventLogger(path, node string, logger *zap.Logger) (*EventLogger, error) {
	if path == "" {
		return nil, fmt.Errorf("identity events log path required")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("open identity events log: %w", err)
	}
	return &EventLogger{
		f:      f,
		node:   node,
		logger: logger,
		now:    time.Now,
		obs:    newLRU(throttleCap),
		snap:   newLRU(throttleCap),
		sig:    newLRU(throttleCap),
	}, nil
}

// EmitIdentityObservation 身份观测记录。发出条件（满足其一即发出，并刷新节流状态）：
//   - 距上次发出 ≥ 5min；
//   - IP 不在已知集（每 identity 记最近 16 个发出 IP，超出淘汰最旧）——新 IP 立即发；
//   - 凭据摘要变化——新凭据立即发（凭据判定逻辑与旧实现一致）。
//
// 身份环境变化是观测重点；已知 IP 回归不重复发——旧实现只记上次发出的单个 IP，同身份
// 多 IP 轮换（AI 自动化渗透典型特征）时几乎每个请求都被当「新 IP」，5min 节流形同虚设。
func (l *EventLogger) EmitIdentityObservation(base CommonRecord, creds []Credential) {
	credSummary := credentialSummary(creds)
	l.mu.Lock()
	defer l.mu.Unlock() // defer 释放：内部任何 panic 不得楔死记录器（fail-open 纪律）
	now := l.now()
	emit := true
	if v, ok := l.obs.get(base.IdentityKey); ok {
		e := v.(*obsThrottleEntry)
		if now.Sub(e.last) < observationThrottle && e.cred == credSummary && e.knownIP(base.ClientIP) {
			emit = false
		} else {
			e.last, e.cred = now, credSummary
			e.rememberIP(base.ClientIP)
		}
	} else {
		entry := &obsThrottleEntry{last: now, cred: credSummary}
		entry.rememberIP(base.ClientIP)
		l.obs.set(base.IdentityKey, entry)
	}
	if emit {
		if creds == nil {
			creds = []Credential{}
		}
		l.writeLocked(identityObservationJSON{
			commonJSON:  l.commonLocked(RecordIdentityObservation, base, now),
			Credentials: creds,
		})
	}
}

// EmitBehaviorSnapshot 行为快照记录。发出条件（满足其一即发出，并同步刷新节流状态）：
//   - 距上次发出 ≥ snapshotThrottle（60s 节流，防扫描洪泛撑爆日志）：1m 记录为当前
//     滑窗估值（window_start=当前桶），行为与旧实现一致；
//   - 1m 桶起点发生轮转：立即补发，1m 记录回放刚完成桶的原始整数计数
//     （window_start=上一桶，取自 Snapshot.CompletedWindow；无双桶数据时为全 0，
//     当前桶计数随下次轮转回放），其余窗口保持当前滑窗估值。server 端按
//     (identity,window_type,window_start) UPSERT 覆盖语义天然去重——早期估值行会被
//     完成桶原始计数覆盖。
//
// 注意：非轮转记录（首发/60s 节流）的 1m 计数仍为滑动窗估算语义；孤立短突发全程不跨
// 1m 桶边界且之后无请求时，尾部计数无轮转快照可回放，仍可能少计（残余语义）。
func (l *EventLogger) EmitBehaviorSnapshot(base CommonRecord, snap *Snapshot) {
	if snap == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	curBucket := snap.Windows[Window1m].WindowStart
	emit := true
	rotated := false
	if v, ok := l.snap.get(base.IdentityKey); ok {
		e := v.(*snapshotThrottleEntry)
		if now.Sub(e.last) < snapshotThrottle && curBucket.Equal(e.bucket1m) {
			emit = false
		} else {
			rotated = !curBucket.Equal(e.bucket1m)
			e.last, e.bucket1m = now, curBucket
		}
	} else {
		l.snap.set(base.IdentityKey, &snapshotThrottleEntry{last: now, bucket1m: curBucket})
	}
	if emit {
		windows := make(map[string]WindowRecord, NumWindows)
		for w := Window1m; w < NumWindows; w++ {
			windows[w.Name()] = windowRecord(snap.Windows[w])
		}
		if rotated {
			// 轮转补发：1m 回放刚完成桶原始计数（桶起点=上一桶），不用当前滑窗估值
			windows[Window1m.Name()] = windowRecord(snap.CompletedWindow)
		}
		l.writeLocked(behaviorSnapshotJSON{
			commonJSON: l.commonLocked(RecordBehaviorSnapshot, base, now),
			Windows:    windows,
		})
	}
}

// EmitReconSignal 侦察信号记录（节流：每 (identity,rule_code) 60s 至多 1 条）。
func (l *EventLogger) EmitReconSignal(base CommonRecord, sig Signal) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	key := base.IdentityKey + "|" + sig.RuleCode
	emit := true
	if v, ok := l.sig.get(key); ok {
		if now.Sub(v.(time.Time)) < signalThrottle {
			emit = false
		} else {
			l.sig.set(key, now)
		}
	} else {
		l.sig.set(key, now)
	}
	if emit {
		meta := sig.Metadata
		if meta == nil {
			meta = map[string]any{}
		}
		l.writeLocked(reconSignalJSON{
			commonJSON:     l.commonLocked(RecordReconSignal, base, now),
			RuleCode:       sig.RuleCode,
			RuleVersion:    sig.RuleVersion,
			Signal:         sig.Signal,
			RiskScoreDelta: sig.ScoreDelta,
			Mode:           sig.Mode,
			Reason:         sig.Reason,
			Window:         sig.Window,
			Metadata:       meta,
		})
	}
}

// commonLocked 构建公共字段（调用方持锁；字段去敏截断——防日志注入，JSON 转义为第二道防线）。
func (l *EventLogger) commonLocked(recordType string, base CommonRecord, now time.Time) commonJSON {
	occurred := base.OccurredAt
	if occurred.IsZero() {
		occurred = now
	}
	return commonJSON{
		RecordType:         recordType,
		RequestID:          sanitize(base.RequestID, maxEventPathLen),
		OccurredAt:         occurred,
		GatewayNode:        l.node,
		AppID:              sanitize(base.AppID, maxEventMethodLen),
		AppCode:            sanitize(base.AppCode, maxEventMethodLen),
		Domain:             sanitize(base.Domain, maxEventDomainLen),
		Method:             sanitize(base.Method, maxEventMethodLen),
		Path:               sanitize(base.Path, maxEventPathLen),
		IdentityKey:        base.IdentityKey,
		IdentityType:       base.IdentityType,
		IdentityConfidence: base.IdentityConfidence,
		IdentityEvidence:   append([]string(nil), base.IdentityEvidence...),
		ClientIP:           base.ClientIP,
		UserAgent:          sanitize(base.UserAgent, maxEventUALen),
		TLSFingerprint:     base.TLSFingerprint,
		BrowserFingerprint: base.BrowserFingerprint,
	}
}

// writeLocked 序列化并写入一行（调用方持锁；失败 zap Warn，不阻断请求）。
func (l *EventLogger) writeLocked(rec any) {
	data, err := json.Marshal(rec)
	if err != nil {
		if l.logger != nil {
			l.logger.Warn("identitybehavior: marshal event failed", zap.Error(err))
		}
		return
	}
	if _, err := l.f.Write(append(data, '\n')); err != nil && l.logger != nil {
		l.logger.Warn("identitybehavior: write event failed", zap.Error(err))
	}
}

// Close 关闭文件（重复调用安全——第二次返回 nil）。
func (l *EventLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// windowRecord 单窗口 JSON 视图（浮点估值四舍五入为整型）。
func windowRecord(w WindowCounts) WindowRecord {
	return WindowRecord{
		WindowStart:            w.WindowStart,
		RequestCount:           int64(math.Round(w.RequestCount)),
		UniqueURICount:         w.UniqueURICount,
		NewURICount:            int64(math.Round(w.NewURICount)),
		Status401Count:         int64(math.Round(w.Status401Count)),
		Status403Count:         int64(math.Round(w.Status403Count)),
		Status404Count:         int64(math.Round(w.Status404Count)),
		Status405Count:         int64(math.Round(w.Status405Count)),
		Status500Count:         int64(math.Round(w.Status500Count)),
		AuthFailCount:          int64(math.Round(w.AuthFailCount)),
		ParameterMutationCount: int64(math.Round(w.ParameterMutationCount)),
		SensitivePathHits:      int64(math.Round(w.SensitivePathHits)),
		AccountEnumCount:       w.AccountEnumCount,
		ObjectEnumCount:        w.ObjectEnumCount,
	}
}

// credentialSummary 凭据摘要（类型+指纹串联；判定「新凭据」用，无明文）。
func credentialSummary(creds []Credential) string {
	var sb strings.Builder
	for _, c := range creds {
		sb.WriteString(string(c.Type))
		sb.WriteByte(':')
		sb.WriteString(c.Hash)
		sb.WriteByte(';')
	}
	return sb.String()
}

// sanitize 截断超长字段、剥离控制字符（防日志注入）。
func sanitize(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}
