// types.go 权威关系接入类型（NG-AZ-01，docs/nextgen/NG-AZ-01-authority-ingest.md §1 冻结契约）。
//
// 契约补充决策（设计附录「实现状态」如实登记）：
//   - 事件携带 key_id（签名字段之一）：设计 §2 第 1 步「按 key_id 选公钥（多公钥轮换）」
//     需要键引用落点；key_id 纳入规范化签名输入，防替换；
//   - 批次携带 key_id：batch_signature 的验签键选择（多 ACTIVE 公钥轮换期可区分）；
//   - snapshot 批次仅接受 GRANT 项：全量状态语义（REVOKE 在 snapshot 中无意义——
//     全量替换即「不在集合即撤销」，语义校验拒收并展示原因）；
//   - tenant_domain → application_id 解析：管理面 ACTIVE 应用域（application_domains
//     normalized_hostname）；解析不到/多义即第 5 步语义失败（关系表 application_id
//     NOT NULL FK 的落点）；
//   - REVOKE 作用域：仅撤销本来源（source_id 相同）AUTHORITY_SYNC 有效行——来源只管
//     自己签发的事实，不撤销 MANUAL/其他来源关系（历史推断恒无阻断资格同纪律）。
package apiauthzauthority

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 来源状态词表。
const (
	SourceStatusActive   = "ACTIVE"
	SourceStatusDisabled = "DISABLED"
)

// 密钥状态词表。
const (
	KeyStatusActive  = "ACTIVE"
	KeyStatusRetired = "RETIRED"
)

// 批次模式与状态词表。
const (
	ModeSnapshot     = "snapshot"
	ModeDelta        = "delta"
	BatchApplied     = "APPLIED"
	BatchRejected    = "REJECTED"
	ChangeGrant      = "GRANT"
	ChangeRevoke     = "REVOKE"
	RelationOwner    = "OWNER"
	ConflictOpen     = "OPEN"
	ConflictResolved = "RESOLVED"
)

// RelationSourceAuthoritySync 权威同步溯源词（api_object_relations.source，迁移 000172 扩词表）。
const RelationSourceAuthoritySync = "AUTHORITY_SYNC"

// 上限（校验链第 4 步；与设计 §1 字段约束一致口径）。
const (
	MaxBatchItems        = 1000
	MaxEventIDLen        = 128
	MaxKeyIDLen          = 64
	MaxNameLen           = 128
	MaxRefLen            = 160 // object_ref 与关系表列宽一致
	MaxPrincipalLen      = 128 // principal_ref 与关系表列宽一致
	MaxObjectTypeLen     = 128
	MaxTenantLen         = 128
	MaxBatchIDLen        = 64
	MaxScopeEntries      = 256
	MaxSourceKeys        = 16
	DefaultMaxEventAge   = 24 * time.Hour // max_event_age_seconds 未配置时的轮换窗口/陈旧默认
	maxBatchBodyBytes    = 8 << 20
	identifierPatternStr = `^[A-Za-z0-9_.\-:]+$`
)

var identifierPattern = regexp.MustCompile(identifierPatternStr)

// SourceScopes 来源范围授权（校验链第 2 步白名单；空数组 = 不限制该维度）。
type SourceScopes struct {
	TenantDomains []string `json:"tenant_domains"`
	ObjectTypes   []string `json:"object_types"`
}

// AuthoritySource 权威来源登记。
type AuthoritySource struct {
	ID                 uuid.UUID    `json:"id"`
	Name               string       `json:"name"`
	Status             string       `json:"status"`
	Scopes             SourceScopes `json:"scopes"`
	MaxEventAgeSeconds *int64       `json:"max_event_age_seconds"` // 可空=不限（仅轮换窗口用默认值）
	CreatedAt          time.Time    `json:"created_at"`
	UpdatedAt          time.Time    `json:"updated_at"`
	Version            int          `json:"version"`
}

// SourceKey 来源验签公钥（Ed25519；三把钥匙不混用——与发布签名密钥/对象 HMAC 密钥隔离）。
type SourceKey struct {
	ID           uuid.UUID  `json:"id"`
	KeyID        string     `json:"key_id"`
	PublicKeyHex string     `json:"public_key_hex"`
	Status       string     `json:"status"`
	RetiredAt    *time.Time `json:"retired_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// ImportBatch 导入批次（审计留痕；REJECTED 批次同样入库——不属于关系原子区）。
type ImportBatch struct {
	ID        uuid.UUID   `json:"id"`
	SourceID  uuid.UUID   `json:"source_id"`
	Mode      string      `json:"mode"`
	Status    string      `json:"status"`
	Counts    BatchCounts `json:"counts"`
	Error     string      `json:"error,omitempty"`
	CreatedBy *uuid.UUID  `json:"created_by,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
}

// BatchCounts 批次计数（applied/skipped_duplicate/skipped_stale/conflicts/grants/revokes）。
type BatchCounts struct {
	Applied          int `json:"applied"`
	SkippedDuplicate int `json:"skipped_duplicate"`
	SkippedStale     int `json:"skipped_stale"`
	Grants           int `json:"grants"`
	Revokes          int `json:"revokes"`
	Conflicts        int `json:"conflicts"`
}

// ChangeEvent 权威变更事件（设计 §1 全字段 + key_id 契约补充；签名字段见 canonical.go）。
type ChangeEvent struct {
	SourceID        string `json:"source_id"`
	EventID         string `json:"event_id"`
	KeyID           string `json:"key_id"`
	Sequence        uint64 `json:"sequence"`
	ObjectType      string `json:"object_type"`
	TenantDomain    string `json:"tenant_domain"`
	PrincipalRef    string `json:"principal_ref"`
	ObjectRef       string `json:"object_ref"`
	Relation        string `json:"relation"`
	ChangeType      string `json:"change_type"`
	ValidFrom       string `json:"valid_from"`
	ValidUntil      string `json:"valid_until,omitempty"`
	IssuedAt        string `json:"issued_at"`
	SourceSignature string `json:"source_signature"`
}

// ImportBatchPayload 批次契约（{batch_id, source_id, mode, key_id, items[], batch_signature}）。
type ImportBatchPayload struct {
	BatchID        string        `json:"batch_id"`
	SourceID       string        `json:"source_id"`
	Mode           string        `json:"mode"`
	KeyID          string        `json:"key_id"`
	Items          []ChangeEvent `json:"items"`
	BatchSignature string        `json:"batch_signature"`
}

// ConflictRecord 冲突状态（同对象两个不同 principal 的有效 OWNER；不按最后到达者覆盖）。
type ConflictRecord struct {
	ID            uuid.UUID `json:"id"`
	ApplicationID uuid.UUID `json:"application_id"`
	ObjectType    string    `json:"object_type"`
	TenantDomain  string    `json:"tenant_domain"`
	ObjectRef     string    `json:"object_ref"`
	Principals    []string  `json:"principals"`
	Status        string    `json:"status"`
	FirstSeen     time.Time `json:"first_seen"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// SourceWatermark 来源水位（last_sequence/revocation_watermark 单调不下降；
// gap_from 可空=无缺口——AUTHZ_SOURCE_GAP 由 status 视图按 gap_from 非空派生）。
type SourceWatermark struct {
	LastSequence        uint64    `json:"last_sequence"`
	LastEventID         string    `json:"last_event_id"`
	RevocationWatermark uint64    `json:"revocation_watermark"`
	GapFrom             *uint64   `json:"gap_from"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// ---------- 输入校验（登记/轮换路径；事件级校验在 verify.go 五步链） ----------

// validateSourceInput 来源登记/更新输入校验（名称/范围/最大年龄形态）。
func validateSourceInput(name string, scopes SourceScopes, maxAge *int64) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > MaxNameLen {
		return fmt.Errorf("name 必填且不超过 %d 字符", MaxNameLen)
	}
	if len(scopes.TenantDomains) > MaxScopeEntries || len(scopes.ObjectTypes) > MaxScopeEntries {
		return fmt.Errorf("scopes 各维度不超过 %d 条", MaxScopeEntries)
	}
	for _, d := range scopes.TenantDomains {
		if d == "" || len(d) > MaxTenantLen {
			return fmt.Errorf("scopes.tenant_domains 含空/超长项")
		}
	}
	for _, t := range scopes.ObjectTypes {
		if t == "" || len(t) > MaxObjectTypeLen || !identifierPattern.MatchString(t) {
			return fmt.Errorf("scopes.object_types 含非法项: %q", t)
		}
	}
	if maxAge != nil && *maxAge <= 0 {
		return fmt.Errorf("max_event_age_seconds 须为正（可空=不限）")
	}
	return nil
}

// validateKeyInput 验签公钥登记校验（key_id 形态 + 32 字节 Ed25519 hex）。
func validateKeyInput(keyID, publicKeyHex string) error {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" || len(keyID) > MaxKeyIDLen || !identifierPattern.MatchString(keyID) {
		return fmt.Errorf("key_id 非法（≤%d，标识符白名单）", MaxKeyIDLen)
	}
	if len(publicKeyHex) != 64 {
		return fmt.Errorf("public_key 须为 32 字节 Ed25519 公钥 hex（64 字符）")
	}
	for _, c := range publicKeyHex {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("public_key 须为小写 hex")
		}
	}
	return nil
}
