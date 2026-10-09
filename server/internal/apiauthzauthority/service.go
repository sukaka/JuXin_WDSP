// service.go 权威关系接入服务（NG-AZ-01）：五步校验链（设计 §2 冻结顺序）+
// snapshot 原子切换 / delta 增量应用 + 水位/缺口/冲突编排。
//
// 校验链（严格按序，任一失败整批 REJECTED 并逐条展示原因，不部分应用）：
//  1. 来源身份验签：source 已登记且 ACTIVE（路径 ID 与批次 source_id 一致）；
//     事件级 source_signature 按 key_id 选公钥验签（RETIRED 键仅限轮换窗口内，
//     与发布签名密钥不混用）；批次级 batch_signature 按批次 key_id 验签；
//  2. 范围权限：tenant_domain/object_type 落在来源 scopes 白名单（空数组=不限）；
//  3. 重放幂等：event_id 已消费跳过计数；(delta) sequence 必须严格大于水位且批内
//     升序——违反即乱序拒收（批次级）；(snapshot) 批次最大 sequence 必须大于水位，
//     整体推进；重放检查在应用事务内完成（水位 FOR UPDATE 防竞态）；
//  4. 大小/字段白名单：批次条数/字段长度/未知字段（严格白名单，未知字段拒收不忽略）；
//  5. 字段语义：词表（relation 仅 OWNER——共享/委托/组继承等首批不支持按 §5 拒收展示、
//     change_type/object_type）、时间关系（valid_from<valid_until、issued_at 可解析、
//     陈旧按来源 max_event_age_seconds）、引用形态（objref:/长度）、snapshot 仅 GRANT、
//     tenant_domain → ACTIVE 应用域解析。
//
// 冲突语义（设计 §3）：GRANT 时发现同对象已有不同 principal 的有效 OWNER → 不落
// 关系行，只记 ConflictRecord（不按最后到达者覆盖）；REVOKE/snapshot 使有效 OWNER
// 收敛 ≤1 时冲突自动 RESOLVED（不伪造持续冲突）。
package apiauthzauthority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Service 权威关系接入服务。
type Service struct {
	store *Store
	now   func() time.Time
}

// NewService 创建服务（now 可注入测试时钟；nil 用 time.Now）。
func NewService(store *Store) *Service {
	return &Service{store: store, now: func() time.Time { return time.Now().UTC() }}
}

// Store 存取（handler 状态视图用）。
func (s *Service) Store() *Store { return s.store }

// ---------- 读透传（handler ServiceAPI 视图） ----------

// GetSource 按 ID 读来源。
func (s *Service) GetSource(ctx context.Context, id uuid.UUID) (*AuthoritySource, error) {
	return s.store.GetSource(ctx, id)
}

// ListSources 来源列表。
func (s *Service) ListSources(ctx context.Context) ([]AuthoritySource, error) {
	return s.store.ListSources(ctx)
}

// ListSourceKeys 来源公钥列表。
func (s *Service) ListSourceKeys(ctx context.Context, sourceID uuid.UUID) ([]SourceKey, error) {
	return s.store.ListSourceKeys(ctx, sourceID)
}

// ListBatches 来源批次历史。
func (s *Service) ListBatches(ctx context.Context, sourceID uuid.UUID, limit int) ([]ImportBatch, error) {
	return s.store.ListBatches(ctx, sourceID, limit)
}

// GetWatermark 读来源水位（无锁）。
func (s *Service) GetWatermark(ctx context.Context, sourceID uuid.UUID) (SourceWatermark, error) {
	return s.store.GetWatermark(ctx, sourceID)
}

// ListConflicts 冲突列表。
func (s *Service) ListConflicts(ctx context.Context, status string, limit int) ([]ConflictRecord, error) {
	return s.store.ListConflicts(ctx, status, limit)
}

// ---------- 来源管理 ----------

// CreateSource 登记来源（initialKeys 可为空——后补钥匙经 PATCH）。
func (s *Service) CreateSource(ctx context.Context, name string, scopes SourceScopes, maxAge *int64, keys []SourceKey) (*AuthoritySource, error) {
	if err := validateSourceInput(name, scopes, maxAge); err != nil {
		return nil, err
	}
	for _, k := range keys {
		if err := validateKeyInput(k.KeyID, k.PublicKeyHex); err != nil {
			return nil, err
		}
	}
	if len(keys) > MaxSourceKeys {
		return nil, fmt.Errorf("keys 超过上限 %d", MaxSourceKeys)
	}
	src := &AuthoritySource{Name: strings.TrimSpace(name), Status: SourceStatusActive,
		Scopes: scopes, MaxEventAgeSeconds: maxAge}
	if err := s.store.CreateSource(ctx, src); err != nil {
		return nil, err
	}
	for i := range keys {
		keys[i].ID = uuid.Nil
		if err := s.store.AddSourceKey(ctx, src.ID, &keys[i]); err != nil {
			return nil, fmt.Errorf("登记验签公钥 %s: %w", keys[i].KeyID, err)
		}
	}
	return src, nil
}

// PatchSource 启停/范围/最大年龄/钥匙轮换（乐观锁；审计由 handler 完成）。
func (s *Service) PatchSource(ctx context.Context, id uuid.UUID, in SourcePatch) (*AuthoritySource, []SourceKey, error) {
	src, err := s.store.GetSource(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if in.Version != src.Version {
		return nil, nil, ErrVersionConflict
	}
	if in.Status != nil {
		switch *in.Status {
		case SourceStatusActive, SourceStatusDisabled:
			src.Status = *in.Status
		default:
			return nil, nil, fmt.Errorf("无效 status（ACTIVE/DISABLED）")
		}
	}
	if in.Scopes != nil {
		if err := validateSourceInput(src.Name, *in.Scopes, src.MaxEventAgeSeconds); err != nil {
			return nil, nil, err
		}
		src.Scopes = *in.Scopes
	}
	if in.MaxEventAgeSeconds != nil {
		if *in.MaxEventAgeSeconds != nil && **in.MaxEventAgeSeconds <= 0 {
			return nil, nil, fmt.Errorf("max_event_age_seconds 须为正（null=不限）")
		}
		src.MaxEventAgeSeconds = *in.MaxEventAgeSeconds
	}
	for _, k := range in.AddKeys {
		if err := validateKeyInput(k.KeyID, k.PublicKeyHex); err != nil {
			return nil, nil, err
		}
	}
	if len(in.AddKeys) > MaxSourceKeys {
		return nil, nil, fmt.Errorf("add_keys 超过上限 %d", MaxSourceKeys)
	}
	if err := s.store.UpdateSource(ctx, src, in.Version); err != nil {
		return nil, nil, err
	}
	for _, k := range in.AddKeys {
		nk := k
		if err := s.store.AddSourceKey(ctx, id, &nk); err != nil {
			return nil, nil, fmt.Errorf("登记验签公钥 %s: %w", k.KeyID, err)
		}
	}
	for _, keyID := range in.RetireKeys {
		if err := s.store.RetireSourceKey(ctx, id, keyID); err != nil {
			return nil, nil, fmt.Errorf("退役公钥 %s: %w", keyID, err)
		}
	}
	src.Version++
	keys, err := s.store.ListSourceKeys(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	return src, keys, nil
}

// SourcePatch PATCH 输入（nil 字段不变更）。
type SourcePatch struct {
	Status             *string       `json:"status,omitempty"`
	Scopes             *SourceScopes `json:"scopes,omitempty"`
	MaxEventAgeSeconds **int64       `json:"max_event_age_seconds,omitempty"`
	AddKeys            []SourceKey   `json:"add_keys,omitempty"`
	RetireKeys         []string      `json:"retire_keys,omitempty"`
	Version            int           `json:"version"`
}

// ---------- 校验链 ----------

// ItemError 逐条失败原因（批次级拒绝时展示）。
type ItemError struct {
	Index   int    `json:"index"`
	EventID string `json:"event_id,omitempty"`
	Step    int    `json:"step"`
	Reason  string `json:"reason"`
}

// batchFailure 批次失败（step + 逐条原因；Import 映射 REJECTED）。
type batchFailure struct {
	step  int
	items []ItemError
}

func (e *batchFailure) Error() string {
	if len(e.items) == 0 {
		return fmt.Sprintf("校验链第 %d 步失败", e.step)
	}
	return fmt.Sprintf("校验链第 %d 步失败: %s", e.step, e.items[0].Reason)
}

// rejectf 构造批次失败。
func rejectf(step int, items ...ItemError) *batchFailure {
	return &batchFailure{step: step, items: items}
}

// summary 逐条原因摘要（批次 error 字段；上限 4000 字符）。
func (e *batchFailure) summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "校验链第 %d 步失败（%d 条原因）: ", e.step, len(e.items))
	for i, it := range e.items {
		if i >= 20 {
			fmt.Fprintf(&b, "; …（其余 %d 条略）", len(e.items)-20)
			break
		}
		fmt.Fprintf(&b, "; [%d] %s", it.Index, it.Reason)
	}
	out := b.String()
	if len(out) > 4000 {
		out = out[:4000]
	}
	return out
}

// parsePayload 批次 JSON 宽松解析（结构；未知字段在第 4 步严格拒收）。
func parsePayload(body []byte) (*ImportBatchPayload, *batchFailure) {
	if len(body) > maxBatchBodyBytes {
		return nil, rejectf(4, ItemError{Step: 4, Reason: fmt.Sprintf("批次体超过 %d 字节", maxBatchBodyBytes)})
	}
	var p ImportBatchPayload
	dec := json.NewDecoder(strings.NewReader(string(body)))
	if err := dec.Decode(&p); err != nil {
		return nil, rejectf(4, ItemError{Step: 4, Reason: "批次 JSON 解析失败: " + err.Error()})
	}
	return &p, nil
}

// verifyStep1Identity 第 1 步：来源身份与两级签名验签。
func (s *Service) verifyStep1Identity(source *AuthoritySource, keys []SourceKey, p *ImportBatchPayload) *batchFailure {
	if source.Status != SourceStatusActive {
		return rejectf(1, ItemError{Step: 1, Reason: "来源已停用（DISABLED）"})
	}
	maxAge := source.maxEventAge()
	byKeyID := map[string]SourceKey{}
	for _, k := range keys {
		byKeyID[k.KeyID] = k
	}
	var items []ItemError
	// 批次签名（ACTIVE 键）
	bk, ok := byKeyID[p.KeyID]
	if !ok || bk.Status != KeyStatusActive {
		items = append(items, ItemError{Step: 1, Reason: fmt.Sprintf("批次签名 key_id %q 无 ACTIVE 公钥", p.KeyID)})
	} else if pub, err := decodePublicKey(bk.PublicKeyHex); err != nil || !verifyBatchSignature(pub, *p) {
		items = append(items, ItemError{Step: 1, Reason: "batch_signature 验签失败"})
	}
	// 事件签名（含轮换窗口）
	for i, e := range p.Items {
		k, ok := byKeyID[e.KeyID]
		if !ok {
			items = append(items, ItemError{Index: i, EventID: e.EventID, Step: 1,
				Reason: fmt.Sprintf("事件 key_id %q 未登记", e.KeyID)})
			continue
		}
		issuedAt, perr := time.Parse(time.RFC3339, e.IssuedAt)
		if perr != nil {
			items = append(items, ItemError{Index: i, EventID: e.EventID, Step: 1,
				Reason: "issued_at 不可解析（无法判定轮换窗口）"})
			continue
		}
		if !keyUsableAt(k, issuedAt, maxAge) {
			items = append(items, ItemError{Index: i, EventID: e.EventID, Step: 1,
				Reason: fmt.Sprintf("key_id %q 已于 %s 退役（轮换窗口外）", e.KeyID, k.RetiredAt)})
			continue
		}
		pub, err := decodePublicKey(k.PublicKeyHex)
		if err != nil || !verifyEventSignature(pub, e) {
			items = append(items, ItemError{Index: i, EventID: e.EventID, Step: 1, Reason: "source_signature 验签失败"})
		}
	}
	if len(items) > 0 {
		return rejectf(1, items...)
	}
	return nil
}

// maxEventAge 来源最大事件年龄（未配置取默认 24h；仅轮换窗口与陈旧判定用）。
func (s *AuthoritySource) maxEventAge() time.Duration {
	if s.MaxEventAgeSeconds != nil && *s.MaxEventAgeSeconds > 0 {
		return time.Duration(*s.MaxEventAgeSeconds) * time.Second
	}
	return DefaultMaxEventAge
}

// verifyStep2Scope 第 2 步：范围权限（空数组 = 不限该维度）。
func verifyStep2Scope(source *AuthoritySource, p *ImportBatchPayload) *batchFailure {
	domainOK := func(d string) bool {
		if len(source.Scopes.TenantDomains) == 0 {
			return true
		}
		for _, x := range source.Scopes.TenantDomains {
			if x == d {
				return true
			}
		}
		return false
	}
	typeOK := func(t string) bool {
		if len(source.Scopes.ObjectTypes) == 0 {
			return true
		}
		for _, x := range source.Scopes.ObjectTypes {
			if x == t {
				return true
			}
		}
		return false
	}
	var items []ItemError
	for i, e := range p.Items {
		if !domainOK(e.TenantDomain) {
			items = append(items, ItemError{Index: i, EventID: e.EventID, Step: 2,
				Reason: fmt.Sprintf("tenant_domain %q 不在来源范围授权内", e.TenantDomain)})
		}
		if !typeOK(e.ObjectType) {
			items = append(items, ItemError{Index: i, EventID: e.EventID, Step: 2,
				Reason: fmt.Sprintf("object_type %q 不在来源范围授权内", e.ObjectType)})
		}
	}
	if len(items) > 0 {
		return rejectf(2, items...)
	}
	return nil
}

// verifyStep4Shape 第 4 步：大小与字段白名单（严格：未知字段拒收不忽略）。
func verifyStep4Shape(body []byte, p *ImportBatchPayload) *batchFailure {
	var items []ItemError
	// 信封严格解码（未知字段拒收）
	var envelope struct {
		BatchID        string            `json:"batch_id"`
		SourceID       string            `json:"source_id"`
		Mode           string            `json:"mode"`
		KeyID          string            `json:"key_id"`
		Items          []json.RawMessage `json:"items"`
		BatchSignature string            `json:"batch_signature"`
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return rejectf(4, ItemError{Step: 4, Reason: "批次信封含未知字段或形态非法: " + err.Error()})
	}
	if p.BatchID == "" || len(p.BatchID) > MaxBatchIDLen {
		items = append(items, ItemError{Step: 4, Reason: "batch_id 必填且不超过 64 字符"})
	}
	if p.Mode != ModeSnapshot && p.Mode != ModeDelta {
		items = append(items, ItemError{Step: 4, Reason: "mode 非法（snapshot|delta）"})
	}
	if p.KeyID == "" || len(p.KeyID) > MaxKeyIDLen {
		items = append(items, ItemError{Step: 4, Reason: "批次 key_id 必填且不超过 64 字符"})
	}
	if len(p.Items) == 0 {
		items = append(items, ItemError{Step: 4, Reason: "items 不能为空"})
	}
	if len(p.Items) > MaxBatchItems {
		items = append(items, ItemError{Step: 4, Reason: fmt.Sprintf("items 超过上限 %d", MaxBatchItems)})
	}
	// 单条严格解码 + 字段长度
	for i, raw := range envelope.Items {
		var ev ChangeEvent
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		if err := d.Decode(&ev); err != nil {
			items = append(items, ItemError{Index: i, Step: 4, Reason: "事件含未知字段或形态非法: " + err.Error()})
			continue
		}
		for name, v := range map[string]string{
			"event_id": ev.EventID, "key_id": ev.KeyID, "object_type": ev.ObjectType,
			"tenant_domain": ev.TenantDomain, "principal_ref": ev.PrincipalRef,
			"object_ref": ev.ObjectRef, "source_signature": ev.SourceSignature,
		} {
			if v == "" {
				items = append(items, ItemError{Index: i, EventID: ev.EventID, Step: 4, Reason: name + " 必填"})
				continue
			}
		}
		if len(ev.EventID) > MaxEventIDLen || len(ev.KeyID) > MaxKeyIDLen ||
			len(ev.ObjectType) > MaxObjectTypeLen || len(ev.TenantDomain) > MaxTenantLen ||
			len(ev.PrincipalRef) > MaxPrincipalLen || len(ev.ObjectRef) > MaxRefLen {
			items = append(items, ItemError{Index: i, EventID: ev.EventID, Step: 4, Reason: "字段超长（event_id≤128/key_id≤64/object_type≤128/tenant≤128/principal≤128/object_ref≤160）"})
		}
		if ev.Sequence == 0 {
			items = append(items, ItemError{Index: i, EventID: ev.EventID, Step: 4, Reason: "sequence 必须 ≥1"})
		}
	}
	if len(items) > 0 {
		return rejectf(4, items...)
	}
	return nil
}

// verifyStep5Semantics 第 5 步：字段语义（词表/时间/引用形态/snapshot 全 GRANT/
// 首批不支持词表按设计 §5 拒收展示，不降级猜义）。
func (s *Service) verifyStep5Semantics(source *AuthoritySource, p *ImportBatchPayload, now time.Time) *batchFailure {
	maxAge := source.maxEventAge()
	var items []ItemError
	for i, e := range p.Items {
		fail := func(reason string) {
			items = append(items, ItemError{Index: i, EventID: e.EventID, Step: 5, Reason: reason})
		}
		if e.SourceID != source.ID.String() {
			fail("事件 source_id 与来源不一致")
		}
		if e.Relation != RelationOwner {
			fail(fmt.Sprintf("relation=%q 首批不支持（共享/委托/组继承/批量对象/复合 ID 一律按不支持拒收，不降级猜义）", e.Relation))
		}
		if e.ChangeType != ChangeGrant && e.ChangeType != ChangeRevoke {
			fail("change_type 非法（GRANT|REVOKE）")
		}
		if p.Mode == ModeSnapshot && e.ChangeType != ChangeGrant {
			fail("snapshot 批次仅接受 GRANT（全量状态语义；不在集合即撤销）")
		}
		if !identifierPattern.MatchString(e.ObjectType) {
			fail("object_type 形态非法（标识符白名单）")
		}
		if !strings.HasPrefix(e.ObjectRef, "objref:") {
			fail("object_ref 必须是 objref: HMAC 引用形态")
		}
		vf, err1 := time.Parse(time.RFC3339, e.ValidFrom)
		if err1 != nil {
			fail("valid_from 不可解析（RFC3339）")
		}
		if e.ValidUntil != "" {
			vu, err2 := time.Parse(time.RFC3339, e.ValidUntil)
			if err2 != nil {
				fail("valid_until 不可解析（RFC3339）")
			} else if err1 == nil && !vu.After(vf) {
				fail("valid_from 必须早于 valid_until")
			}
		}
		issuedAt, err3 := time.Parse(time.RFC3339, e.IssuedAt)
		if err3 != nil {
			fail("issued_at 不可解析（RFC3339）")
		} else {
			if source.MaxEventAgeSeconds != nil && now.Sub(issuedAt) > maxAge {
				fail(fmt.Sprintf("事件陈旧（issued_at 早于来源最大可接受年龄 %s）", maxAge))
			}
			if issuedAt.After(now.Add(5 * time.Minute)) {
				fail("issued_at 超前当前时间超过 5 分钟（时钟漂移容忍外）")
			}
		}
	}
	if len(items) > 0 {
		return rejectf(5, items...)
	}
	return nil
}

// ---------- 导入编排 ----------

// Import 离线签名批次导入（五步校验链 → snapshot/delta 应用；批次留痕恒入库）。
func (s *Service) Import(ctx context.Context, sourceID uuid.UUID, body []byte, actorID uuid.UUID) (*ImportBatch, error) {
	batch := &ImportBatch{ID: uuid.New(), SourceID: sourceID, CreatedBy: &actorID}
	batchPersist := true // 未登记来源无 FK 落点：留痕跳过（结果照常返回，见下）
	payload, perr := parsePayload(body)
	if perr == nil {
		batch.Mode = payload.Mode
	}
	finish := func(fail *batchFailure) (*ImportBatch, error) {
		batch.Status = BatchRejected
		batch.Error = fail.summary()
		if batch.Mode == "" {
			batch.Mode = ModeDelta // 留痕占位（解析失败场景）
		}
		if batchPersist {
			// 未登记来源无 FK 落点：留痕跳过（结果照常 REJECTED 返回；设计附录 D6）
			if _, err := s.store.GetSource(ctx, sourceID); err != nil {
				if errors.Is(err, ErrNotFound) {
					batchPersist = false
				} else {
					return nil, err
				}
			}
		}
		if batchPersist {
			if err := s.store.InsertBatch(ctx, batch); err != nil {
				return nil, err
			}
		}
		return batch, nil
	}
	if perr != nil {
		return finish(perr)
	}
	if payload.SourceID != sourceID.String() {
		return finish(rejectf(1, ItemError{Step: 1, Reason: "批次 source_id 与路径来源不一致"}))
	}

	source, err := s.store.GetSource(ctx, sourceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			batchPersist = false // 批次表 source_id FK 落点不存在——留痕跳过（设计附录 D6）
			return finish(rejectf(1, ItemError{Step: 1, Reason: "来源未登记（不自动登记）"}))
		}
		return nil, err
	}
	keys, err := s.store.ListSourceKeys(ctx, sourceID)
	if err != nil {
		return nil, err
	}

	// 第 1 步：来源身份验签
	if fail := s.verifyStep1Identity(source, keys, payload); fail != nil {
		return finish(fail)
	}
	// 第 2 步：范围权限
	if fail := verifyStep2Scope(source, payload); fail != nil {
		return finish(fail)
	}
	// 第 4 步：大小与字段白名单（第 3 步重放检查在应用事务内，见下）
	if fail := verifyStep4Shape(body, payload); fail != nil {
		return finish(fail)
	}
	// 第 5 步：字段语义
	if fail := s.verifyStep5Semantics(source, payload, s.now()); fail != nil {
		return finish(fail)
	}

	// delta：批内 sequence 严格升序（乱序拒收展示）
	if payload.Mode == ModeDelta {
		items := append([]ChangeEvent(nil), payload.Items...)
		sort.Slice(items, func(i, j int) bool { return items[i].Sequence < items[j].Sequence })
		for i := range items {
			if items[i].Sequence != payload.Items[i].Sequence {
				return finish(rejectf(3, ItemError{Index: i, Step: 3,
					Reason: "delta 批次 items 未按 sequence 升序（乱序拒收）"}))
			}
		}
	}

	// 应用（第 3 步重放检查在事务内水位锁下完成）
	var applyErr error
	var fail *batchFailure
	batch.Counts, fail, applyErr = s.applyBatch(ctx, source, payload, batch.ID)
	if applyErr != nil {
		return nil, applyErr
	}
	if fail != nil {
		return finish(fail)
	}
	batch.Status = BatchApplied
	if err := s.store.InsertBatch(ctx, batch); err != nil {
		return nil, err
	}
	return batch, nil
}
