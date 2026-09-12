// Package learning 参数/Schema 学习版本：候选 → 人工确认冻结；冻结后不可变，偏离不扩大正式模型。
package learning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

var (
	ErrNotFound        = errors.New("model version not found")
	ErrAlreadyFrozen   = errors.New("formal model already frozen")
	ErrNotCandidate    = errors.New("only candidate versions can be confirmed")
	ErrFormalImmutable = errors.New("formal model is immutable")
)

// Status 版本状态。
type Status string

const (
	StatusCandidate  Status = "CANDIDATE"
	StatusFormal     Status = "FORMAL"
	StatusSuperseded Status = "SUPERSEDED"
)

// Version 模型版本（不可变快照内容）。
type Version struct {
	ID          string
	Endpoint    string // METHOD path-template
	Status      Status
	Schema      map[string]string // field -> type
	ContentHash string
	CreatedAt   time.Time
	// FrozenAt set when confirmed
	FrozenAt *time.Time
}

// Store 内存学习仓储（单测与进程内；服务端可有 DB 实现同一语义）。
type Store struct {
	mu       sync.Mutex
	versions map[string]*Version
	// formalByEndpoint endpoint key -> formal version id
	formal map[string]string
	// sampleSeen for pollution: track source diversity (simplified)
	samples int
}

// NewStore 创建空仓储。
func NewStore() *Store {
	return &Store{
		versions: map[string]*Version{},
		formal:   map[string]string{},
	}
}

// Observe 记录一次观测字段；达到最小样本后可生成候选（此处每次 Observe 可 CreateCandidate）。
func (s *Store) Observe(endpoint string, fields map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples++
	_ = fields
	_ = endpoint
}

// CreateCandidate 从观测 schema 创建候选版本（内容哈希固化）。
func (s *Store) CreateCandidate(endpoint string, schema map[string]string) (*Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := copySchema(schema)
	h := hashSchema(endpoint, cp)
	id := "cand-" + h[:12]
	v := &Version{
		ID: id, Endpoint: endpoint, Status: StatusCandidate,
		Schema: cp, ContentHash: h, CreatedAt: time.Now().UTC(),
	}
	s.versions[id] = v
	return cloneVersion(v), nil
}

// Confirm 人工确认：候选 → 正式冻结；原正式标为 SUPERSEDED。
func (s *Store) Confirm(versionID string) (*Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[versionID]
	if !ok {
		return nil, ErrNotFound
	}
	if v.Status != StatusCandidate {
		return nil, ErrNotCandidate
	}
	if oldID, ok := s.formal[v.Endpoint]; ok {
		if old, ok := s.versions[oldID]; ok {
			old.Status = StatusSuperseded
		}
	}
	now := time.Now().UTC()
	v.Status = StatusFormal
	v.FrozenAt = &now
	s.formal[v.Endpoint] = v.ID
	return cloneVersion(v), nil
}

// FormalSchema 返回端点冻结模型；不存在返回 nil。
func (s *Store) FormalSchema(endpoint string) map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.formal[endpoint]
	if !ok {
		return nil
	}
	v := s.versions[id]
	if v == nil {
		return nil
	}
	return copySchema(v.Schema)
}

// MutateFormal 故意尝试修改正式模型 — 必须失败（测试/防护用）。
func (s *Store) MutateFormal(endpoint string, schema map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.formal[endpoint]
	if !ok {
		return ErrNotFound
	}
	v := s.versions[id]
	if v.Status == StatusFormal {
		return ErrFormalImmutable
	}
	v.Schema = copySchema(schema)
	return nil
}

// Get 查询版本。
func (s *Store) Get(id string) (*Version, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.versions[id]
	if !ok {
		return nil, ErrNotFound
	}
	return cloneVersion(v), nil
}

func copySchema(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func cloneVersion(v *Version) *Version {
	cp := *v
	cp.Schema = copySchema(v.Schema)
	if v.FrozenAt != nil {
		t := *v.FrozenAt
		cp.FrozenAt = &t
	}
	return &cp
}

func hashSchema(endpoint string, schema map[string]string) string {
	keys := make([]string, 0, len(schema))
	for k := range schema {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	type pair struct{ K, V string }
	arr := make([]pair, 0, len(keys))
	for _, k := range keys {
		arr = append(arr, pair{k, schema[k]})
	}
	b, _ := json.Marshal(struct {
		E string
		S []pair
	}{endpoint, arr})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
