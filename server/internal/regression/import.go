// import.go 回归报告导入核验管线（任务书 §7.1）。
//
// 顺序固定：manifest 规范形/schema → 签名（算法/key_id/撤销/验签）→ 幂等判定
// → 全部必需对象哈希与类别限额逐块校验 → 用例唯一性与计数对账 → 单事务落库。
// 任何一步失败：不落任何运行记录（不残留可用的半份报告），调用方记失败审计。
// 客户端声明的 declared_status=PASS 不直接成为后端通过状态——verification_status
// 只在全部核验通过后落 PASSED。
package regression

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// ImportObjectInput 导入请求中的对象引用（仅接受已登记受控对象 ID；
// 不接收任意 URL、服务器文件路径、压缩包或 shell 命令）。
type ImportObjectInput struct {
	ObjectID uuid.UUID `json:"object_id"`
	Role     string    `json:"role"`
	Name     string    `json:"name"`
}

// ImportRequest 导入请求（签名独立封装；无 skip/override 类参数）。
type ImportRequest struct {
	ManifestObjectID uuid.UUID           `json:"manifest_object_id"`
	Signature        SignatureEnvelope   `json:"signature"`
	Objects          []ImportObjectInput `json:"objects"`
}

// ImportResult 导入结果。
type ImportResult struct {
	Run           *Run     `json:"run"`
	Idempotent    bool     `json:"idempotent"`
	RejectReasons []string `json:"reject_reasons,omitempty"`
}

// ImportStore 导入所需存取接口（*Store 实现；单测注入 fake）。
type ImportStore interface {
	GetRunByRunID(ctx context.Context, runID string) (*Run, error)
	GetObject(ctx context.Context, id uuid.UUID) (*EvidenceObject, error)
	GetPolicy(ctx context.Context) (*Policy, error)
	ImportRun(ctx context.Context, run *Run, cases []CaseEntry, refs []ImportObjectRef) (stored *Run, idempotent bool, err error)
}

// Importer 导入核验器。
type Importer struct {
	store    ImportStore
	evidence *LocalEvidenceStore
	keys     SettingsReader
}

// NewImporter 创建导入核验器。
func NewImporter(store ImportStore, evidence *LocalEvidenceStore, keys SettingsReader) *Importer {
	return &Importer{store: store, evidence: evidence, keys: keys}
}

// Import 执行完整核验与登记。reject 类失败返回 (nil, reasons, nil)；
// 依赖/存储失败返回 error（调用方 500）；冲突返回 ErrConflict（409）。
func (im *Importer) Import(ctx context.Context, req ImportRequest, operator string) (*ImportResult, []string, error) {
	if len(req.Objects) > 1+MaxChunksPerRun+16 {
		return nil, []string{"对象引用数量超限"}, nil
	}
	// 1. manifest 对象读取（落盘哈希先校验；CONSUMED 状态可读以支持幂等判定）
	manifestBytes, manifestObj, err := im.evidence.ReadAll(ctx, req.ManifestObjectID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, []string{"manifest 对象不存在"}, nil
		}
		if errors.Is(err, ErrHashMismatch) {
			return nil, []string{"manifest 对象落盘内容与登记哈希不一致（疑似篡改）"}, nil
		}
		return nil, nil, err
	}
	if manifestObj.Kind != KindManifest {
		return nil, []string{"manifest_object_id 引用的对象类别不是 MANIFEST"}, nil
	}
	// 2. 规范形 + schema
	m, reasons := ParseManifest(manifestBytes)
	if reasons != nil {
		return nil, reasons, nil
	}
	// 3. 签名（算法/key_id/撤销/验签；密钥登记解析失败 = 依赖不可用 500）
	trustedKeys, err := LoadTrustedKeys(ctx, im.keys)
	if err != nil {
		return nil, nil, err
	}
	if err := VerifyManifestSignature(trustedKeys, req.Signature, manifestBytes); err != nil {
		return nil, []string{err.Error()}, nil
	}
	// 4. 幂等/冲突（同 run_id 同 manifest 哈希 → 返回既有；异内容 → 409 审计）
	existing, err := im.store.GetRunByRunID(ctx, m.RunID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, nil, err
	}
	if existing != nil {
		if existing.ManifestSHA256 == manifestObj.SHA256 {
			return &ImportResult{Run: existing, Idempotent: true}, nil, nil
		}
		return nil, nil, fmt.Errorf("%w: run_id %s 已登记不同内容", ErrConflict, m.RunID)
	}
	// 5. 必需对象覆盖与逐块校验
	byKey := map[string]ImportObjectInput{}
	for _, o := range req.Objects {
		k := o.Role + "/" + o.Name
		if _, dup := byKey[k]; dup {
			return nil, []string{"重复对象引用: " + k}, nil
		}
		byKey[k] = o
	}
	var refs []ImportObjectRef
	var chunks []*CasesChunk
	var totalBytes int64 = manifestObj.SizeBytes
	chunkCount := 0
	for _, f := range m.Files {
		o, ok := byKey[f.Role+"/"+f.Name]
		if !ok {
			return nil, []string{fmt.Sprintf("必需文件 %s/%s 缺少对应已登记对象", f.Role, f.Name)}, nil
		}
		delete(byKey, f.Role+"/"+f.Name)
		obj, err := im.store.GetObject(ctx, o.ObjectID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return nil, []string{fmt.Sprintf("对象 %s 不存在", o.ObjectID)}, nil
			}
			return nil, nil, err
		}
		if obj.State != ObjectRegistered {
			return nil, []string{fmt.Sprintf("对象 %s 已被其他运行消费", o.ObjectID)}, nil
		}
		if obj.Kind != f.Role {
			return nil, []string{fmt.Sprintf("对象 %s 类别 %s 与清单要求 %s 不一致", o.ObjectID, obj.Kind, f.Role)}, nil
		}
		if obj.SHA256 != f.SHA256 || obj.SizeBytes != f.SizeBytes {
			return nil, []string{fmt.Sprintf("%s: 对象 %s 登记哈希与清单不一致", ErrHashMismatch, o.ObjectID)}, nil
		}
		totalBytes += obj.SizeBytes
		if totalBytes > MaxTotalBytesPerRun {
			return nil, []string{"单次运行对象总量超限"}, nil
		}
		if f.Role == KindCasesChunk {
			chunkCount++
			if chunkCount > MaxChunksPerRun {
				return nil, []string{"用例分块数量超限"}, nil
			}
			data, _, err := im.evidence.ReadAll(ctx, o.ObjectID)
			if err != nil {
				if errors.Is(err, ErrHashMismatch) || errors.Is(err, ErrNotFound) {
					return nil, []string{fmt.Sprintf("对象 %s 落盘校验失败: %v", o.ObjectID, err)}, nil
				}
				return nil, nil, err
			}
			chunk, reasons := ParseCasesChunk(data, m.RunID)
			if reasons != nil {
				return nil, []string{fmt.Sprintf("分块 %s 校验失败: %v", f.Name, reasons)}, nil
			}
			chunks = append(chunks, chunk)
		}
		refs = append(refs, ImportObjectRef{ObjectID: o.ObjectID, Role: f.Role, SHA256: f.SHA256})
	}
	if len(byKey) > 0 {
		return nil, []string{"存在清单未声明的多余对象引用"}, nil
	}
	refs = append(refs, ImportObjectRef{ObjectID: req.ManifestObjectID, Role: KindManifest, SHA256: manifestObj.SHA256})
	// 6. 用例唯一性与计数对账
	if reasons := ReconcileCounts(m, chunks); len(reasons) > 0 {
		return nil, reasons, nil
	}
	// 7. 组装运行记录（策略版本留痕）并单事务落库
	policy, err := im.store.GetPolicy(ctx)
	if err != nil {
		return nil, nil, err
	}
	started, _ := parseTime(m.RunStartedAt)
	finished, _ := parseTime(m.RunFinishedAt)
	run := &Run{
		RunID:               m.RunID,
		ManifestSHA256:      manifestObj.SHA256,
		Level:               m.Level,
		DeclaredStatus:      m.DeclaredStatus,
		VerificationStatus:  VerifyPassed,
		VerificationReasons: []byte(`[]`),
		SignatureAlgorithm:  req.Signature.Algorithm,
		SignatureKeyID:      req.Signature.KeyID,
		ConfigFingerprint:   m.Candidate.ConfigFingerprint,
		BuildDigest:         m.Candidate.BuildDigest,
		Compiler:            m.Candidate.Compiler,
		CorpusID:            m.Candidate.CorpusID,
		CorpusVersion:       m.Candidate.CorpusVersion,
		CorpusSHA256:        m.Candidate.CorpusSHA256,
		PlanSHA256:          m.Candidate.PlanSHA256,
		Counts:              m.Counts,
		RunStartedAt:        started,
		RunFinishedAt:       finished,
		PolicyVersion:       policy.Version,
		ImportedBy:          operator,
	}
	var cases []CaseEntry
	for _, ch := range chunks {
		for _, cs := range ch.Cases {
			cases = append(cases, CaseEntry{
				CaseID: cs.CaseID, CaseVersion: cs.CaseVersion, Family: cs.Family,
				Truth: cs.Truth, Criticality: cs.Criticality, Status: cs.Status,
				DiffSummary: cs.Diff,
			})
		}
	}
	stored, idem, err := im.store.ImportRun(ctx, run, cases, refs)
	if err != nil {
		return nil, nil, err
	}
	return &ImportResult{Run: stored, Idempotent: idem}, nil, nil
}
