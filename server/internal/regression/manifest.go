// manifest.go 回归报告 manifest schema v1 与用例分块 schema v1（任务书 §6.2：
// 版本化 manifest 包含用例结果摘要、全部必需文件哈希、构建/计划/语料/配置
// 指纹、运行级别和时间；固定 schema，拒绝未知主版本）。
package regression

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Manifest 报告清单 schema v1（签名字节 = 本结构规范形 JSON 原文）。
type Manifest struct {
	SchemaVersion  int               `json:"schema_version"`
	RunID          string            `json:"run_id"`
	Level          string            `json:"level"`
	CreatedAt      string            `json:"created_at"`
	RunStartedAt   string            `json:"run_started_at"`
	RunFinishedAt  string            `json:"run_finished_at"`
	DeclaredStatus string            `json:"declared_status"`
	Candidate      ManifestCandidate `json:"candidate"`
	Counts         ManifestCounts    `json:"counts"`
	Files          []ManifestFile    `json:"files"`
}

// ManifestCandidate 候选产物指纹（构建/编译器/语料/计划/配置；配置指纹为门禁绑定键）。
type ManifestCandidate struct {
	ConfigFingerprint string `json:"config_fingerprint"`
	BuildDigest       string `json:"build_digest"`
	Compiler          string `json:"compiler"`
	CorpusID          string `json:"corpus_id"`
	CorpusVersion     int    `json:"corpus_version"`
	CorpusSHA256      string `json:"corpus_sha256"`
	PlanSHA256        string `json:"plan_sha256"`
}

// ManifestCounts 用例结果摘要计数（服务端与分块实际内容逐项对账）。
type ManifestCounts struct {
	Planned         int `json:"planned"`
	Executed        int `json:"executed"`
	Skipped         int `json:"skipped"`
	Blocked         int `json:"blocked"`
	NotRun          int `json:"not_run"`
	Passed          int `json:"passed"`
	Failed          int `json:"failed"`
	MandatoryTotal  int `json:"mandatory_total"`
	MandatoryFailed int `json:"mandatory_failed"`
}

// ManifestFile 必需文件哈希登记（role 不含 MANIFEST——manifest 自身经导入请求
// 单独引用；用例结果分块逐块校验）。
type ManifestFile struct {
	Role      string `json:"role"` // CASES_CHUNK / REPORT / PERF / LOG
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

// CasesChunk 用例结果分块 schema v1。
type CasesChunk struct {
	SchemaVersion int          `json:"schema_version"`
	RunID         string       `json:"run_id"`
	Cases         []CaseResult `json:"cases"`
}

// CaseResult 用例索引/差异条目（不含原始请求/响应正文——正文摘要在受控对象中，
// 数据库行只存状态与差异摘要引用）。
type CaseResult struct {
	CaseID         string          `json:"case_id"`
	CaseVersion    int             `json:"case_version"`
	Family         string          `json:"family"`
	Truth          string          `json:"truth"`       // BENIGN / ATTACK / UNKNOWN
	Criticality    string          `json:"criticality"` // MANDATORY / OPTIONAL
	Status         string          `json:"status"`      // PASS / FAIL / SKIP / BLOCKED / NOT_RUN
	ExpectedAction string          `json:"expected_action,omitempty"`
	ObservedAction string          `json:"observed_action,omitempty"`
	Diff           json.RawMessage `json:"diff,omitempty"`
}

// ParseManifest 规范形校验 + schema 校验。返回 (manifest, 拒绝原因列表)；
// 任何拒绝原因存在即不可进入验签后的登记流程。
func ParseManifest(data []byte) (*Manifest, []string) {
	raw, err := ValidateCanonicalJSON(data)
	if err != nil {
		return nil, []string{err.Error()}
	}
	// 已确认无重复键且为规范形；再按 schema 严格解码（DisallowUnknownFields
	// 拒绝未知字段，固定 schema 主版本）。
	re, _ := canonicalReencode(raw)
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(re))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", ErrInvalidManifest, err)}
	}
	if reasons := m.Validate(); len(reasons) > 0 {
		return nil, reasons
	}
	return &m, nil
}

// Validate 字段级校验（版本化 schema：未知主版本、非法词表、指纹/哈希词形
// 与时间格式逐项拒绝）。
func (m *Manifest) Validate() []string {
	var bad []string
	add := func(f, msg string) { bad = append(bad, f+": "+msg) }
	if m.SchemaVersion != 1 {
		add("schema_version", "未知 schema 主版本（仅支持 1）")
	}
	if !validRunID(m.RunID) {
		add("run_id", "非法 run_id")
	}
	switch m.Level {
	case LevelSmoke, LevelFull, LevelRelease:
	default:
		add("level", "非法运行级别")
	}
	switch m.DeclaredStatus {
	case StatusPass, StatusFail, StatusSkip, StatusBlocked, StatusNotRun:
	default:
		add("declared_status", "非法状态词")
	}
	for _, ts := range []struct {
		field, v string
	}{{"created_at", m.CreatedAt}, {"run_started_at", m.RunStartedAt}, {"run_finished_at", m.RunFinishedAt}} {
		if _, err := time.Parse(time.RFC3339, ts.v); err != nil {
			add(ts.field, "非法 RFC3339 时间")
		}
	}
	c := m.Candidate
	if !strings.HasPrefix(c.ConfigFingerprint, FingerprintPrefixV1) ||
		!validHex(strings.TrimPrefix(c.ConfigFingerprint, FingerprintPrefixV1), 64) {
		add("candidate.config_fingerprint", "非法候选配置指纹（须为 cfgfpv1:<64 hex>）")
	}
	if len(c.BuildDigest) > 160 || len(c.Compiler) > 160 {
		add("candidate.build_digest/compiler", "长度超限")
	}
	if c.CorpusID == "" || len(c.CorpusID) > 128 {
		add("candidate.corpus_id", "为空或超长")
	}
	if !validHex(c.CorpusSHA256, 64) {
		add("candidate.corpus_sha256", "非法 sha256")
	}
	if !validHex(c.PlanSHA256, 64) {
		add("candidate.plan_sha256", "非法 sha256")
	}
	n := m.Counts
	for _, v := range []int{n.Planned, n.Executed, n.Skipped, n.Blocked, n.NotRun,
		n.Passed, n.Failed, n.MandatoryTotal, n.MandatoryFailed} {
		if v < 0 {
			add("counts", "计数不能为负")
			break
		}
	}
	if n.Planned > MaxCasesPerRun {
		add("counts.planned", "超过用例数硬上限")
	}
	if n.Passed+n.Failed > n.Executed {
		add("counts", "passed+failed 不能超过 executed")
	}
	if n.MandatoryFailed > n.MandatoryTotal {
		add("counts", "mandatory_failed 不能超过 mandatory_total")
	}
	if len(m.Files) > 1+MaxChunksPerRun+16 {
		add("files", "必需文件数量超限")
	}
	seenFile := map[string]struct{}{}
	for i, f := range m.Files {
		switch f.Role {
		case KindCasesChunk, KindReport, KindPerf, KindLog:
		case KindManifest:
			add(fmt.Sprintf("files[%d].role", i), "manifest 自身不得列入必需文件")
		default:
			add(fmt.Sprintf("files[%d].role", i), "非法文件类别")
		}
		if f.Name == "" || len(f.Name) > 256 || strings.Contains(f.Name, "/") || strings.Contains(f.Name, "\\") || strings.Contains(f.Name, "..") {
			add(fmt.Sprintf("files[%d].name", i), "非法文件名（不得含路径）")
		}
		key := f.Role + "/" + f.Name
		if _, dup := seenFile[key]; dup {
			add(fmt.Sprintf("files[%d]", i), "重复文件条目")
		}
		seenFile[key] = struct{}{}
		if !validHex(f.SHA256, 64) {
			add(fmt.Sprintf("files[%d].sha256", i), "非法 sha256")
		}
		if f.SizeBytes < 0 || f.SizeBytes > kindLimit(f.Role) {
			add(fmt.Sprintf("files[%d].size_bytes", i), "超过类别限额")
		}
	}
	return bad
}

// ParseCasesChunk 规范形校验 + 分块 schema 校验（run_id 必须与 manifest 一致）。
func ParseCasesChunk(data []byte, wantRunID string) (*CasesChunk, []string) {
	raw, err := ValidateCanonicalJSON(data)
	if err != nil {
		return nil, []string{err.Error()}
	}
	re, _ := canonicalReencode(raw)
	var c CasesChunk
	dec := json.NewDecoder(bytes.NewReader(re))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, []string{fmt.Sprintf("%s: %v", ErrInvalidManifest, err)}
	}
	var bad []string
	if c.SchemaVersion != 1 {
		bad = append(bad, "schema_version: 未知主版本")
	}
	if c.RunID != wantRunID {
		bad = append(bad, "run_id: 与 manifest 不一致")
	}
	if len(c.Cases) == 0 {
		bad = append(bad, "cases: 空分块不允许")
	}
	if len(c.Cases) > MaxCasesPerRun {
		bad = append(bad, "cases: 超过硬上限")
	}
	for i, cs := range c.Cases {
		if cs.CaseID == "" || len(cs.CaseID) > 160 {
			bad = append(bad, fmt.Sprintf("cases[%d].case_id: 为空或超长", i))
		}
		switch cs.Truth {
		case "BENIGN", "ATTACK", "UNKNOWN":
		default:
			bad = append(bad, fmt.Sprintf("cases[%d].truth: 非法词", i))
		}
		switch cs.Criticality {
		case "MANDATORY", "OPTIONAL":
		default:
			bad = append(bad, fmt.Sprintf("cases[%d].criticality: 非法词", i))
		}
		switch cs.Status {
		case StatusPass, StatusFail, StatusSkip, StatusBlocked, StatusNotRun:
		default:
			bad = append(bad, fmt.Sprintf("cases[%d].status: 非法词", i))
		}
		if len(cs.Diff) > 16*1024 {
			bad = append(bad, fmt.Sprintf("cases[%d].diff: 差异摘要超限", i))
		}
	}
	if len(bad) > 0 {
		return nil, bad
	}
	return &c, nil
}

// ReconcileCounts 分块实际内容与 manifest 计数对账（执行数量、用例唯一性及
// 结果一致性；唯一性另由存储 UNIQUE(run_ref, case_id) 兜底）。
func ReconcileCounts(m *Manifest, chunks []*CasesChunk) []string {
	var bad []string
	seen := map[string]struct{}{}
	var executed, skipped, blocked, notRun, passed, failed, mandatory, mandatoryFailed int
	total := 0
	for _, ch := range chunks {
		for _, cs := range ch.Cases {
			total++
			if _, dup := seen[cs.CaseID]; dup {
				bad = append(bad, "用例重复: "+cs.CaseID)
				continue
			}
			seen[cs.CaseID] = struct{}{}
			switch cs.Status {
			case StatusPass:
				executed++
				passed++
			case StatusFail:
				executed++
				failed++
			case StatusSkip:
				skipped++
			case StatusBlocked:
				blocked++
			case StatusNotRun:
				notRun++
			}
			if cs.Criticality == "MANDATORY" {
				mandatory++
				if cs.Status != StatusPass {
					mandatoryFailed++
				}
			}
		}
	}
	n := m.Counts
	check := func(field string, want, got int) {
		if want != got {
			bad = append(bad, fmt.Sprintf("counts.%s: manifest=%d 实际=%d", field, want, got))
		}
	}
	check("planned", n.Planned, total)
	check("executed", n.Executed, executed)
	check("skipped", n.Skipped, skipped)
	check("blocked", n.Blocked, blocked)
	check("not_run", n.NotRun, notRun)
	check("passed", n.Passed, passed)
	check("failed", n.Failed, failed)
	check("mandatory_total", n.MandatoryTotal, mandatory)
	check("mandatory_failed", n.MandatoryFailed, mandatoryFailed)
	return bad
}

// kindLimit 类别限额（对象登记与 manifest 声明共用同一口径）。
func kindLimit(kind string) int64 {
	switch kind {
	case KindManifest:
		return MaxManifestBytes
	case KindCasesChunk:
		return MaxChunkBytes
	case KindReport:
		return MaxReportBytes
	case KindPerf:
		return MaxPerfBytes
	case KindLog:
		return MaxLogBytes
	}
	return 0
}

// KindLimit 导出类别限额（HTTP 层上传限额提示用）。
func KindLimit(kind string) int64 { return kindLimit(kind) }

// ValidKind 类别词表校验。
func ValidKind(kind string) bool {
	switch kind {
	case KindManifest, KindCasesChunk, KindReport, KindPerf, KindLog:
		return true
	}
	return false
}

func validRunID(s string) bool {
	if s == "" || len(s) > maxRunIDLen {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// parseTime RFC3339 解析为可空时间（Validate 已保证格式）。
func parseTime(s string) (*time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
