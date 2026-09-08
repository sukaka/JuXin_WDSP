// filecomp_test.go 文件合规检测单测（W13-GW / P2-03）：
// 编译校验（词表/取值/正则非法如实报错）、EXT 精确（带点/不带点/大小写归一）、MIME 前缀、
// FILENAME_REGEX、方向过滤、动作×模式类别映射（BLOCK+PROTECT 升级 / would-block / OBSERVE 恒记录）、
// 双扩展名信号（EXT 按最后一段 + file.double_extension OBSERVE/LOW）、证据不落内容。
package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// fileCompTestObs 构造文件观测（字段与 parser/response 产物同形态，已归一化）。
func fileCompTestObs(direction, filename, mime string) dsctx.FileObservation {
	return dsctx.FileObservation{
		Direction: direction,
		FileName:  dsctx.SanitizeFileName(filename),
		Extension: dsctx.FileExtension(dsctx.SanitizeFileName(filename)),
		MIME:      dsctx.SanitizeMIME(mime),
		Size:      128,
	}
}

func fileCompCompile(t *testing.T, rules []FileComplianceRule) *FileComplianceRuleSet {
	t.Helper()
	set, err := CompileFileComplianceRules(rules)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return set
}

// matchesByRule 取上下文中指定 rule_id 的明细。
func matchesByRule(ctx *dsctx.RequestContext, ruleID string) []dsctx.DetectorMatch {
	var out []dsctx.DetectorMatch
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			out = append(out, m)
		}
	}
	return out
}

// TestCompileFileComplianceRules 编译：非法配置逐类如实报错；EXT/MIME 归一（带点不带点统一、
// 大小写不敏感）；空列表 nil（零行为）；方向标志。
func TestCompileFileComplianceRules(t *testing.T) {
	// 空列表 → nil 集（无规则零行为）
	if set, err := CompileFileComplianceRules(nil); err != nil || set != nil {
		t.Fatalf("empty rules must yield nil set: %v %v", set, err)
	}
	// 合法规则：EXT ".EXE" 归一为 "exe"；方向标志
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "upload", Match: "EXT", Value: ".EXE", Action: "block", Reason: "可执行文件"},
		{Direction: "DOWNLOAD", Match: "mime", Value: "Image/", Action: "OBSERVE"},
		{Direction: "DOWNLOAD", Match: "FILENAME_REGEX", Value: `(?i)\.scr$`, Action: "OBSERVE"},
	})
	if !set.HasUploadRules() || !set.HasDownloadRules() {
		t.Fatalf("direction flags wrong: %+v", set)
	}
	if set.rules[0].ext != "exe" || set.rules[1].mime != "image/" {
		t.Fatalf("normalization wrong: %+v", set.rules)
	}
	if set.rules[0].Direction != "UPLOAD" || set.rules[0].Action != "BLOCK" {
		t.Fatalf("keyword normalization wrong: %+v", set.rules[0])
	}

	// 非法配置：逐类报错（含序号）
	bad := []struct {
		name string
		rule FileComplianceRule
	}{
		{"方向未知", FileComplianceRule{Direction: "BOTH", Match: "EXT", Value: "exe", Action: "BLOCK"}},
		{"匹配类型未知", FileComplianceRule{Direction: "UPLOAD", Match: "SIZE", Value: "1", Action: "BLOCK"}},
		{"动作未知", FileComplianceRule{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "DENY"}},
		{"value 空", FileComplianceRule{Direction: "UPLOAD", Match: "EXT", Value: " ", Action: "BLOCK"}},
		{"EXT 归一后空", FileComplianceRule{Direction: "UPLOAD", Match: "EXT", Value: ".", Action: "BLOCK"}},
		{"MIME 归一后空", FileComplianceRule{Direction: "UPLOAD", Match: "MIME", Value: "", Action: "BLOCK"}},
		{"正则非法", FileComplianceRule{Direction: "UPLOAD", Match: "FILENAME_REGEX", Value: "([", Action: "BLOCK"}},
		{"reason 超长", FileComplianceRule{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK", Reason: strings.Repeat("r", 300)}},
		{"value 超长", FileComplianceRule{Direction: "UPLOAD", Match: "MIME", Value: strings.Repeat("v", 300), Action: "BLOCK"}},
	}
	for _, c := range bad {
		if _, err := CompileFileComplianceRules([]FileComplianceRule{c.rule}); err == nil {
			t.Errorf("%s: %+v must fail", c.name, c.rule)
		}
	}
}

// TestCheckFileComplianceEXT EXT 精确匹配：带点/不带点统一、大小写不敏感、精确（非前缀）；
// BLOCK+PROTECT 升级 BLOCK 类（证据不落内容）。
func TestCheckFileComplianceEXT(t *testing.T) {
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: ".Exe", Action: "BLOCK", Reason: "可执行文件"},
	})
	ctx := dsctx.New("req-ext-1", dsctx.DefaultParseLimits())
	CheckFileCompliance(ctx, []dsctx.FileObservation{
		fileCompTestObs("UPLOAD", "evil.EXE", "application/octet-stream"),
		fileCompTestObs("UPLOAD", "evil.exe.bak", "application/octet-stream"), // 末段 bak 不命中
		fileCompTestObs("UPLOAD", "notes.txt", "text/plain"),
	}, set, decision.ModeProtect)
	ms := matchesByRule(ctx, "file.compliance_violation")
	if len(ms) != 1 {
		t.Fatalf("want exactly 1 violation, got %+v", ctx.CopyMatches())
	}
	m := ms[0]
	if m.Category != "BLOCK" || m.Severity != "HIGH" || m.Detector != "file" {
		t.Fatalf("PROTECT block discipline broken: %+v", m)
	}
	if m.Evidence["filename"] != "evil.EXE" || m.Evidence["ext"] != "exe" ||
		m.Evidence["match"] != "EXT" || m.Evidence["value"] != ".Exe" ||
		m.Evidence["reason"] != "可执行文件" || m.Evidence["mime"] != "application/octet-stream" {
		t.Fatalf("evidence = %+v", m.Evidence)
	}
	for k, v := range m.Evidence {
		if strings.Contains(v, "FAKE-CONTENT") || strings.Contains(k, "content") || strings.Contains(k, "body") {
			t.Fatalf("evidence must not carry file content: %s=%s", k, v)
		}
	}
}

// TestCheckFileComplianceMIME MIME 前缀匹配：image/ 命中 image/png；text/plain 精确前缀命中；
// 不同主类型不命中。
func TestCheckFileComplianceMIME(t *testing.T) {
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "DOWNLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"},
		{Direction: "DOWNLOAD", Match: "MIME", Value: "application/pdf", Action: "OBSERVE"},
	})
	ctx := dsctx.New("req-mime-1", dsctx.DefaultParseLimits())
	CheckFileCompliance(ctx, []dsctx.FileObservation{
		fileCompTestObs("DOWNLOAD", "a.png", "image/png"),
		fileCompTestObs("DOWNLOAD", "b.pdf", "application/pdf; charset=binary"),
		fileCompTestObs("DOWNLOAD", "c.txt", "text/plain"),
	}, set, decision.ModeObserve)
	ms := matchesByRule(ctx, "file.compliance_violation")
	if len(ms) != 2 {
		t.Fatalf("want 2 violations, got %+v", ctx.CopyMatches())
	}
	for _, m := range ms {
		if m.Category != "OBSERVE" || m.Severity != "LOW" {
			t.Fatalf("OBSERVE action must stay LOW observe: %+v", m)
		}
	}
}

// TestCheckFileComplianceFilenameRegex 文件名正则（RE2）：命中/不命中；大小写标记可用。
func TestCheckFileComplianceFilenameRegex(t *testing.T) {
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "UPLOAD", Match: "FILENAME_REGEX", Value: `(?i)^confidential.*\.xlsx$`, Action: "OBSERVE", Reason: "敏感命名"},
	})
	ctx := dsctx.New("req-re-1", dsctx.DefaultParseLimits())
	CheckFileCompliance(ctx, []dsctx.FileObservation{
		fileCompTestObs("UPLOAD", "Confidential_2026_Q1.xlsx", "application/vnd.ms-excel"),
		fileCompTestObs("UPLOAD", "public.xlsx", "application/vnd.ms-excel"),
	}, set, decision.ModeProtect)
	ms := matchesByRule(ctx, "file.compliance_violation")
	if len(ms) != 1 || ms[0].Evidence["filename"] != "Confidential_2026_Q1.xlsx" {
		t.Fatalf("regex match wrong: %+v", ctx.CopyMatches())
	}
	// OBSERVE 动作在 PROTECT 下仍恒 OBSERVE（不升级）
	if ms[0].Category != "OBSERVE" || ms[0].Severity != "LOW" {
		t.Fatalf("OBSERVE action must not escalate: %+v", ms[0])
	}
}

// TestCheckFileComplianceDirectionFilter 方向过滤：UPLOAD 规则不评估下载观测，反之亦然；
// 无方向规则时零行为（含双扩展名信号）。
func TestCheckFileComplianceDirectionFilter(t *testing.T) {
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK"},
	})
	ctx := dsctx.New("req-dir-1", dsctx.DefaultParseLimits())
	// 下载方向观测：无 DOWNLOAD 规则 → 零行为（连双扩展名信号也不产）
	CheckFileCompliance(ctx, []dsctx.FileObservation{
		fileCompTestObs("DOWNLOAD", "evil.pdf.exe", "application/octet-stream"),
	}, set, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("no download rules must be zero-behavior: %+v", ctx.CopyMatches())
	}
	// 上传方向观测：命中
	CheckFileCompliance(ctx, []dsctx.FileObservation{
		fileCompTestObs("UPLOAD", "evil.exe", "application/octet-stream"),
	}, set, decision.ModeProtect)
	if len(matchesByRule(ctx, "file.compliance_violation")) != 1 {
		t.Fatalf("upload rule must hit upload observation: %+v", ctx.CopyMatches())
	}
}

// TestCheckFileComplianceWouldBlock BLOCK 动作在 OBSERVE 模式维持 OBSERVE/MEDIUM（would-block，
// 不定案阻断，与 addRelationViolation 同一语义）。
func TestCheckFileComplianceWouldBlock(t *testing.T) {
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK"},
	})
	ctx := dsctx.New("req-wb-1", dsctx.DefaultParseLimits())
	CheckFileCompliance(ctx, []dsctx.FileObservation{
		fileCompTestObs("UPLOAD", "evil.exe", "application/octet-stream"),
	}, set, decision.ModeObserve)
	ms := matchesByRule(ctx, "file.compliance_violation")
	if len(ms) != 1 || ms[0].Category != "OBSERVE" || ms[0].Severity != "MEDIUM" {
		t.Fatalf("would-block semantics broken: %+v", ctx.CopyMatches())
	}
}

// TestCheckFileComplianceDoubleExtension 双扩展名：EXT 判定按最后一段（.exe 命中 BLOCK 规则），
// 并额外产 file.double_extension OBSERVE/LOW；单扩展名/隐藏文件/超长伪后缀不产信号。
func TestCheckFileComplianceDoubleExtension(t *testing.T) {
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK"},
	})
	ctx := dsctx.New("req-dbl-1", dsctx.DefaultParseLimits())
	CheckFileCompliance(ctx, []dsctx.FileObservation{
		fileCompTestObs("UPLOAD", "evil.pdf.exe", "application/octet-stream"),
		fileCompTestObs("UPLOAD", "readme.txt", "text/plain"),
	}, set, decision.ModeProtect)
	// EXT 按最后一段：evil.pdf.exe 命中 exe BLOCK 规则
	vio := matchesByRule(ctx, "file.compliance_violation")
	if len(vio) != 1 || vio[0].Evidence["ext"] != "exe" || vio[0].Category != "BLOCK" {
		t.Fatalf("last-segment EXT judgment wrong: %+v", ctx.CopyMatches())
	}
	// 双扩展名信号：仅 evil.pdf.exe 产一条 OBSERVE/LOW
	dbl := matchesByRule(ctx, "file.double_extension")
	if len(dbl) != 1 {
		t.Fatalf("want 1 double_extension signal, got %+v", ctx.CopyMatches())
	}
	d := dbl[0]
	if d.Category != "OBSERVE" || d.Severity != "LOW" ||
		d.Evidence["filename"] != "evil.pdf.exe" || d.Evidence["ext"] != "exe" || d.Evidence["stem_ext"] != "pdf" {
		t.Fatalf("double extension signal wrong: %+v", d)
	}

	// 隐藏文件与超长伪后缀：不识别为扩展名，不产双扩展名信号
	ctx2 := dsctx.New("req-dbl-2", dsctx.DefaultParseLimits())
	CheckFileCompliance(ctx2, []dsctx.FileObservation{
		fileCompTestObs("UPLOAD", ".profile", "text/plain"),
		fileCompTestObs("UPLOAD", "archive.verylongfakesuffix", "application/octet-stream"),
	}, set, decision.ModeProtect)
	if len(matchesByRule(ctx2, "file.double_extension")) != 0 {
		t.Fatalf("hidden/superlong pseudo-ext must not signal: %+v", ctx2.CopyMatches())
	}
}

// TestCheckFileComplianceLongFileName 超长文件名回归（HIGH-6）：FileName 截断 128 仅供证据，
// EXT/FILENAME_REGEX 与双扩展名判定一律基于未截断完整名（MatchName）——先截断会把后缀
// 截掉（A×200.exe 扩展名丢失），合规规则与双扩展名信号被静默绕过。观测按 parser/response
// 产物的真实构造方式（MatchName=完整名，Extension 按完整名提取）。
func TestCheckFileComplianceLongFileName(t *testing.T) {
	longObs := func(direction, name, mime string) dsctx.FileObservation {
		full := dsctx.SanitizeFileNameFull(name)
		return dsctx.FileObservation{
			Direction: direction,
			FileName:  dsctx.TruncateFileName(full),
			MatchName: full,
			Extension: dsctx.FileExtension(full),
			MIME:      dsctx.SanitizeMIME(mime),
			Size:      1,
		}
	}
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK"},
		{Direction: "UPLOAD", Match: "FILENAME_REGEX", Value: `(?i)\.exe$`, Action: "OBSERVE"},
	})
	ctx := dsctx.New("req-long-1", dsctx.DefaultParseLimits())
	longName := strings.Repeat("A", 200) + ".exe"
	CheckFileCompliance(ctx, []dsctx.FileObservation{
		longObs("UPLOAD", longName, "application/octet-stream"),
	}, set, decision.ModeProtect)
	// EXT 规则必须命中（扩展名来自未截断完整名）；证据落库的 filename 仍截断 128
	vio := matchesByRule(ctx, "file.compliance_violation")
	if len(vio) != 2 {
		t.Fatalf("EXT and FILENAME_REGEX must both hit long filename, got %+v", ctx.CopyMatches())
	}
	for _, m := range vio {
		if m.Evidence["ext"] != "exe" {
			t.Fatalf("ext evidence = %q, want exe (from untruncated name)", m.Evidence["ext"])
		}
		if n := len([]rune(m.Evidence["filename"])); n != dsctx.MaxFileNameLen {
			t.Fatalf("evidence filename must be truncated to %d runes, got %d", dsctx.MaxFileNameLen, n)
		}
	}
	// 超长名 + 伪装中间后缀：双扩展名信号同样不得被截断绕过
	ctx2 := dsctx.New("req-long-2", dsctx.DefaultParseLimits())
	longDouble := strings.Repeat("B", 200) + ".pdf.exe"
	CheckFileCompliance(ctx2, []dsctx.FileObservation{
		longObs("UPLOAD", longDouble, "application/octet-stream"),
	}, set, decision.ModeProtect)
	dbl := matchesByRule(ctx2, "file.double_extension")
	if len(dbl) != 1 || dbl[0].Evidence["stem_ext"] != "pdf" || dbl[0].Evidence["ext"] != "exe" {
		t.Fatalf("double extension on long filename must signal: %+v", ctx2.CopyMatches())
	}
}

// TestCheckFileComplianceNilGuards 空守卫：nil 上下文/规则集/观测列表不 panic、零行为。
func TestCheckFileComplianceNilGuards(t *testing.T) {
	set := fileCompCompile(t, []FileComplianceRule{
		{Direction: "UPLOAD", Match: "EXT", Value: "exe", Action: "BLOCK"},
	})
	CheckFileCompliance(nil, []dsctx.FileObservation{fileCompTestObs("UPLOAD", "a.exe", "")}, set, decision.ModeProtect)
	ctx := dsctx.New("req-nil-1", dsctx.DefaultParseLimits())
	CheckFileCompliance(ctx, nil, set, decision.ModeProtect)
	CheckFileCompliance(ctx, []dsctx.FileObservation{fileCompTestObs("UPLOAD", "a.exe", "")}, nil, decision.ModeProtect)
	if ctx.MatchCount() != 0 {
		t.Fatalf("nil guards must be zero-behavior: %+v", ctx.CopyMatches())
	}
	if (*FileComplianceRuleSet)(nil).HasUploadRules() || (*FileComplianceRuleSet)(nil).HasDownloadRules() {
		t.Fatal("nil set must report no rules")
	}
}
