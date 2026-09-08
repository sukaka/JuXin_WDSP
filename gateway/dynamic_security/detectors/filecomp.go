// filecomp.go 文件合规检测（W13-GW / P2-03，任务书 §44 文件异常检测子集）：
// 发布通道下发 api_file_compliance_rules（对应管理面 api_file_compliance_rules 表 enabled 行），
// 对文件传输观测（上传 multipart part 元数据 / 下载 Content-Disposition 观测）按规则评估：
//
//	EXT            扩展名精确匹配（大小写不敏感，规则值带点/不带点归一统一；双扩展名按最后一段判定）；
//	MIME           Content-Type 主类型前缀匹配（如 "image/" 命中 "image/png"；归一小写）；
//	FILENAME_REGEX 文件名正则（Go regexp 即 RE2 语法，线性时间，无回溯风险）。
//
// 动作语义（与 schema.param_required 的类别语义一致——类别描述违例等级，模式决定是否执行）：
//   - action=BLOCK 且 PROTECT → BLOCK 类（上传方向决策定案 403；下载方向由挂点侧抑制已缓冲
//     响应为 403）；OBSERVE/OFF 模式维持 OBSERVE 级观察（would-block）；
//   - action=OBSERVE → 恒记录 OBSERVE/LOW 观察信号，永不升级。
//
// 双扩展名（如 evil.pdf.exe）：EXT 判定按最后一段（.exe），并额外产 file.double_extension
// OBSERVE/LOW 信号（伪装扩展名属常见投递手法；仅观察不阻断，.tar.gz 类合法双后缀会同样
// 命中，属 v1 已知边界——信号供审计与人工研判，不参与定案）。
//
// 证据纪律：只含方向/文件名（已归一化截断 128）/扩展名/MIME/规则描述，绝不落文件内容。
// 匹配纪律：EXT 扩展名（观测构建期按未截断完整名提取）、FILENAME_REGEX 与双扩展名判定
// 一律基于未截断完整文件名（FileObservation.MatchFileName()）——先截断后匹配会把超长
// 文件名的后缀截掉（A×200.exe 扩展名丢失），合规规则被静默绕过；截断只用于证据落库。
package detectors

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

// 文件合规规则词表（与发布通道下发 api_file_compliance_rules 及管理面表 CHECK 约束一致）。
const (
	FileComplianceDirectionUpload   = "UPLOAD"
	FileComplianceDirectionDownload = "DOWNLOAD"

	FileComplianceMatchExt           = "EXT"
	FileComplianceMatchMIME          = "MIME"
	FileComplianceMatchFilenameRegex = "FILENAME_REGEX"

	FileComplianceActionObserve = "OBSERVE"
	FileComplianceActionBlock   = "BLOCK"
)

// 文件合规配置护栏（防误配；与既有下发段同一纪律）。
const (
	maxFileComplianceRules     = 512
	maxFileComplianceValueLen  = 256
	maxFileComplianceReasonLen = 200
	// maxFileComplianceFindingsPerFile 单文件命中明细上限（防大量规则命中撑爆事件）
	maxFileComplianceFindingsPerFile = 8
)

// FileComplianceRule 文件合规规则（发布通道下发；server gatewayconfig.GuardFileComplianceRule 镜像）。
// json tag 为跨分片契约，不得改动。
type FileComplianceRule struct {
	Direction string `json:"direction"` // UPLOAD / DOWNLOAD
	Match     string `json:"match"`     // EXT / MIME / FILENAME_REGEX
	Value     string `json:"value"`     // 匹配值（EXT 带点/不带点均可，归一小写无点）
	Action    string `json:"action"`    // OBSERVE / BLOCK
	Reason    string `json:"reason,omitempty"`
}

// compiledFileComplianceRule 编译后规则（原字段 + 归一/编译产物）。
type compiledFileComplianceRule struct {
	FileComplianceRule
	ext   string         // EXT 归一值（小写、剥前导点）
	mime  string         // MIME 归一前缀（小写）
	regex *regexp.Regexp // FILENAME_REGEX 编译产物（RE2）
}

// FileComplianceRuleSet 文件合规规则编译产物（装配层一次编译，运行期按方向 O(1) 判定）。
type FileComplianceRuleSet struct {
	rules     []compiledFileComplianceRule
	hasUpload bool
	hasDown   bool
}

// HasUploadRules 存在上传方向规则（请求相位评估门槛；无规则零行为）。
func (s *FileComplianceRuleSet) HasUploadRules() bool { return s != nil && s.hasUpload }

// HasDownloadRules 存在下载方向规则（响应相位评估与捕获缓冲判定门槛；无规则零行为）。
func (s *FileComplianceRuleSet) HasDownloadRules() bool { return s != nil && s.hasDown }

// FileComplianceConfigError 文件合规配置错误（含序号与原因；不含任何文件内容）。
type FileComplianceConfigError struct {
	Index  int
	Reason string
}

func (e *FileComplianceConfigError) Error() string {
	return fmt.Sprintf("api_file_compliance_rules: 第 %d 条配置非法: %s", e.Index, e.Reason)
}

// CompileFileComplianceRules 编译文件合规规则：逐条校验词表/取值并按匹配类型归一或预编译
// （配置错误显式返回，拒绝加载，不静默吞错；与 ValidateParamRelations 同一纪律）。
// 空列表返回 nil（无规则，网关对应方向检测零行为）。
func CompileFileComplianceRules(rules []FileComplianceRule) (*FileComplianceRuleSet, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	if len(rules) > maxFileComplianceRules {
		return nil, fmt.Errorf("api_file_compliance_rules: 条数超过 %d", maxFileComplianceRules)
	}
	set := &FileComplianceRuleSet{rules: make([]compiledFileComplianceRule, 0, len(rules))}
	for i, r := range rules {
		cr := compiledFileComplianceRule{FileComplianceRule: r}
		switch strings.ToUpper(strings.TrimSpace(r.Direction)) {
		case FileComplianceDirectionUpload:
			cr.Direction = FileComplianceDirectionUpload
			set.hasUpload = true
		case FileComplianceDirectionDownload:
			cr.Direction = FileComplianceDirectionDownload
			set.hasDown = true
		default:
			return nil, &FileComplianceConfigError{Index: i, Reason: "未知 direction: " + r.Direction}
		}
		if utf8.RuneCountInString(r.Value) == 0 {
			return nil, &FileComplianceConfigError{Index: i, Reason: "value 为空"}
		}
		if utf8.RuneCountInString(r.Value) > maxFileComplianceValueLen {
			return nil, &FileComplianceConfigError{Index: i, Reason: fmt.Sprintf("value 长度超过 %d", maxFileComplianceValueLen)}
		}
		if utf8.RuneCountInString(r.Reason) > maxFileComplianceReasonLen {
			return nil, &FileComplianceConfigError{Index: i, Reason: fmt.Sprintf("reason 长度超过 %d", maxFileComplianceReasonLen)}
		}
		switch strings.ToUpper(strings.TrimSpace(r.Match)) {
		case FileComplianceMatchExt:
			cr.Match = FileComplianceMatchExt
			// 带点/不带点统一：剥前导点后小写（".EXE" 与 "exe" 等价；观测侧扩展名同为小写无点）
			cr.ext = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(r.Value), "."))
			if cr.ext == "" {
				return nil, &FileComplianceConfigError{Index: i, Reason: "EXT value 归一后为空"}
			}
		case FileComplianceMatchMIME:
			cr.Match = FileComplianceMatchMIME
			cr.mime = strings.ToLower(strings.TrimSpace(r.Value))
			if cr.mime == "" {
				return nil, &FileComplianceConfigError{Index: i, Reason: "MIME value 归一后为空"}
			}
		case FileComplianceMatchFilenameRegex:
			cr.Match = FileComplianceMatchFilenameRegex
			re, err := regexp.Compile(r.Value) // Go regexp 即 RE2：线性时间，无回溯风险
			if err != nil {
				return nil, &FileComplianceConfigError{Index: i, Reason: "FILENAME_REGEX 编译失败: " + err.Error()}
			}
			cr.regex = re
		default:
			return nil, &FileComplianceConfigError{Index: i, Reason: "未知 match: " + r.Match}
		}
		switch strings.ToUpper(strings.TrimSpace(r.Action)) {
		case FileComplianceActionObserve:
			cr.Action = FileComplianceActionObserve
		case FileComplianceActionBlock:
			cr.Action = FileComplianceActionBlock
		default:
			return nil, &FileComplianceConfigError{Index: i, Reason: "未知 action: " + r.Action}
		}
		set.rules = append(set.rules, cr)
	}
	return set, nil
}

// CheckFileCompliance 对一批同方向文件观测执行合规评估（上传=请求相位 multipart 观测；
// 下载=响应相位 Content-Disposition 观测）。mode 为已解析防护模式（BLOCK 动作升级判定依据）。
// 仅评估与观测方向一致的规则；无方向规则零行为。证据不落文件内容。
func CheckFileCompliance(ctx *dsctx.RequestContext, obs []dsctx.FileObservation, rules *FileComplianceRuleSet, mode decision.Mode) {
	if ctx == nil || rules == nil || len(obs) == 0 {
		return
	}
	for i := range obs {
		o := obs[i]
		dirRules := rulesFor(rules, o.Direction)
		if len(dirRules) == 0 {
			continue // 本方向无规则：零行为（含双扩展名信号——无下发不产新信号）
		}
		// 双扩展名信号：EXT 判定按最后一段，伪装中间后缀另产观察信号（头部注释已知边界）；
		// 判定基于未截断完整名（截断会截掉后缀造成绕过）
		if stemExt := doubleExtensionStemExt(o.MatchFileName()); stemExt != "" {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "file",
				RuleID:     "file.double_extension",
				Category:   "OBSERVE",
				Severity:   "LOW",
				Message:    "double file extension observed (inner extension may disguise real type)",
				Confidence: 0.7, // 形态判定确定但是否恶意属推断，保守取值
				Evidence: map[string]string{
					"direction": o.Direction,
					"filename":  o.FileName,
					"ext":       o.Extension,
					"stem_ext":  stemExt,
				},
				ScoreDelta: 5,
			})
		}
		n := 0
		for _, rule := range dirRules {
			if n >= maxFileComplianceFindingsPerFile {
				break
			}
			if !fileComplianceRuleHits(rule, o) {
				continue
			}
			addFileComplianceFinding(ctx, rule, o, mode)
			n++
		}
	}
}

// rulesFor 取方向匹配的规则（规则数受 maxFileComplianceRules 护栏，线性筛选开销可忽略）。
func rulesFor(rules *FileComplianceRuleSet, direction string) []compiledFileComplianceRule {
	var out []compiledFileComplianceRule
	for _, r := range rules.rules {
		if r.Direction == direction {
			out = append(out, r)
		}
	}
	return out
}

// fileComplianceRuleHits 单规则命中判定（EXT 精确 / MIME 前缀 / 文件名 RE2）。
// 文件名匹配基于未截断完整名（MatchFileName；超长名截断会截掉后缀造成绕过）。
func fileComplianceRuleHits(rule compiledFileComplianceRule, o dsctx.FileObservation) bool {
	switch rule.Match {
	case FileComplianceMatchExt:
		return o.Extension != "" && o.Extension == rule.ext
	case FileComplianceMatchMIME:
		return o.MIME != "" && strings.HasPrefix(o.MIME, rule.mime)
	case FileComplianceMatchFilenameRegex:
		name := o.MatchFileName()
		return name != "" && rule.regex.MatchString(name)
	default:
		return false
	}
}

// addFileComplianceFinding 合规命中明细：BLOCK 动作 PROTECT 升级 BLOCK 类（上传决策 403、
// 下载挂点抑制 403），其余模式维持 OBSERVE/MEDIUM（would-block）；OBSERVE 动作恒 OBSERVE/LOW。
// 证据只含方向/文件名/扩展名/MIME/规则描述（match+value+reason），不落内容。
func addFileComplianceFinding(ctx *dsctx.RequestContext, rule compiledFileComplianceRule, o dsctx.FileObservation, mode decision.Mode) {
	evidence := map[string]string{
		"direction": o.Direction,
		"filename":  o.FileName,
		"match":     rule.Match,
		"value":     rule.Value,
	}
	if o.Extension != "" {
		evidence["ext"] = o.Extension
	}
	if o.MIME != "" {
		evidence["mime"] = o.MIME
	}
	if rule.Reason != "" {
		evidence["reason"] = rule.Reason
	}
	message := fmt.Sprintf("file compliance rule matched (%s %q)", rule.Match, rule.Value)
	if rule.Action == FileComplianceActionBlock && mode == decision.ModeProtect {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "file",
			RuleID:     "file.compliance_violation",
			Category:   "BLOCK",
			Severity:   "HIGH",
			Message:    message,
			Evidence:   evidence,
			Confidence: 1.0, // 确定性规则匹配
			ScoreDelta: 40,
		})
		return
	}
	if rule.Action == FileComplianceActionBlock {
		// would-block（OBSERVE/OFF 模式不执行阻断，与 addRelationViolation 同一语义）
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "file",
			RuleID:     "file.compliance_violation",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    message,
			Evidence:   evidence,
			Confidence: 1.0,
			ScoreDelta: 15,
		})
		return
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "file",
		RuleID:     "file.compliance_violation",
		Category:   "OBSERVE",
		Severity:   "LOW",
		Message:    message,
		Evidence:   evidence,
		Confidence: 1.0,
		ScoreDelta: 5,
	})
}

// doubleExtensionStemExt 双扩展名判定：最终扩展名之外，去尾段后的词干仍带可识别扩展名时
// 返回词干扩展名（如 evil.pdf.exe → "pdf"）；否则返回空串。
// .profile 类隐藏文件与超长伪后缀由 FileExtension 既有口径排除（不识别为扩展名）。
func doubleExtensionStemExt(name string) string {
	ext := dsctx.FileExtension(name)
	if ext == "" {
		return ""
	}
	stem := name[:len(name)-len(ext)-1]
	return dsctx.FileExtension(stem)
}
