package detectors

import (
	"strconv"
	"strings"
	"sync"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// BOLA/BFLA 辅助检测：归一化路径含对象段（{id}/{uuid}/{hex}）时的对象级访问信号。
// 仅为辅助信号（对象段 + 无凭据），不直接认定越权（任务书：不得仅凭对象 ID 差异确认 BOLA）。
const objectTrackerMaxKeys = 10000

// defaultObjectTracker 包级对象 ID 游标（identity+endpoint → 上一数字对象 ID，
// 用于连续数字 ID 遍历识别；LRU 定容，单节点限制同 windowTracker）。
var defaultObjectTracker = &objectTracker{entries: newLRU(objectTrackerMaxKeys)}

type objectTracker struct {
	mu      sync.Mutex
	entries *lru // key → int64
}

// consecutive 记录本次对象 ID；返回是否紧邻上一 ID（id == prev+1）。
func (t *objectTracker) consecutive(key string, id int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev, ok := t.entries.get(key)
	t.entries.set(key, id)
	if !ok {
		return false
	}
	return id == prev.(int64)+1
}

// CheckResourceAccess 对象级访问辅助：
// 对象段 + 无任何身份凭据 → UNAUTHENTICATED_OBJECT_ACCESS（OBSERVE）；
// 连续数字 ID + 无凭据 + 写方法 → 升 HIGH（BLOCK 类）。
// 对象标识类型始终写入 ctx 扩展 api.object_id_type（numeric/uuid/hex）。
func CheckResourceAccess(ctx *dsctx.RequestContext, p *parser.Parsed, identity string) {
	if ctx == nil || p == nil {
		return
	}
	objType, rawID := objectSegment(p)
	if objType == "" {
		return
	}
	ctx.SetExtension("api.object_id_type", objType)
	if hasCredential(p) {
		return
	}
	match := dsctx.DetectorMatch{
		Detector: "resource_access",
		RuleID:   "resource.unauthenticated_object_access",
		Category: "OBSERVE",
		Severity: "MEDIUM",
		Message:  "object access without credential",
		Evidence: map[string]string{
			"object_type": objType,
			"method":      p.Method,
		},
		ScoreDelta: 15,
	}
	// 连续数字 ID + 无凭据 + 写方法：疑似对象遍历/篡改，升 BLOCK 类
	if objType == "numeric" && IsWriteMethod(p.Method) && identity != "" {
		if id, err := strconv.ParseInt(rawID, 10, 64); err == nil {
			ek := normalizer.EndpointKey(p.Method, p.RawPath)
			if defaultObjectTracker.consecutive(identity+"|"+ek, id) {
				match.Category = "BLOCK"
				match.Severity = "HIGH"
				match.Message = "sequential numeric object id on write without credential"
				match.Evidence["pattern"] = "sequential_numeric_id"
				match.ScoreDelta = 30
			}
		}
	}
	ctx.AddMatch(match)
}

// objectSegment 返回归一化路径中首个对象段的类型与原始值（无对象段返回空）。
func objectSegment(p *parser.Parsed) (objType, rawValue string) {
	norm := strings.Split(strings.Trim(p.NormalizedPath, "/"), "/")
	raw := strings.Split(strings.Trim(p.RawPath, "/"), "/")
	for i, s := range norm {
		var typ string
		switch s {
		case "{id}":
			typ = "numeric"
		case "{uuid}":
			typ = "uuid"
		case "{hex}":
			typ = "hex"
		default:
			continue
		}
		val := ""
		if i < len(raw) {
			val = raw[i]
		}
		return typ, val
	}
	return "", ""
}

// hasCredential 凭据存在性（parser 已脱敏，仅存 [redacted] 标记）。
func hasCredential(p *parser.Parsed) bool {
	if p == nil {
		return false
	}
	_, authz := p.Headers["authorization"]
	_, apiKey := p.Headers["x-api-key"]
	return authz || apiKey
}
