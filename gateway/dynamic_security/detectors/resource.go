package detectors

import (
	"sort"
	"strconv"
	"strings"
	"sync"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// BOLA/BFLA 辅助检测：归一化路径含对象段（{id}/{uuid}/{hex}）或 Query 参数值命中
// 对象标识形态时的对象级访问信号。
// 仅为辅助信号（对象标识 + 无凭据），不直接认定越权（任务书：不得仅凭对象 ID 差异确认 BOLA）。
const objectTrackerMaxKeys = 10000

// defaultObjectTracker 包级对象 ID 游标（identity+endpoint+段位置/参数名 → 上一数字对象 ID，
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

// objectRef 单个对象标识事实：来源 + 形态 + 原始值。
// 原始值只活在进程内存（numeric 连续枚举判定），永不写入证据/事件。
type objectRef struct {
	source string // "path" | "query"
	typ    string // numeric | uuid | hex
	raw    string // 原始值（仅 numeric 连续判定使用）
	dim    string // 游标/证据维度：path 为段位置序号，query 为参数名（结构信息，可入证据）
}

// objectRefs 返回请求中的全部对象标识：路径对象段 + Query 形态 +（可选）BODY 语义类型联动。
// semanticIDPaths：参数约束下发的 id 类字段路径集合（空则不做 BODY 联动）。
func objectRefs(p *parser.Parsed, semanticIDPaths map[string]string) []objectRef {
	var refs []objectRef
	// 路径对象段：归一化模板与原始路径按 / 对齐切分，逐段提取
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
		refs = append(refs, objectRef{source: "path", typ: typ, raw: val, dim: strconv.Itoa(i)})
	}
	// Query 参数对象标识：形态识别 + 语义类型（若下发）
	if len(p.Query) > 0 {
		names := make([]string, 0, len(p.Query))
		for name := range p.Query {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			val := p.Query[name]
			typ := normalizer.IdentifierShape(val)
			if typ == "" && semanticIDPaths != nil {
				if st := semanticIDPaths["QUERY:"+name]; isObjectSemantic(st) {
					typ = semanticToShape(st, val)
				}
			}
			if typ != "" {
				refs = append(refs, objectRef{source: "query", typ: typ, raw: val, dim: name})
			}
		}
	}
	// BODY：参数模型 semantic_type 联动（id/uuid/user_id 等）
	if len(semanticIDPaths) > 0 && p.JSONValues != nil {
		paths := make([]string, 0)
		for k := range semanticIDPaths {
			if strings.HasPrefix(k, "BODY:") {
				paths = append(paths, strings.TrimPrefix(k, "BODY:"))
			}
		}
		sort.Strings(paths)
		for _, path := range paths {
			val, ok := p.JSONValues[path]
			if !ok || val == "" {
				continue
			}
			st := semanticIDPaths["BODY:"+path]
			typ := semanticToShape(st, val)
			if typ == "" {
				typ = normalizer.IdentifierShape(val)
			}
			if typ != "" {
				refs = append(refs, objectRef{source: "body", typ: typ, raw: val, dim: path})
			}
		}
	}
	return refs
}

func isObjectSemantic(st string) bool {
	switch strings.ToLower(strings.TrimSpace(st)) {
	case "id", "user_id", "account_id", "order_id", "resource_id", "uuid", "object_id", "numeric_id":
		return true
	default:
		return false
	}
}

func semanticToShape(st, val string) string {
	st = strings.ToLower(strings.TrimSpace(st))
	if st == "uuid" {
		if normalizer.IdentifierShape(val) == "uuid" {
			return "uuid"
		}
		return "uuid" // 语义声明为 uuid 即计入对象标识
	}
	if shape := normalizer.IdentifierShape(val); shape != "" {
		return shape
	}
	if st == "id" || strings.HasSuffix(st, "_id") || st == "numeric_id" || st == "object_id" {
		if _, err := strconv.ParseInt(val, 10, 64); err == nil {
			return "numeric"
		}
		return "hex"
	}
	return ""
}

// SemanticIDPathsFromConstraints 从下发参数约束提取 id 类字段键（location:name 或 location:path）。
func SemanticIDPathsFromConstraints(params []ParamConstraint) map[string]string {
	if len(params) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, pc := range params {
		if !isObjectSemantic(pc.SemanticType) {
			continue
		}
		loc := strings.ToUpper(pc.Location)
		switch loc {
		case "QUERY":
			out["QUERY:"+pc.Name] = pc.SemanticType
		case "BODY":
			path := pc.Path
			if path == "" {
				path = pc.Name
			}
			out["BODY:"+path] = pc.SemanticType
		case "PATH":
			out["PATH:"+pc.Name] = pc.SemanticType
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// CheckResourceAccess 对象级访问辅助：
// 对象标识（路径段/Query/BODY 语义）+ 无任何身份凭据 → UNAUTHENTICATED_OBJECT_ACCESS（OBSERVE）；
// 连续数字 ID + 无凭据 + 写方法 → 升 HIGH（BLOCK 类）；
// semanticIDPaths 来自参数约束 semantic_type（可 nil）。
// endpointKey 为管线统一端点键（gRPC 流量为 EndpointKeyPreserve 路径全保留口径）：
// 游标键与管线 endpoint_key 同一取值，消除同端点双键空间；
// 空串回退按 EndpointKey 归一化口径重算（与历史行为一致，供无管线上下文的直接调用）。
func CheckResourceAccess(ctx *dsctx.RequestContext, p *parser.Parsed, identity, endpointKey string, semanticIDPaths map[string]string) {
	if ctx == nil || p == nil {
		return
	}
	refs := objectRefs(p, semanticIDPaths)
	if len(refs) == 0 {
		return
	}
	// 对象类型事实落上下文（无论是否有凭据、是否产生 match）——风险分析需要事实而非只有告警
	types := make([]string, 0, len(refs))
	firstPathType := ""
	for _, ref := range refs {
		types = append(types, ref.source+":"+ref.dim+":"+ref.typ)
		if firstPathType == "" && ref.source == "path" {
			firstPathType = ref.typ
		}
	}
	if firstPathType != "" {
		ctx.SetExtension("api.object_id_type", firstPathType)
	}
	ctx.SetExtension("api.object_id_types", types)
	if hasCredential(p) {
		return
	}
	ek := endpointKey
	if ek == "" {
		ek = normalizer.EndpointKey(p.Method, p.RawPath)
	}
	for _, ref := range refs {
		match := dsctx.DetectorMatch{
			Detector: "resource_access",
			RuleID:   "resource.unauthenticated_object_access",
			Category: "OBSERVE",
			Severity: "MEDIUM",
			Message:  "object access without credential",
			Evidence: map[string]string{
				"object_type": ref.typ,
				"method":      p.Method,
				"source":      ref.source,
			},
			ScoreDelta: 15,
		}
		// 证据注明结构维度（段位置/参数名本身可入证据，值绝不入）
		switch ref.source {
		case "path":
			match.Evidence["segment"] = ref.dim
		case "query":
			match.Evidence["param"] = ref.dim
		case "body":
			match.Evidence["field"] = ref.dim
		}
		// 连续数字 ID + 无凭据 + 写方法：疑似对象遍历/篡改，升 BLOCK 类
		// 游标键加段位置/参数名后缀（identity|endpoint|seg/参数名），LRU 纪律不变
		if ref.typ == "numeric" && IsWriteMethod(p.Method) && identity != "" {
			if id, err := strconv.ParseInt(ref.raw, 10, 64); err == nil {
				if objectConsecutive(ctx, identity+"|"+ek+"|"+ref.source+":"+ref.dim, id) {
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
