// Package parser 在 ParseLimits 下一次解析请求（Query/头/JSON/表单/XML/multipart/GraphQL），供 Web 与 API 检测共享。
package parser

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// 写入 RequestContext.Extensions 的扩展键（键集合固定，禁止无界动态膨胀；值均已脱敏）。
const (
	ExtFormFields           = "req.form_fields"
	ExtXMLFields            = "req.xml_fields"
	ExtMultipartParts       = "req.multipart_parts"
	ExtHasFiles             = "req.has_files"
	ExtGraphQLOperation     = "req.graphql_operation"
	ExtGraphQLOperationName = "req.graphql_operation_name"
	ExtGraphQLVariables     = "req.graphql_variables"
	ExtMultipartCapped      = "req.multipart_capped"
	ExtXMLTruncated         = "req.xml_truncated"
	ExtXMLDTDBlocked        = "req.xml_dtd_blocked"
)

// 歧义位置词表（ParamAmbiguity.Location；钉死小写，检测器按词表机械映射规则码）。
const (
	AmbLocationQuery  = "query"
	AmbLocationHeader = "header"
	AmbLocationForm   = "form"
	AmbLocationJSON   = "json"
)

// maxAmbiguities 单请求歧义记录上限（防 HPP/重复键风暴撑爆事件行；超限置
// AmbiguityCapped，已有记录保留——前若干条已足够暴露歧义攻击特征）。
const maxAmbiguities = 32

// ParamAmbiguity 解析歧义记录（阶段2 Parser 歧义检测原料）：多值/重复键不再
// 静默丢弃，登记为可追溯元信息。严禁落 raw_value/normalized_value——如需值溯源
// 须走 paramobs.go value_hash（HMAC 指纹）纪律；本期只记 名称+位置+次数。
type ParamAmbiguity struct {
	Location      string `json:"location"`       // query / header / form / json（见 AmbLocation*）
	ParameterName string `json:"parameter_name"` // 参数名（JSON 为重复键名）
	ValueCount    int    `json:"value_count"`    // 出现次数（仅 >1 时登记）
	Path          string `json:"path,omitempty"` // JSON 点路径（与 walkJSON 同口径，数组段 []；仅 location=json）
}

// addAmbiguity 登记一条解析歧义（只含名/位置/次数；超上限置标记后不再追加）。
func (p *Parsed) addAmbiguity(a ParamAmbiguity) {
	if len(p.Ambiguities) >= maxAmbiguities {
		p.AmbiguityCapped = true
		return
	}
	p.Ambiguities = append(p.Ambiguities, a)
}

// Parsed 一次解析结果（不含明文密钥；字段名与粗类型供学习/偏离使用）。
type Parsed struct {
	Method         string
	RawPath        string
	NormalizedPath string
	Query          map[string]string
	Headers        map[string]string // 已脱敏（authorization/cookie 仅标记存在）
	ContentType    string
	JSONFields     map[string]string // path -> type: string|number|bool|object|array|null
	// JSONValues 可选标量值留存（path -> 截断 256 的标量值；仅当 ParseLimits.RetainJSONScalarValues
	// 为 true 时填充，值只在请求内存活，供参数约束检测取值，禁止写入事件/日志）
	JSONValues map[string]string
	FormFields map[string]string // urlencoded 表单字段名 -> type: string|number|bool
	// FormValues 可选表单标量值留存（字段名 -> 截断 256 的值；仅当 ParseLimits.RetainFormScalarValues
	// 为 true 时填充，值只在请求内存活，供值级敏感检测取值，禁止写入事件/日志）
	FormValues     map[string]string
	XMLFields      map[string]string // XML 元素路径 -> 叶子类型: string|number|bool
	MultipartParts []PartMeta        // multipart part 元数据（按出现顺序；文件内容不落内存）
	HasFiles       bool              // multipart 中含文件 part
	// GraphQL 识别（application/graphql 原始查询，或 /graphql 路径 + JSON body 含 query 字段）
	GraphQLOperation     string   // query|mutation|subscription|unknown
	GraphQLOperationName string   // operationName（缺省时从查询文本推断）
	GraphQLVariables     []string // variables 顶层键名（排序，不存值）
	FieldCount           int      // Body 侧字段计数（JSON/Form/XML 共用体侧配额；Query 键独立计数不占本配额）
	BodySize             int
	BodyHash             string
	BodyTruncated        bool
	FieldCapped          bool // Body 侧字段数超 MaxFieldCount 已截断（检测可见性由 parser.field_count_capped 明细承载）
	// QueryCapped Query 键数超 MaxFieldCount 已截断（Query 独立配额：distinct query 键
	// 先消费共享配额会把 JSONFields/JSONValues 排空——LLM 形态确认、敏感字段、schema 偏离、
	// BODY 参数约束被静默跳过；截断事实由 parser.field_count_capped 明细进事件流）
	QueryCapped     bool
	MultipartCapped bool // part 元数据数超 MaxFileMetaCount，已截断
	XMLTruncated    bool // 元素嵌套超 MaxXMLDepth，已停止解析
	XMLDTDBlocked   bool // 遇 DOCTYPE 拒绝解析（XXE 防御：禁止 DTD/实体展开）
	IsJSON          bool
	// GRPC gRPC 帧结构观测（P2-05：Content-Type application/grpc(+proto) 且带体时
	// 由逐帧校验填充；仅结构事实与计数，不落消息内容；非 gRPC 流量为 nil）
	GRPC *GRPCInfo
	// Ambiguities 解析歧义记录（阶段2：query/header 多值、form/JSON 重复键；
	// 只含名/位置/次数元信息，值永不入列——见 ParamAmbiguity 注释）
	Ambiguities []ParamAmbiguity
	// AmbiguityCapped 歧义记录数超 maxAmbiguities 已截断
	AmbiguityCapped bool
}

// ParseRequest 解析 HTTP 请求并填充 RequestContext 的请求侧字段。
func ParseRequest(r *http.Request, ctx *dsctx.RequestContext) (*Parsed, error) {
	if r == nil {
		return nil, nil
	}
	limits := dsctx.DefaultParseLimits()
	if ctx != nil {
		limits = ctx.Limits
	}
	p := &Parsed{
		Method:         strings.ToUpper(r.Method),
		RawPath:        r.URL.Path,
		NormalizedPath: normalizer.NormalizePath(r.URL.Path),
		Query:          map[string]string{},
		Headers:        map[string]string{},
		JSONFields:     map[string]string{},
		JSONValues:     map[string]string{},
		FormFields:     map[string]string{},
		FormValues:     map[string]string{},
		XMLFields:      map[string]string{},
		ContentType:    r.Header.Get("Content-Type"),
	}
	// Query（独立配额：query 键数不消耗 Body 侧 FieldCount 预算——
	// ≥MaxFieldCount 个 distinct query 键（约 12KB URL）曾把 JSON 字段解析整体排空，
	// 体侧检测被静默跳过；两向各自封顶互不挤占）
	queryCount := 0
	for k, vs := range r.URL.Query() {
		if queryCount >= limits.MaxFieldCount {
			p.QueryCapped = true
			break
		}
		if len(vs) > 1 {
			// 多值参数（HPP 信号）：保留首值语义（仍取 vs[0]），登记歧义（只记名+次数，不落值）
			p.addAmbiguity(ParamAmbiguity{Location: AmbLocationQuery, ParameterName: k, ValueCount: len(vs)})
		}
		if len(vs) > 0 {
			p.Query[k] = vs[0]
			queryCount++
		}
	}
	// Headers (minimize secrets)
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		// 多头歧义计数须在脱敏分支之前统计（只记名+次数，不落值）：
		// authorization/cookie/x-api-key 多头同样是 HPP/走私信号
		if len(vs) > 1 {
			p.addAmbiguity(ParamAmbiguity{Location: AmbLocationHeader, ParameterName: lk, ValueCount: len(vs)})
		}
		if lk == "authorization" || lk == "cookie" || lk == "x-api-key" {
			p.Headers[lk] = "[redacted]"
			continue
		}
		if len(vs) > 0 {
			p.Headers[lk] = vs[0]
		}
	}

	// Body
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		mediaType, params := splitMediaType(p.ContentType)
		if mediaType == "multipart/form-data" && params["boundary"] != "" {
			// multipart 流式解析：文件内容不落内存，仅计 part 元数据与大小
			p.parseMultipart(r.Body, params["boundary"], limits)
		} else {
			limit := int64(limits.MaxBodyParseBytes) + 1
			if limit < 2 {
				limit = 2
			}
			raw, err := io.ReadAll(io.LimitReader(r.Body, limit))
			if err != nil && err != io.EOF {
				return p, err
			}
			_ = r.Body.Close()
			if len(raw) > limits.MaxBodyParseBytes {
				p.BodyTruncated = true
				sample := limits.MaxBodySampleBytes
				if sample <= 0 {
					sample = limits.MaxBodyParseBytes
				}
				if sample > len(raw) {
					sample = len(raw)
				}
				// keep only sample for type sniffing; do not full-parse oversized bodies
				raw = raw[:sample]
			}
			p.BodySize = len(raw)
			p.BodyHash = shortHash(raw)
			ct := strings.ToLower(p.ContentType)
			isJSONBody := strings.Contains(ct, "application/json") || looksLikeJSON(raw)
			switch {
			case IsGRPCMediaType(mediaType):
				// gRPC 帧结构校验（P2-05）：截断体仅校验样本内完整帧
				// （单帧超上限仍可判，声明长度超样本剩余不可判——样本边界非体边界）
				p.GRPC = parseGRPCFrames(raw, limits.MaxGRPCFrameBytes, !p.BodyTruncated)
			case p.BodyTruncated:
				// truncated: skip full field walk to avoid partial schema pollution
				if isJSONBody {
					p.IsJSON = true
				}
			case mediaType == "application/graphql":
				// 原始 GraphQL 查询文档（优先于 JSON 嗅探："{" 开头的查询不是 JSON）
				p.extractGraphQLQuery(string(raw))
			case isJSONBody:
				p.IsJSON = true
				// 重复键流式预扫（json.Unmarshal last-wins 使重复键不可追溯的修复）：
				// BodyTruncated 时样本非完整 JSON 必误扫，跳过——switch 分支序已保证
				// 截断体走不到本分支，此处双保险
				if !p.BodyTruncated {
					p.scanJSONDuplicateKeys(raw, limits)
				}
				// 一次解析：解码根值复用于 GraphQL 提取（任务书原则 2.1，禁止重复解析）
				if v, ok := extractJSONFields(raw, "", p, limits); ok {
					p.extractGraphQLJSON(v)
				}
			case mediaType == "application/x-www-form-urlencoded":
				p.extractFormFields(raw, limits)
			case isXMLMediaType(mediaType):
				p.extractXMLFields(raw, limits)
			}
		}
	}

	if ctx != nil {
		ctx.HTTPMethod = p.Method
		ctx.RawPath = p.RawPath
		ctx.NormalizedPath = p.NormalizedPath
		ctx.RequestContentType = p.ContentType
		ctx.RequestBodySize = int64(p.BodySize)
		ctx.RequestBodyHash = p.BodyHash
		ctx.BodyTruncated = p.BodyTruncated
		ctx.FieldCountCapped = p.FieldCapped
		// 解析产物经 Extensions 写入（键固定，值已脱敏；见 Ext* 常量）
		if len(p.FormFields) > 0 {
			ctx.SetExtension(ExtFormFields, p.FormFields)
		}
		if len(p.XMLFields) > 0 {
			ctx.SetExtension(ExtXMLFields, p.XMLFields)
		}
		if len(p.MultipartParts) > 0 {
			ctx.SetExtension(ExtMultipartParts, p.MultipartParts)
		}
		if p.HasFiles {
			ctx.SetExtension(ExtHasFiles, true)
		}
		if p.GraphQLOperation != "" {
			ctx.SetExtension(ExtGraphQLOperation, p.GraphQLOperation)
		}
		if p.GraphQLOperationName != "" {
			ctx.SetExtension(ExtGraphQLOperationName, p.GraphQLOperationName)
		}
		if len(p.GraphQLVariables) > 0 {
			ctx.SetExtension(ExtGraphQLVariables, p.GraphQLVariables)
		}
		if p.MultipartCapped {
			ctx.SetExtension(ExtMultipartCapped, true)
		}
		if p.XMLTruncated {
			ctx.SetExtension(ExtXMLTruncated, true)
		}
		if p.XMLDTDBlocked {
			ctx.SetExtension(ExtXMLDTDBlocked, true)
		}
		if id := r.Header.Get("X-Request-Id"); id != "" && ctx.RequestID == "" {
			ctx.RequestID = id
		}
		if ctx.RequestID == "" {
			if id := r.Header.Get("X-Jiuzhang-Request-ID"); id != "" {
				ctx.RequestID = id
			}
		}
	}
	return p, nil
}

func looksLikeJSON(b []byte) bool {
	s := strings.TrimSpace(string(b))
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func extractJSONFields(raw []byte, prefix string, p *Parsed, limits dsctx.ParseLimits) (any, bool) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, false
	}
	walkJSON(v, prefix, 0, p, limits)
	return v, true
}

// scanJSONDuplicateKeys 对内存中的完整 JSON body 做一趟流式扫描，检测对象重复键
// （含嵌套对象；json.Unmarshal 到 map 的 last-wins 语义使重复键不可追溯，此为
// 可追溯修复）。只记录键路径与出现次数，不落值；结果先落本地缓冲，根值配平
// 读完才登记——截断/非法 JSON 整条丢弃（与 extractJSONFields 解析失败零字段
// 同一语义，不产出半份扫描结论；json.Decoder.Token 对截断输入返回裸 io.EOF，
// 故配平不变量须自行维护）；深度超 MaxJSONDepth 的层级不再跟踪键（继续配平
// 校验整篇文档），深度内已扫记录保留（与 walkJSON 深度截断仍落字段同一纪律）。
// 调用方保证体未截断（截断样本非完整 JSON，不扫）。
func (p *Parsed) scanJSONDuplicateKeys(raw []byte, limits dsctx.ParseLimits) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	type frame struct {
		isObj     bool
		path      string         // 帧路径（根为 ""，数组段以 [] 结尾，与 walkJSON 同口径）
		expectKey bool           // 对象帧：下一 string token 是否为键名
		lastKey   string         // 对象帧：最近键名（值若为容器，作子帧路径段）
		seen      map[string]int // 对象帧：键名出现次数
		dupIdx    map[string]int // 对象帧：重复键 → found 下标（次数递增原地更新）
	}
	var found []ParamAmbiguity
	stack := make([]frame, 0, 8)
	overflow := 0  // 深度上限外的容器计数（只配平校验，不跟踪键）
	ended := false // 根值已完整结束（恰好一个根值且容器全配平）
	open := func(isObj bool) {
		f := frame{isObj: isObj, expectKey: true}
		if n := len(stack); n > 0 {
			top := &stack[n-1]
			if top.isObj {
				f.path = joinJSONPath(top.path, top.lastKey)
				top.expectKey = true // 容器作为该键的值已消费，回到待键状态
			} else {
				f.path = top.path + "[]"
			}
		}
		if isObj {
			f.seen = map[string]int{}
			f.dupIdx = map[string]int{}
		}
		stack = append(stack, f)
	}
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return // 非法 JSON：丢弃半份扫描（字段解析侧同样失败，不重复报错）
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				if ended {
					return // 第二根值：非法 JSON，丢弃半份扫描
				}
				if overflow > 0 {
					overflow++
					break
				}
				if len(stack) >= limits.MaxJSONDepth {
					// 深度上限：值槽已消费（父对象帧回到待键），深层只配平不跟踪键
					if n := len(stack); n > 0 && stack[n-1].isObj {
						stack[n-1].expectKey = true
					}
					overflow = 1
					break
				}
				open(t == '{')
			case '}', ']':
				if overflow > 0 {
					overflow--
					break
				}
				if len(stack) == 0 {
					return // 配平破坏：非法 JSON，丢弃半份扫描
				}
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					ended = true
				}
			}
		case string:
			if overflow > 0 {
				break // 深度上限外：不跟踪键
			}
			if n := len(stack); n > 0 && stack[n-1].isObj {
				top := &stack[n-1]
				if !top.expectKey {
					top.expectKey = true // 字符串值：回到待键状态
					break
				}
				top.expectKey = false
				top.lastKey = t
				top.seen[t]++
				switch c := top.seen[t]; {
				case c == 2:
					top.dupIdx[t] = len(found)
					found = append(found, ParamAmbiguity{
						Location:      AmbLocationJSON,
						ParameterName: t,
						ValueCount:    c,
						Path:          joinJSONPath(top.path, t),
					})
				case c > 2:
					// 同键第 3+ 次出现：原地更新次数（一条歧义记总数，不重复发记录）
					found[top.dupIdx[t]].ValueCount = c
				}
			}
		default:
			if overflow > 0 {
				break
			}
			// 数字/布尔/null 标量值：对象帧回到待键状态（值不入任何记录）
			if n := len(stack); n > 0 && stack[n-1].isObj {
				stack[n-1].expectKey = true
			}
		}
	}
	if !ended {
		return // 截断/空输入：根值未完整结束，丢弃半份扫描
	}
	for _, a := range found {
		p.addAmbiguity(a)
	}
}

// joinJSONPath 拼接 JSON 点路径（与 walkJSON 的 path 口径一致）。
func joinJSONPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// maxScalarValueLen 标量值留存截断长度（字符数；值只在请求内存活）。
const maxScalarValueLen = 256

func walkJSON(v any, path string, depth int, p *Parsed, limits dsctx.ParseLimits) {
	if depth > limits.MaxJSONDepth {
		return
	}
	if p.FieldCount >= limits.MaxFieldCount {
		p.FieldCapped = true
		return
	}
	switch t := v.(type) {
	case map[string]any:
		if path != "" {
			p.JSONFields[path] = "object"
			p.FieldCount++
		}
		for k, child := range t {
			if p.FieldCount >= limits.MaxFieldCount {
				p.FieldCapped = true
				return
			}
			np := k
			if path != "" {
				np = path + "." + k
			}
			walkJSON(child, np, depth+1, p, limits)
		}
	case []any:
		p.JSONFields[path] = "array"
		p.FieldCount++
		if len(t) > 0 {
			walkJSON(t[0], path+"[]", depth+1, p, limits)
		}
	case string:
		p.JSONFields[path] = "string"
		p.FieldCount++
		if limits.RetainJSONScalarValues {
			p.JSONValues[path] = truncateScalarValue(t)
		}
	case float64:
		p.JSONFields[path] = "number"
		p.FieldCount++
		if limits.RetainJSONScalarValues {
			p.JSONValues[path] = strconv.FormatFloat(t, 'g', -1, 64)
		}
	case bool:
		p.JSONFields[path] = "bool"
		p.FieldCount++
		if limits.RetainJSONScalarValues {
			p.JSONValues[path] = strconv.FormatBool(t)
		}
	case nil:
		p.JSONFields[path] = "null"
		p.FieldCount++
	default:
		p.JSONFields[path] = "unknown"
		p.FieldCount++
	}
}

// truncateScalarValue 标量值截断（按字符数），防超长值占内存。
func truncateScalarValue(s string) string {
	if utf8.RuneCountInString(s) <= maxScalarValueLen {
		return s
	}
	return string([]rune(s)[:maxScalarValueLen])
}

func shortHash(b []byte) string {
	// FNV-1a 64 for lightweight body fingerprint (not crypto)
	var h uint64 = 14695981039346656037
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return formatHex(h)
}

func formatHex(h uint64) string {
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 16)
	for i := 15; i >= 0; i-- {
		buf[i] = hexdigits[h&0xf]
		h >>= 4
	}
	return string(buf)
}

// splitMediaType 拆分 Content-Type 主类型与参数；头部畸形时降级为 ';' 前缀（小写）。
func splitMediaType(ct string) (string, map[string]string) {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0])), nil
	}
	return mt, params
}

// isXMLMediaType 匹配 application/xml、text/xml 及 +xml 后缀类型（如 application/soap+xml）。
func isXMLMediaType(mt string) bool {
	return mt == "application/xml" || mt == "text/xml" || strings.HasSuffix(mt, "+xml")
}
