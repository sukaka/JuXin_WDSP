// authzcheck.go 授权基线运行时检测（W4-GW，P0-16 BFLA / P0-17 字段权限；W11-RAUTHZ 补响应侧）：
//   - 角色提取：JWT Bearer 未验签 claims 的 role/roles 自定义 claim（字符串或数组），无凭据 = 匿名；
//   - BFLA：端点存在 confirmed 角色基线时，请求角色无匹配 allowed 基线 / 匿名访问产生观察明细；
//   - 字段权限（请求侧）：请求 JSON BODY 字段命中 FORBIDDEN / READ_ONLY / SERVER_GENERATED /
//     ADMIN_WRITABLE 基线时产出明细；
//   - 字段权限（响应侧，W11-RAUTHZ）：响应 JSON 字段命中 RESPONSE 方向 FORBIDDEN / SENSITIVE
//     基线时产出越权读取/敏感暴露观察明细（与脱敏计划、敏感字段检测去重）。
//
// 纪律：无端点基线零行为（基线缺失不判）；证据只含字段名/角色名/属性，绝不落请求/响应值。
package detectors

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// RoleBaseline 发布通道下发的角色功能级基线（server api_role_baselines 表 confirmed 行镜像）。
// 运行时按 endpoint+method+role 归并判定：action 为管理面业务动作语义，随契约透传但不参与匹配
// （网关无法观测业务动作）。json tag 为跨分片契约，不得改动。
type RoleBaseline struct {
	EndpointKey string `json:"endpoint_key"`
	Role        string `json:"role"`
	Method      string `json:"method"`
	Action      string `json:"action"`
	Allowed     bool   `json:"allowed"`
}

// FieldPermission 发布通道下发的字段权限（server api_field_permissions 表行镜像）。
// Role/Tenant 空串 = 默认行。json tag 为跨分片契约，不得改动。
type FieldPermission struct {
	EndpointKey string `json:"endpoint_key"`
	FieldPath   string `json:"field_path"` // location.a.b 风格（本波仅消费 json. 前缀）
	Direction   string `json:"direction"`  // REQUEST / RESPONSE
	Attribute   string `json:"attribute"`  // 七值枚举（见 fieldAttribute* 常量）
	Role        string `json:"role"`       // 空 = 默认行；非空 = 角色覆盖行
	Tenant      string `json:"tenant"`     // 空 = 默认行；非空 = 租户覆盖行
}

// 字段方向（与 api_field_permissions.direction CHECK 对齐）。
const (
	fieldDirectionRequest  = "REQUEST"
	fieldDirectionResponse = "RESPONSE"
)

// 字段属性七值（与 api_field_permissions.attribute CHECK 对齐）。
const (
	fieldAttributeReadable        = "READABLE"
	fieldAttributeWritable        = "WRITABLE"
	fieldAttributeReadOnly        = "READ_ONLY"
	fieldAttributeAdminWritable   = "ADMIN_WRITABLE"
	fieldAttributeServerGenerated = "SERVER_GENERATED"
	fieldAttributeSensitive       = "SENSITIVE"
	fieldAttributeForbidden       = "FORBIDDEN"
)

// maxAuthzFieldMatches 单请求字段权限 match 上限（防超大报文撑爆事件，与 maxSensitiveMatches 同纪律）。
const maxAuthzFieldMatches = 20

// maxRoleClaimLen / maxRolesPerRequest 未验签 JWT 角色声明的读取上限：
// claims 不可信，限长防脏数据放大（与管理面 maxRoleLen=64 对齐）。
const (
	maxRoleClaimLen     = 64
	maxRolesPerRequest  = 16
	anonymousRoleReason = "no_credential"
)

// ExtractRequestRoles 提取请求角色集：Authorization Bearer JWT 的未验签 claims 中
// role/roles 自定义 claim（字符串或字符串数组；两键并存时合并去重）。
// 不验签（与 authentication.go 的 JWT 结构级解析同一纪律：角色声明仅作观察信号，不作信任决策）。
// 无凭据/非 Bearer/非 JWT 形态/claims 不可解析/无角色声明时返回 nil（调用方按匿名或无角色处理）。
func ExtractRequestRoles(r *http.Request) []string {
	if r == nil {
		return nil
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if authz == "" {
		return nil
	}
	parts := strings.SplitN(authz, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "bearer") {
		return nil
	}
	segs := strings.Split(strings.TrimSpace(parts[1]), ".")
	if len(segs) != 3 {
		return nil // 非 JWT 形态（opaque bearer）无 claims 可解
	}
	payload, err := base64.RawURLEncoding.DecodeString(segs[1])
	if err != nil {
		// 兼容带 padding（与 authentication.go 同一容错）
		payload, err = base64.URLEncoding.DecodeString(segs[1])
		if err != nil {
			return nil
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	var roles []string
	seen := map[string]bool{}
	roles = appendRoleClaim(roles, seen, claims["role"])
	roles = appendRoleClaim(roles, seen, claims["roles"])
	return roles
}

// appendRoleClaim 归并单个 role/roles claim（字符串或字符串数组；去重、限长、限量）。
func appendRoleClaim(roles []string, seen map[string]bool, v any) []string {
	switch t := v.(type) {
	case string:
		roles = appendOneRole(roles, seen, t)
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok {
				roles = appendOneRole(roles, seen, s)
			}
		}
	}
	return roles
}

// appendOneRole 追加单个角色名（trim、限长 64、去重、单请求上限 16）。
func appendOneRole(roles []string, seen map[string]bool, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxRoleClaimLen || seen[s] || len(roles) >= maxRolesPerRequest {
		return roles
	}
	seen[s] = true
	return append(roles, s)
}

// hasAuthzCredential 判定请求是否携带凭据（Authorization/X-API-Key/Cookie；
// BFLA 匿名判定口径，与 CredentialKey 的凭据口径一致）。
func hasAuthzCredential(r *http.Request) bool {
	if r == nil {
		return false
	}
	return strings.TrimSpace(r.Header.Get("Authorization")) != "" ||
		strings.TrimSpace(r.Header.Get("X-API-Key")) != "" ||
		strings.TrimSpace(r.Header.Get("Cookie")) != ""
}

func roleIn(role string, roles []string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// CheckRoleBaseline BFLA 基线检测：baselines 为本端点 confirmed 角色基线（装配层按端点解析后传入）。
// 无端点基线零行为（基线缺失不判——未建模端点不得放大为误报）。
// 有基线时：匿名访问 → authz.bfla_anonymous（OBSERVE/HIGH）；
// 请求角色无任何匹配（endpoint+method+role）allowed 基线 → authz.bfla_role_mismatch（OBSERVE/MEDIUM）。
// 证据只含端点/方法/角色名，不落凭据与请求值。
func CheckRoleBaseline(ctx *dsctx.RequestContext, r *http.Request, endpointKey, method string, baselines []RoleBaseline) {
	if ctx == nil || len(baselines) == 0 {
		return
	}
	if !hasAuthzCredential(r) {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_authz",
			RuleID:     "authz.bfla_anonymous",
			Category:   "OBSERVE",
			Severity:   "HIGH",
			Message:    "anonymous access to endpoint with confirmed role baseline",
			Evidence:   map[string]string{"endpoint_key": endpointKey, "method": method, "reason": anonymousRoleReason},
			ScoreDelta: 30,
		})
		return
	}
	roles := ExtractRequestRoles(r)
	for _, b := range baselines {
		if b.Allowed && strings.EqualFold(b.Method, method) && roleIn(b.Role, roles) {
			return // 命中允许基线：无违例
		}
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "api_authz",
		RuleID:     "authz.bfla_role_mismatch",
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "request role has no allowed baseline for endpoint+method",
		Evidence:   map[string]string{"endpoint_key": endpointKey, "method": method, "roles": strings.Join(roles, ",")},
		ScoreDelta: 15,
	})
}

// CheckFieldPermissions 字段权限检测（Mass Assignment）：perms 为本端点字段权限（装配层按端点解析后传入）。
// 仅消费 direction=REQUEST、tenant 为空（默认/角色覆盖行）、field_path 为 json. 前缀的行；
// RESPONSE 方向行由响应相位 CheckResponseFieldPermissions 消费（本函数恒定跳过）；
// 租户覆盖行运行时无租户上下文可比对，本波不判定（跳过而非放行语义）。
// 命中语义：FORBIDDEN → authz.forbidden_field（BLOCK 类：PROTECT 定案阻断，OBSERVE 维持观察）；
// SERVER_GENERATED → authz.server_generated_write（OBSERVE）；READ_ONLY → authz.readonly_write（OBSERVE）；
// ADMIN_WRITABLE 且请求角色不含行内指定角色 → authz.readonly_write（OBSERVE）。
// 证据只含字段名/属性/角色名，绝不落请求值。
func CheckFieldPermissions(ctx *dsctx.RequestContext, r *http.Request, endpointKey string, perms []FieldPermission, p *parser.Parsed) {
	if ctx == nil || p == nil || len(perms) == 0 || len(p.JSONFields) == 0 {
		return
	}
	// 索引本波可判定行（REQUEST 方向 + 无租户限定 + json. 前缀）
	byField := map[string][]FieldPermission{}
	for _, pm := range perms {
		if !strings.EqualFold(pm.Direction, fieldDirectionRequest) {
			continue
		}
		if pm.Tenant != "" {
			continue
		}
		if !strings.HasPrefix(pm.FieldPath, "json.") {
			continue
		}
		byField[pm.FieldPath] = append(byField[pm.FieldPath], pm)
	}
	if len(byField) == 0 {
		return
	}
	roles := ExtractRequestRoles(r)
	// 稳定遍历序（map 乱序会让事件明细序抖动）
	paths := make([]string, 0, len(p.JSONFields))
	for path := range p.JSONFields {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	n := 0
	for _, path := range paths {
		rows := byField["json."+path]
		if len(rows) == 0 {
			continue
		}
		if evaluateFieldPermission(ctx, endpointKey, path, rows, roles) {
			n++
			if n >= maxAuthzFieldMatches {
				return
			}
		}
	}
}

// evaluateFieldPermission 对单字段的可判定权限行求值，命中时写一条 match 并返回 true。
// 优先级：FORBIDDEN > SERVER_GENERATED > READ_ONLY > ADMIN_WRITABLE（每字段至多一条明细）。
// 行适用性：默认行（role 空）对全部角色生效；角色覆盖行仅对行内角色生效。
// ADMIN_WRITABLE 例外：行的 role 为「指定可写角色」，请求角色不含它即违例，
// 故其判定不要求行适用；role 为空的 ADMIN_WRITABLE 默认行未指定可写角色，运行时不可判定，跳过。
func evaluateFieldPermission(ctx *dsctx.RequestContext, endpointKey, path string, rows []FieldPermission, roles []string) bool {
	var forbidden, serverGenerated, readOnly bool
	var adminRoles []string
	for _, row := range rows {
		applies := row.Role == "" || roleIn(row.Role, roles)
		switch row.Attribute {
		case fieldAttributeForbidden:
			if applies {
				forbidden = true
			}
		case fieldAttributeServerGenerated:
			if applies {
				serverGenerated = true
			}
		case fieldAttributeReadOnly:
			if applies {
				readOnly = true
			}
		case fieldAttributeAdminWritable:
			if row.Role != "" {
				adminRoles = append(adminRoles, row.Role)
			}
		default:
			// READABLE/WRITABLE 为允许语义、SENSITIVE 由敏感数据检测器覆盖：请求侧不产生运行时信号
		}
	}
	ev := func(attribute string) map[string]string {
		return map[string]string{
			"endpoint_key": endpointKey,
			"field":        path,
			"location":     "json",
			"attribute":    attribute,
			"roles":        strings.Join(roles, ","),
		}
	}
	switch {
	case forbidden:
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_authz",
			RuleID:     "authz.forbidden_field",
			Category:   "BLOCK",
			Severity:   "HIGH",
			Message:    "forbidden field present in request body (mass assignment)",
			Evidence:   ev(fieldAttributeForbidden),
			ScoreDelta: 40,
		})
		return true
	case serverGenerated:
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_authz",
			RuleID:     "authz.server_generated_write",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "server-generated field provided by client",
			Evidence:   ev(fieldAttributeServerGenerated),
			ScoreDelta: 15,
		})
		return true
	case readOnly:
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_authz",
			RuleID:     "authz.readonly_write",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "read-only field written in request body",
			Evidence:   ev(fieldAttributeReadOnly),
			ScoreDelta: 15,
		})
		return true
	default:
		// ADMIN_WRITABLE：存在指定可写角色且请求角色均不匹配 → 越权写入嫌疑
		for _, designated := range adminRoles {
			if roleIn(designated, roles) {
				return false // 指定角色本人写入：允许
			}
		}
		if len(adminRoles) > 0 {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "api_authz",
				RuleID:     "authz.readonly_write",
				Category:   "OBSERVE",
				Severity:   "MEDIUM",
				Message:    "admin-only field written by non-designated role",
				Evidence:   ev(fieldAttributeAdminWritable),
				ScoreDelta: 15,
			})
			return true
		}
		return false
	}
}

// CheckResponseFieldPermissions 响应方向字段权限检测（W11-RAUTHZ，P0-17 响应侧防越权读取）：
// perms 为本端点字段权限（装配层按端点解析后传入）；roles 为请求角色集（挂点侧复用
// ExtractRequestRoles 提取，匿名/无角色声明为 nil）；fields 为响应相位 JSON 解析产物
// （字段路径→类型，不落值）；plan 为本相位已生成的脱敏计划；sensitive 为本相位敏感字段命中。
//
// 仅消费 direction=RESPONSE、tenant 为空（默认/角色覆盖行）、field_path 为 json. 前缀的行；
// 租户覆盖行运行时无租户上下文可比对，本波不判定（跳过而非放行语义，与请求侧同一纪律）。
//
// 命中语义（每字段至多一条明细，FORBIDDEN 优先）：
//   - FORBIDDEN → authz.response_forbidden_field（OBSERVE/MEDIUM，越权读取嫌疑）；字段同被
//     本相位脱敏计划以 REMOVE/MASK 覆盖时不重复产出——脱敏是管理面对该字段的显式治理
//     （值不明文外发），治理动作优先于越权读取观察；HASH 仍外发摘要，不参与去重；
//   - SENSITIVE → authz.response_sensitive_field（OBSERVE/LOW，人工确认敏感属性随响应暴露）；
//     字段已被敏感字段检测命中（sensitive.response_field）时不重复产出（同路径证据不叠加）。
//
// 行适用性与请求侧一致：默认行（role 空）对全部角色生效；角色覆盖行仅对行内角色生效。
// 其余属性（READABLE/WRITABLE/READ_ONLY/ADMIN_WRITABLE/SERVER_GENERATED）无响应侧语义，跳过。
// 证据只含字段路径/属性/角色名，绝不落响应值；无下发或无解析产物时零行为。
func CheckResponseFieldPermissions(ctx *dsctx.RequestContext, roles []string, endpointKey string, perms []FieldPermission, fields map[string]string, plan []dsctx.FieldTransform, sensitive []dsctx.SensitiveFieldHit) {
	if ctx == nil || len(perms) == 0 || len(fields) == 0 {
		return
	}
	// 索引可判定行（RESPONSE 方向 + 无租户限定 + json. 前缀；键为去掉前缀的字段路径）
	byField := map[string][]FieldPermission{}
	for _, pm := range perms {
		if !strings.EqualFold(pm.Direction, fieldDirectionResponse) {
			continue
		}
		if pm.Tenant != "" {
			continue
		}
		if !strings.HasPrefix(pm.FieldPath, "json.") {
			continue
		}
		path := strings.TrimPrefix(pm.FieldPath, "json.")
		byField[path] = append(byField[path], pm)
	}
	if len(byField) == 0 {
		return
	}
	// 脱敏去重集合：REMOVE/MASK 计划项覆盖的字段路径
	//（算法词表见 dsctx.FieldTransform.Algorithm，与 response.Algorithm* 常量一致）
	masked := map[string]bool{}
	for _, ft := range plan {
		if ft.Algorithm == "REMOVE" || ft.Algorithm == "MASK" {
			masked[ft.FieldPath] = true
		}
	}
	// 敏感检测去重集合（与 sensitive.response_field 同路径不重复产出）
	sensitiveHit := map[string]bool{}
	for _, h := range sensitive {
		sensitiveHit[h.Path] = true
	}
	// 稳定遍历序（map 乱序会让事件明细序抖动，与请求侧同一纪律）
	paths := make([]string, 0, len(fields))
	for path := range fields {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	n := 0
	for _, path := range paths {
		rows := byField[path]
		if len(rows) == 0 {
			continue
		}
		if evaluateResponseFieldPermission(ctx, endpointKey, path, rows, roles, masked, sensitiveHit) {
			n++
			if n >= maxAuthzFieldMatches {
				return
			}
		}
	}
}

// evaluateResponseFieldPermission 对单字段的响应方向权限行求值，命中时写一条 match 并返回 true。
// 优先级：FORBIDDEN > SENSITIVE（每字段至多一条明细）；去重语义见 CheckResponseFieldPermissions。
func evaluateResponseFieldPermission(ctx *dsctx.RequestContext, endpointKey, path string, rows []FieldPermission, roles []string, masked, sensitiveHit map[string]bool) bool {
	var forbidden, sensitiveAttr bool
	for _, row := range rows {
		if row.Role != "" && !roleIn(row.Role, roles) {
			continue // 角色覆盖行仅对行内角色生效
		}
		switch row.Attribute {
		case fieldAttributeForbidden:
			forbidden = true
		case fieldAttributeSensitive:
			sensitiveAttr = true
		default:
			// READABLE/WRITABLE/READ_ONLY/ADMIN_WRITABLE/SERVER_GENERATED 无响应侧语义
		}
	}
	ev := func(attribute string) map[string]string {
		return map[string]string{
			"endpoint_key": endpointKey,
			"field":        path,
			"location":     "response_json",
			"attribute":    attribute,
			"roles":        strings.Join(roles, ","),
		}
	}
	switch {
	case forbidden:
		if masked[path] {
			return false // 字段已被 REMOVE/MASK 治理（值不明文外发），不重复判定
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_authz",
			RuleID:     "authz.response_forbidden_field",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "forbidden field present in response body (excessive data exposure)",
			Evidence:   ev(fieldAttributeForbidden),
			ScoreDelta: 10,
		})
		return true
	case sensitiveAttr:
		if sensitiveHit[path] {
			return false // 敏感字段检测已产出同路径证据，不重复判定
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_authz",
			RuleID:     "authz.response_sensitive_field",
			Category:   "OBSERVE",
			Severity:   "LOW",
			Message:    "confirmed-sensitive field present in response body",
			Evidence:   ev(fieldAttributeSensitive),
			ScoreDelta: 5,
		})
		return true
	default:
		return false
	}
}

// GroupRoleBaselines 按 endpoint_key 归组角色基线（装配层调用；运行期按端点直接选取，避免逐请求全量扫描）。
func GroupRoleBaselines(in []RoleBaseline) map[string][]RoleBaseline {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]RoleBaseline, len(in))
	for _, b := range in {
		out[b.EndpointKey] = append(out[b.EndpointKey], b)
	}
	return out
}

// GroupFieldPermissions 按 endpoint_key 归组字段权限（装配层调用，纪律同 GroupRoleBaselines）。
func GroupFieldPermissions(in []FieldPermission) map[string][]FieldPermission {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]FieldPermission, len(in))
	for _, pm := range in {
		out[pm.EndpointKey] = append(out[pm.EndpointKey], pm)
	}
	return out
}

// ValidateAuthzRules 装配期校验授权基线下发内容（配置错误显式返回，不静默吞错）：
// 基线 endpoint_key/role/method 非空；字段权限 endpoint_key/field_path 非空且
// direction/attribute 在冻结词汇内（与迁移 000044 CHECK 一致）。
func ValidateAuthzRules(baselines []RoleBaseline, perms []FieldPermission) error {
	for i, b := range baselines {
		if b.EndpointKey == "" || b.Role == "" || b.Method == "" {
			return fmt.Errorf("api_role_baselines[%d]: endpoint_key/role/method must be non-empty", i)
		}
	}
	for i, pm := range perms {
		if pm.EndpointKey == "" || pm.FieldPath == "" {
			return fmt.Errorf("api_field_permissions[%d]: endpoint_key/field_path must be non-empty", i)
		}
		switch pm.Direction {
		case fieldDirectionRequest, fieldDirectionResponse:
		default:
			return fmt.Errorf("api_field_permissions[%d]: invalid direction %q", i, pm.Direction)
		}
		switch pm.Attribute {
		case fieldAttributeReadable, fieldAttributeWritable, fieldAttributeReadOnly,
			fieldAttributeAdminWritable, fieldAttributeServerGenerated, fieldAttributeSensitive,
			fieldAttributeForbidden:
		default:
			return fmt.Errorf("api_field_permissions[%d]: invalid attribute %q", i, pm.Attribute)
		}
	}
	return nil
}
