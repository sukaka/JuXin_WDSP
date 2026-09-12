// types.go 敏感数据管理面实体、枚举常量与纯函数校验（handler 与 store 共用）。
package apidata

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound 资源不存在（敏感数据类型 / 脱敏规则）。
var ErrNotFound = errors.New("api data resource not found")

// 权限点常量（种子迁移由集成方登记，本包只引用）。
const (
	PermDataRead   = "api_data.read"
	PermDataManage = "api_data.manage"
)

// 五级敏感等级（api_sensitive_data_types.level CHECK 对齐）。
const (
	LevelNonSensitive = "NON_SENSITIVE"
	LevelGeneral      = "GENERAL"
	LevelSensitive    = "SENSITIVE"
	LevelImportant    = "IMPORTANT"
	LevelCore         = "CORE"
)

// 类型状态（api_sensitive_data_types.status CHECK 对齐）。
const (
	TypeStatusEnabled  = "ENABLED"
	TypeStatusDisabled = "DISABLED"
)

// 脱敏作用域（api_masking_rules.scope CHECK 对齐）。
const (
	ScopeGlobal      = "GLOBAL"
	ScopeApplication = "APPLICATION"
	ScopeEndpoint    = "ENDPOINT"
)

// 脱敏算法（api_masking_rules.algorithm CHECK 对齐）。
const (
	AlgorithmMask   = "MASK"   // 掩码（params：keep_head/keep_tail 等）
	AlgorithmHash   = "HASH"   // 散列（params：hash_algo/salt_key 等）
	AlgorithmRemove = "REMOVE" // 整体移除字段
)

// ValidatorLuhn 值校验器：银行卡号 luhn 校验（白名单可扩展，空串 = 无值校验器）。
const ValidatorLuhn = "luhn"

// validLocations 字段可能出现位置白名单。
// query/json/form/xml 与网关 sensitive.go 当前扫描面一致；header/cookie/path/response_body
// 为规划扩展面（P0-19 Known Gap：PATH/HEADER/COOKIE/RESPONSE_* 尚未覆盖），管理面先行登记。
var validLocations = map[string]bool{
	"query": true, "json": true, "form": true, "xml": true,
	"header": true, "cookie": true, "path": true, "response_body": true,
}

// 输入上限（防超大定义撑爆表与请求体）。
const (
	maxNameLen        = 128
	maxCategoryLen    = 64
	maxDataTypeLen    = 64
	maxDescriptionLen = 512
	maxRegexLen       = 1024
	maxFieldPathLen   = 512
	maxStrListItems   = 64
	maxStrListItemLen = 128
)

// SensitiveDataType 敏感数据类型（api_sensitive_data_types）。
type SensitiveDataType struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Category      string    `json:"category"`
	Level         string    `json:"level"`          // 五级敏感等级
	DataType      string    `json:"data_type"`      // 数据类型标签（与网关 evidence.data_type 对齐）
	Locations     []string  `json:"locations"`      // 可能出现位置
	Keywords      []string  `json:"keywords"`       // 字段名词根
	Regex         string    `json:"regex"`          // 值级正则（空 = 不做值检测）
	Validator     string    `json:"validator"`      // 值校验器（'' / luhn）
	ExcludeFields []string  `json:"exclude_fields"` // 排除字段名
	Status        string    `json:"status"`         // ENABLED / DISABLED
	Version       int       `json:"version"`        // 编辑自增
	IsBuiltin     bool      `json:"is_builtin"`     // 内置类型：禁删、名称不可改
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// MaskingRule 脱敏规则（api_masking_rules；列名为跨分片契约，发布分片按列名读取下发网关）。
// EndpointKey/DataType/ApplicationID/CreatedBy 为可空列，Go 侧用指针表达 NULL 语义。
type MaskingRule struct {
	ID            uuid.UUID       `json:"id"`
	Name          string          `json:"name"`
	Enabled       bool            `json:"enabled"`
	Scope         string          `json:"scope"`           // GLOBAL / APPLICATION / ENDPOINT
	ApplicationID *uuid.UUID      `json:"application_id"`  // scope=APPLICATION 必填
	EndpointKey   *string         `json:"endpoint_key"`    // scope=ENDPOINT 必填（METHOD + 空格 + 路径模板）
	FieldPath     string          `json:"field_path"`      // 目标字段路径（与 DataType 至少其一）
	DataType      *string         `json:"data_type"`       // 目标数据类型标签（整类脱敏）
	Algorithm     string          `json:"algorithm"`       // MASK / HASH / REMOVE
	Params        json.RawMessage `json:"params_json"`     // 算法参数对象
	Exclusions    json.RawMessage `json:"exclusions_json"` // 排除对象
	CreatedBy     *string         `json:"created_by"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// MaskExclusions exclusions_json 解析结果（键白名单 identity/role/ip）。
type MaskExclusions struct {
	Identity []string `json:"identity,omitempty"` // 身份指纹精确匹配
	Role     []string `json:"role,omitempty"`     // 角色码精确匹配
	IP       []string `json:"ip,omitempty"`       // IP 或 CIDR
}

// ---------- 校验（纯函数） ----------

// validLevel / validTypeStatus / validScope / validAlgorithm 枚举校验。
func validLevel(s string) bool {
	switch s {
	case LevelNonSensitive, LevelGeneral, LevelSensitive, LevelImportant, LevelCore:
		return true
	}
	return false
}

func validTypeStatus(s string) bool { return s == TypeStatusEnabled || s == TypeStatusDisabled }

func validScope(s string) bool {
	return s == ScopeGlobal || s == ScopeApplication || s == ScopeEndpoint
}

func validAlgorithm(s string) bool {
	return s == AlgorithmMask || s == AlgorithmHash || s == AlgorithmRemove
}

// checkStrList 校验字符串数组列（keywords/locations/exclude_fields 共用）。
func checkStrList(field string, items []string, whitelist map[string]bool) error {
	if len(items) > maxStrListItems {
		return fmt.Errorf("%s 数量不能超过 %d", field, maxStrListItems)
	}
	for _, it := range items {
		if strings.TrimSpace(it) == "" || len(it) > maxStrListItemLen {
			return fmt.Errorf("%s 项不能为空且长度不能超过 %d", field, maxStrListItemLen)
		}
		if whitelist != nil && !whitelist[it] {
			return fmt.Errorf("%s 含非法取值 %q", field, it)
		}
	}
	return nil
}

// validateType 校验敏感数据类型（创建/编辑/导入共用；调用前已完成 trim 与默认值归一）。
func validateType(t *SensitiveDataType) error {
	if t.Name == "" || len(t.Name) > maxNameLen {
		return fmt.Errorf("name 必填且长度不能超过 %d", maxNameLen)
	}
	if !validLevel(t.Level) {
		return fmt.Errorf("无效的 level 取值（NON_SENSITIVE/GENERAL/SENSITIVE/IMPORTANT/CORE）")
	}
	if !validTypeStatus(t.Status) {
		return fmt.Errorf("无效的 status 取值（ENABLED/DISABLED）")
	}
	if t.DataType == "" || len(t.DataType) > maxDataTypeLen {
		return fmt.Errorf("data_type 必填且长度不能超过 %d（与网关证据标签对齐）", maxDataTypeLen)
	}
	if len(t.Category) > maxCategoryLen {
		return fmt.Errorf("category 长度不能超过 %d", maxCategoryLen)
	}
	if len(t.Description) > maxDescriptionLen {
		return fmt.Errorf("description 长度不能超过 %d", maxDescriptionLen)
	}
	if t.Regex != "" {
		if len(t.Regex) > maxRegexLen {
			return fmt.Errorf("regex 长度不能超过 %d", maxRegexLen)
		}
		if _, err := regexp.Compile(t.Regex); err != nil {
			return fmt.Errorf("regex 无法编译：%v", err)
		}
	}
	if t.Validator != "" && t.Validator != ValidatorLuhn {
		return fmt.Errorf("无效的 validator 取值（空或 luhn）")
	}
	if err := checkStrList("keywords", t.Keywords, nil); err != nil {
		return err
	}
	if err := checkStrList("locations", t.Locations, validLocations); err != nil {
		return err
	}
	return checkStrList("exclude_fields", t.ExcludeFields, nil)
}

// ParseMaskExclusions 解析并结构校验 exclusions_json：
// 必须是 JSON 对象（空串/nil/null 视为空对象）；键仅允许 identity/role/ip；
// 值为非空字符串数组（≤64 项、单项 ≤128 字符）；ip 项必须是合法 IP 或 CIDR。
func ParseMaskExclusions(raw json.RawMessage) (*MaskExclusions, error) {
	out := &MaskExclusions{}
	if len(raw) == 0 || string(raw) == "null" {
		return out, nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return nil, fmt.Errorf("exclusions_json 必须是对象且仅支持 identity/role/ip 键：%v", err)
	}
	for _, field := range []struct {
		name  string
		items []string
	}{{"identity", out.Identity}, {"role", out.Role}, {"ip", out.IP}} {
		if err := checkStrList("exclusions."+field.name, field.items, nil); err != nil {
			return nil, err
		}
	}
	for _, ip := range out.IP {
		if _, err := netip.ParseAddr(ip); err != nil {
			if _, perr := netip.ParsePrefix(ip); perr != nil {
				return nil, fmt.Errorf("exclusions.ip 项 %q 不是合法 IP 或 CIDR", ip)
			}
		}
	}
	return out, nil
}

// validateJSONObject 校验 JSON 为对象（params_json 用；空串/nil 归一为 {}）。
func validateJSONObject(field string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage(`{}`), nil
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("%s 必须是 JSON 对象", field)
	}
	if len(raw) > 8192 {
		return nil, fmt.Errorf("%s 长度不能超过 8192", field)
	}
	return raw, nil
}

// validateMaskingRule 校验脱敏规则（合并后的整体校验；与迁移 000040 的 CHECK 约束一致）。
func validateMaskingRule(r *MaskingRule) error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > maxNameLen {
		return fmt.Errorf("name 必填且长度不能超过 %d", maxNameLen)
	}
	if !validScope(r.Scope) {
		return fmt.Errorf("无效的 scope 取值（GLOBAL/APPLICATION/ENDPOINT）")
	}
	// 作用域一致性（与表 CHECK 约束同口径）
	switch r.Scope {
	case ScopeGlobal:
		if r.ApplicationID != nil || r.EndpointKey != nil {
			return errors.New("scope=GLOBAL 不允许设置 application_id/endpoint_key")
		}
	case ScopeApplication:
		if r.ApplicationID == nil {
			return errors.New("scope=APPLICATION 必须设置 application_id")
		}
		if r.EndpointKey != nil {
			return errors.New("scope=APPLICATION 不允许设置 endpoint_key")
		}
	case ScopeEndpoint:
		if r.EndpointKey == nil || strings.TrimSpace(*r.EndpointKey) == "" {
			return errors.New("scope=ENDPOINT 必须设置 endpoint_key")
		}
	}
	if r.EndpointKey != nil && len(*r.EndpointKey) > 560 {
		return fmt.Errorf("endpoint_key 长度不能超过 560")
	}
	if !validAlgorithm(r.Algorithm) {
		return fmt.Errorf("无效的 algorithm 取值（MASK/HASH/REMOVE）")
	}
	if len(r.FieldPath) > maxFieldPathLen {
		return fmt.Errorf("field_path 长度不能超过 %d", maxFieldPathLen)
	}
	if r.DataType != nil && (strings.TrimSpace(*r.DataType) == "" || len(*r.DataType) > maxDataTypeLen) {
		return fmt.Errorf("data_type 设置时不能为空且长度不能超过 %d", maxDataTypeLen)
	}
	if strings.TrimSpace(r.FieldPath) == "" && r.DataType == nil {
		return errors.New("field_path 与 data_type 至少设置其一")
	}
	if _, err := validateJSONObject("params_json", r.Params); err != nil {
		return err
	}
	_, err := ParseMaskExclusions(r.Exclusions)
	return err
}
