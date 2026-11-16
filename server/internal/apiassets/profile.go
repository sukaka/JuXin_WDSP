package apiassets

import (
	"fmt"
	"strings"
)

// AssetProfile api_assets 可编辑档案（Update 全量替换语义）。
// Owner 即界面「系统负责人」；数据等级/API 等级/认证方式枚举在应用层校验。
type AssetProfile struct {
	Purpose        string
	Exposure       string
	Owner          string
	Tags           []string
	BusinessType   string
	Organization   string
	BusinessSystem string
	TechnicalOwner string
	DataOwner      string
	DataLevel      string
	APILevel       string
	AuthType       string
}

// 数据等级：核心数据/重要数据/一般数据；UNKNOWN=未标注。
var validDataLevels = map[string]bool{"UNKNOWN": true, "CORE": true, "IMPORTANT": true, "GENERAL": true}

// API 等级：一级/二级/三级；UNKNOWN=未标注。
var validAPILevels = map[string]bool{"UNKNOWN": true, "LEVEL_1": true, "LEVEL_2": true, "LEVEL_3": true}

// 认证方式：空串=未标注（UNKNOWN 入参归一为空串）。
var validAuthTypes = map[string]bool{
	"": true, "NONE": true, "BASIC": true, "API_KEY": true, "TOKEN": true,
	"JWT": true, "OAUTH2": true, "MTLS": true, "SESSION": true, "OTHER": true,
}

// normalizeAssetProfile 归一大小写/缺省值并校验枚举；两存储实现共用。
func normalizeAssetProfile(p AssetProfile) (AssetProfile, error) {
	p.Exposure = strings.ToUpper(strings.TrimSpace(p.Exposure))
	if p.Exposure == "" {
		p.Exposure = "INTERNAL"
	}
	p.BusinessType = NormalizeBusinessType(p.BusinessType)
	if !validBusinessTypes[p.BusinessType] {
		return p, fmt.Errorf("无效的业务类型：%s", p.BusinessType)
	}
	p.DataLevel = strings.ToUpper(strings.TrimSpace(p.DataLevel))
	if p.DataLevel == "" {
		p.DataLevel = "UNKNOWN"
	}
	if !validDataLevels[p.DataLevel] {
		return p, fmt.Errorf("无效的数据等级：%s", p.DataLevel)
	}
	p.APILevel = strings.ToUpper(strings.TrimSpace(p.APILevel))
	if p.APILevel == "" {
		p.APILevel = "UNKNOWN"
	}
	if !validAPILevels[p.APILevel] {
		return p, fmt.Errorf("无效的 API 等级：%s", p.APILevel)
	}
	p.AuthType = strings.ToUpper(strings.TrimSpace(p.AuthType))
	if p.AuthType == "UNKNOWN" {
		p.AuthType = ""
	}
	if !validAuthTypes[p.AuthType] {
		return p, fmt.Errorf("无效的认证方式：%s", p.AuthType)
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}
	return p, nil
}
