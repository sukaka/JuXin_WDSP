package users

import (
	"errors"
	"strings"
)

// 保留用户名（禁止使用）
var reservedUsernames = map[string]bool{
	"root": true, "system": true, "anonymous": true,
	"null": true, "undefined": true,
}

// validateUsername 校验用户名规则。
func validateUsername(username string) error {
	if len(username) < 4 || len(username) > 64 {
		return errors.New("用户名长度须为4至64位")
	}
	for _, c := range username {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-'
		if !ok {
			return errors.New("用户名仅允许字母、数字、下划线和短横线")
		}
	}
	if reservedUsernames[strings.ToLower(username)] {
		return errors.New("该用户名为系统保留名称")
	}
	return nil
}
