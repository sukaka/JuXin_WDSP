package accessrules

import (
	"errors"
	"testing"
)

// TestValidateStatusTransition 状态机流转：DRAFT 草稿语义与非法流转拒绝。
func TestValidateStatusTransition(t *testing.T) {
	legal := []struct{ from, to string }{
		{StatusDraft, StatusActive},      // 草稿启用
		{StatusDisabled, StatusActive},   // 停用后启用
		{StatusActive, StatusActive},     // 幂等启用
		{StatusActive, StatusDisabled},   // 停用
		{StatusDisabled, StatusDisabled}, // 幂等停用
		{StatusExpired, StatusDisabled},  // 过期规则可停用
	}
	for _, c := range legal {
		if err := ValidateStatusTransition(c.from, c.to); err != nil {
			t.Errorf("%s → %s 应合法, 得到 %v", c.from, c.to, err)
		}
	}

	illegal := []struct{ from, to string }{
		{StatusDraft, StatusDisabled},   // 草稿未生效，无需停用
		{StatusExpired, StatusActive},   // 已过期需先延期
		{StatusDeleted, StatusActive},   // 已删除不可达（防御性断言）
		{StatusDeleted, StatusDisabled}, // 已删除不可达（防御性断言）
	}
	for _, c := range illegal {
		err := ValidateStatusTransition(c.from, c.to)
		if err == nil {
			t.Errorf("%s → %s 应拒绝", c.from, c.to)
			continue
		}
		if !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s → %s 错误应为 ErrInvalidState, 得到 %v", c.from, c.to, err)
		}
	}
}
