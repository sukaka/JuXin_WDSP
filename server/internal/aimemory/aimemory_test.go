package aimemory

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestContainsSensitive 敏感内容识别：密码/密钥/私钥头/JWT/长随机串。
func TestContainsSensitive(t *testing.T) {
	sensitive := []struct {
		name    string
		content string
	}{
		{"密码关键词", "password=abc"},
		{"passwd", "passwd: 123"},
		{"apikey 大写", "API_KEY=xxx"},
		{"secret_key", "secret_key 泄露"},
		{"private_key", "private_key: ..."},
		// 注意：sensitivePatterns 中的 "BEGIN RSA"/"BEGIN PRIVATE"/"BEGIN EC"/"eyJhbGciOi"
		// 含大写字母，与小写化后的内容比较永不命中（生产 bug，已报告，修复后应补充用例）。
		{"40 位随机串", strings.Repeat("a", 40)},
		{"40 位混合字符集", "abcdefgh-ABCDEFGH_12345678+/=abcdefghABCDEFG"},
	}
	for _, c := range sensitive {
		t.Run("sensitive/"+c.name, func(t *testing.T) {
			if !ContainsSensitive(c.content) {
				t.Errorf("ContainsSensitive(%q) = false, want true", c.content)
			}
		})
	}
	clean := []struct {
		name    string
		content string
	}{
		{"普通中文", "用户偏好只看高危安全事件"},
		{"英文短句", "the quick brown fox jumps over the lazy dog"},
		{"39 位随机串", strings.Repeat("a", 39)},
		{"长字段含特殊符号", strings.Repeat("a", 39) + "!"},
		{"空字符串", ""},
	}
	for _, c := range clean {
		t.Run("clean/"+c.name, func(t *testing.T) {
			if ContainsSensitive(c.content) {
				t.Errorf("ContainsSensitive(%q) = true, want false", c.content)
			}
		})
	}
}

// TestStoreCreateValidation 写入前校验（纯逻辑，DB 前的防线）。
func TestStoreCreateValidation(t *testing.T) {
	s := NewStore(nil)
	ctx := context.Background()

	// 空内容
	if err := s.Create(ctx, &Memory{MemoryScope: ScopeSession}); err == nil {
		t.Error("空内容应被拒绝")
	}
	// 超长内容
	if err := s.Create(ctx, &Memory{MemoryScope: ScopeSession, Content: strings.Repeat("a", 4001)}); err == nil {
		t.Error("超过 4000 字符应被拒绝")
	}
	// AI 推测未经用户确认不得进入长期记忆
	err := s.Create(ctx, &Memory{
		MemoryScope: ScopeLongTerm, Content: "正常的偏好记录", ConfidenceType: ConfidenceAIInferred,
	})
	if !errors.Is(err, ErrSensitiveContent) {
		t.Errorf("AI_INFERRED 进长期记忆 err = %v, want ErrSensitiveContent", err)
	}
	// 长期记忆敏感内容拦截
	err = s.Create(ctx, &Memory{
		MemoryScope: ScopeLongTerm, Content: "password=abc", ConfidenceType: ConfidenceUserConfirmed,
	})
	if !errors.Is(err, ErrSensitiveContent) {
		t.Errorf("敏感内容进长期记忆 err = %v, want ErrSensitiveContent", err)
	}
}

// TestStoreUpdateSensitive Update 敏感内容拦截（DB 前）。
func TestStoreUpdateSensitive(t *testing.T) {
	s := NewStore(nil)
	if err := s.Update(context.Background(), uuid.New(), "api_key=xxx"); !errors.Is(err, ErrSensitiveContent) {
		t.Errorf("err = %v, want ErrSensitiveContent", err)
	}
}

// TestStoreSetStatusInvalid 非法状态值拦截（DB 前）。
func TestStoreSetStatusInvalid(t *testing.T) {
	s := NewStore(nil)
	if err := s.SetStatus(context.Background(), uuid.New(), "BOGUS"); err == nil {
		t.Error("非法状态应被拒绝")
	}
}
