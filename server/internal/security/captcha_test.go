package security

import (
	"bytes"
	"image/png"
	"strings"
	"testing"
)

// TestRandomCodeAndRandInt 验证码随机源回归：randInt/randomCode 如实返回错误，
// 正常路径必须落在字符集与取值范围内（配合 LOW-S6 错误传播改造）。
func TestRandomCodeAndRandInt(t *testing.T) {
	code, err := randomCode(6)
	if err != nil {
		t.Fatalf("randomCode: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("code length=%d, want 6", len(code))
	}
	for _, ch := range code {
		if !strings.ContainsRune(captchaCharset, ch) {
			t.Fatalf("code %q contains char %q outside captcha charset", code, ch)
		}
	}
	for i := 0; i < 100; i++ {
		v, err := randInt(7)
		if err != nil {
			t.Fatalf("randInt: %v", err)
		}
		if v < 0 || v >= 7 {
			t.Fatalf("randInt(7)=%d out of range", v)
		}
	}
}

// TestRenderPNG 验证码图片生成回归：输出必须是可解码的 PNG。
func TestRenderPNG(t *testing.T) {
	img, err := renderPNG("AB23")
	if err != nil {
		t.Fatalf("renderPNG: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(img)); err != nil {
		t.Fatalf("renderPNG output not a valid png: %v", err)
	}
}
