package security

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math/big"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/cache"
)

// 验证码错误
var (
	ErrCaptchaNotFound = errors.New("captcha not found or expired")
	ErrCaptchaMismatch = errors.New("captcha code mismatch")
	ErrCaptchaDisabled = errors.New("captcha disabled")
)

const captchaKeyPrefix = "jiuzhang:captcha:"

// 验证码字符集（去除易混淆字符 0/O、1/I/l）
const captchaCharset = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// CaptchaService 提供图形验证码生成与校验。
type CaptchaService struct {
	cache *cache.Client
}

// NewCaptchaService 创建验证码服务。
func NewCaptchaService(c *cache.Client) *CaptchaService {
	return &CaptchaService{cache: c}
}

// Captcha 是生成的验证码结果。
type Captcha struct {
	ID        string `json:"captcha_id"`
	Image     string `json:"image"` // data:image/png;base64,...
	ExpiresIn int    `json:"expires_in"`
}

// Generate 生成验证码：随机字符 + PNG 图片，答案存 Valkey（短期 TTL）。
func (s *CaptchaService) Generate(ctx context.Context, codeLen int, expireSeconds int) (*Captcha, error) {
	if codeLen <= 0 {
		codeLen = 4
	}
	if expireSeconds <= 0 {
		expireSeconds = 120
	}
	code, err := randomCode(codeLen)
	if err != nil {
		return nil, err
	}
	id, err := NewRandomToken(16)
	if err != nil {
		return nil, err
	}
	img, err := renderPNG(code)
	if err != nil {
		return nil, err
	}
	key := captchaKeyPrefix + id
	if err := s.cache.Set(ctx, key, code, time.Duration(expireSeconds)*time.Second); err != nil {
		return nil, fmt.Errorf("store captcha: %w", err)
	}
	return &Captcha{
		ID:        id,
		Image:     "data:image/png;base64," + base64.StdEncoding.EncodeToString(img),
		ExpiresIn: expireSeconds,
	}, nil
}

// Verify 校验验证码。一次性使用：校验后立即失效。
// caseSensitive 控制是否区分大小写。
func (s *CaptchaService) Verify(ctx context.Context, id, code string, caseSensitive bool) error {
	if id == "" || code == "" {
		return ErrCaptchaMismatch
	}
	key := captchaKeyPrefix + id
	stored, err := s.cache.Get(ctx, key)
	if err != nil {
		return ErrCaptchaNotFound
	}
	// 一次性使用：无论对错立即删除
	_ = s.cache.Del(ctx, key)
	if caseSensitive {
		if stored != code {
			return ErrCaptchaMismatch
		}
	} else {
		if !strings.EqualFold(stored, code) {
			return ErrCaptchaMismatch
		}
	}
	return nil
}

func randomCode(n int) (string, error) {
	buf := make([]byte, n)
	max := big.NewInt(int64(len(captchaCharset)))
	for i := range buf {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		buf[i] = captchaCharset[v.Int64()]
	}
	return string(buf), nil
}

// renderPNG 绘制带干扰线的验证码图片（无第三方依赖）。
func renderPNG(code string) ([]byte, error) {
	const (
		width  = 140
		height = 44
	)
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// 背景
	bg := color.RGBA{245, 247, 250, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bg}, image.Point{}, draw.Src)

	// 干扰线
	for i := 0; i < 6; i++ {
		c := randomColor()
		x1 := randInt(width)
		y1 := randInt(height)
		x2 := randInt(width)
		y2 := randInt(height)
		drawLine(img, x1, y1, x2, y2, c)
	}
	// 干扰点
	for i := 0; i < 80; i++ {
		img.Set(randInt(width), randInt(height), randomColor())
	}

	// 字符（逐字符绘制，简易点阵字体，随机偏移与颜色）
	cellW := width / (len(code) + 1)
	for i, ch := range code {
		x := cellW*(i+1) - 6 + randInt(4) - 2
		y := 10 + randInt(6) - 3
		drawChar(img, byte(ch), x, y, randomDarkColor())
	}

	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func randInt(max int) int {
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(v.Int64())
}

func randomColor() color.RGBA {
	return color.RGBA{
		uint8(120 + randInt(135)),
		uint8(120 + randInt(135)),
		uint8(120 + randInt(135)),
		255,
	}
}

func randomDarkColor() color.RGBA {
	return color.RGBA{
		uint8(30 + randInt(90)),
		uint8(30 + randInt(90)),
		uint8(60 + randInt(100)),
		255,
	}
}

func drawLine(img *image.RGBA, x1, y1, x2, y2 int, c color.RGBA) {
	dx := abs(x2 - x1)
	dy := abs(y2 - y1)
	steps := dx
	if dy > steps {
		steps = dy
	}
	if steps == 0 {
		img.Set(x1, y1, c)
		return
	}
	for i := 0; i <= steps; i++ {
		x := x1 + (x2-x1)*i/steps
		y := y1 + (y2-y1)*i/steps
		if image.Pt(x, y).In(img.Bounds()) {
			img.Set(x, y, c)
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// 5x7 点阵字体（覆盖数字与大写字母，每个字符 5 列 7 行，1 表示填充）
var font5x7 = map[byte][7]string{
	'2': {"01110", "10001", "00001", "00010", "00100", "01000", "11111"},
	'3': {"11110", "00001", "00001", "01110", "00001", "00001", "11110"},
	'4': {"00010", "00110", "01010", "10010", "11111", "00010", "00010"},
	'5': {"11111", "10000", "11110", "00001", "00001", "10001", "01110"},
	'6': {"00110", "01000", "10000", "11110", "10001", "10001", "01110"},
	'7': {"11111", "00001", "00010", "00100", "01000", "01000", "01000"},
	'8': {"01110", "10001", "10001", "01110", "10001", "10001", "01110"},
	'9': {"01110", "10001", "10001", "01111", "00001", "00010", "01100"},
	'A': {"01110", "10001", "10001", "11111", "10001", "10001", "10001"},
	'B': {"11110", "10001", "10001", "11110", "10001", "10001", "11110"},
	'C': {"01110", "10001", "10000", "10000", "10000", "10001", "01110"},
	'D': {"11100", "10010", "10001", "10001", "10001", "10010", "11100"},
	'E': {"11111", "10000", "10000", "11110", "10000", "10000", "11111"},
	'F': {"11111", "10000", "10000", "11110", "10000", "10000", "10000"},
	'G': {"01110", "10001", "10000", "10111", "10001", "10001", "01111"},
	'H': {"10001", "10001", "10001", "11111", "10001", "10001", "10001"},
	'J': {"00111", "00010", "00010", "00010", "00010", "10010", "01100"},
	'K': {"10001", "10010", "10100", "11000", "10100", "10010", "10001"},
	'L': {"10000", "10000", "10000", "10000", "10000", "10000", "11111"},
	'M': {"10001", "11011", "10101", "10101", "10001", "10001", "10001"},
	'N': {"10001", "11001", "10101", "10011", "10001", "10001", "10001"},
	'P': {"11110", "10001", "10001", "11110", "10000", "10000", "10000"},
	'Q': {"01110", "10001", "10001", "10001", "10101", "10010", "01101"},
	'R': {"11110", "10001", "10001", "11110", "10100", "10010", "10001"},
	'S': {"01111", "10000", "10000", "01110", "00001", "00001", "11110"},
	'T': {"11111", "00100", "00100", "00100", "00100", "00100", "00100"},
	'U': {"10001", "10001", "10001", "10001", "10001", "10001", "01110"},
	'V': {"10001", "10001", "10001", "10001", "10001", "01010", "00100"},
	'W': {"10001", "10001", "10001", "10101", "10101", "10101", "01010"},
	'X': {"10001", "10001", "01010", "00100", "01010", "10001", "10001"},
	'Y': {"10001", "10001", "01010", "00100", "00100", "00100", "00100"},
	'Z': {"11111", "00001", "00010", "00100", "01000", "10000", "11111"},
}

func drawChar(img *image.RGBA, ch byte, x, y int, c color.RGBA) {
	glyph, ok := font5x7[ch]
	if !ok {
		return
	}
	const scale = 3
	for row, line := range glyph {
		for col, px := range line {
			if px == '1' {
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						pxx := x + col*scale + dx
						pyy := y + row*scale + dy
						if image.Pt(pxx, pyy).In(img.Bounds()) {
							img.Set(pxx, pyy, c)
						}
					}
				}
			}
		}
	}
}
