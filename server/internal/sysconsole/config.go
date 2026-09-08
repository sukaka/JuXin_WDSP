// config.go 运维控制台配置（/etc/jiuzhang/console.yaml，0600 root 拥有）。
// 格式为极简「key: value」行（bcrypt 哈希不含冒号），有意不引入完整 YAML 依赖。
package sysconsole

import (
	"fmt"
	"os"
	"strings"
)

// Config 控制台配置。
type Config struct {
	Username     string // 控制台账号
	PasswordHash string // bcrypt 哈希（不落明文口令）
}

// LoadConfig 读取配置文件；文件不存在或键缺失返回错误（由入口转为安装引导提示）。
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	for line := range strings.Lines(string(raw)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "username":
			c.Username = strings.TrimSpace(v)
		case "password_hash":
			c.PasswordHash = strings.TrimSpace(v)
		}
	}
	if c.Username == "" || c.PasswordHash == "" {
		return nil, fmt.Errorf("配置缺少 username/password_hash：%s", path)
	}
	return c, nil
}

// SaveConfig 写回配置（保留 0600；供 passwd 命令更新哈希）。
func SaveConfig(path string, c *Config) error {
	body := fmt.Sprintf("# 九章运维控制台账号（由 install-console.sh / passwd 命令维护，勿手改）\nusername: %s\npassword_hash: %s\n",
		c.Username, c.PasswordHash)
	return os.WriteFile(path, []byte(body), 0o600)
}
