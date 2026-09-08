// auth.go 控制台口令哈希与校验（bcrypt；明文口令只存在于用户输入瞬间）。
package sysconsole

import "golang.org/x/crypto/bcrypt"

// HashPassword 生成 bcrypt 哈希（安装脚本与 passwd 命令共用）。
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPassword 校验口令是否匹配哈希。
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
