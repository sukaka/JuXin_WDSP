// fingerprint.go 宿主机指纹材料读取：安装期由 ops/lib/fingerprint.sh 在宿主机
// 采集并写入 runtime/license/host_fingerprint（chmod 600），compose 只读挂载进
// 容器；产品侧启动与周期复核时读取，与授权绑定指纹精确比对。
package license

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// 宿主机指纹文件路径（env LICENSE_HOST_FINGERPRINT_FILE 覆盖默认值）。
const (
	// HostFingerprintFileEnv 指纹文件路径覆盖环境变量。
	HostFingerprintFileEnv = "LICENSE_HOST_FINGERPRINT_FILE"
	// DefaultHostFingerprintFile 容器内默认挂载路径。
	DefaultHostFingerprintFile = "/app/runtime/license/host_fingerprint"
)

// ErrNoFingerprintMaterial 宿主机指纹材料缺失（文件不存在或内容为空）。
// 绑定指纹的授权在此状态下一律校验不通过（如实报错，不做任何绕过）。
var ErrNoFingerprintMaterial = errors.New("宿主机指纹材料缺失")

// HostFingerprintFile 解析指纹文件路径：env 优先，缺省 /app/runtime/license/host_fingerprint。
func HostFingerprintFile() string {
	if v := strings.TrimSpace(os.Getenv(HostFingerprintFileEnv)); v != "" {
		return v
	}
	return DefaultHostFingerprintFile
}

// ReadHostFingerprint 读取宿主机指纹（去首尾空白）。
// 文件缺失/内容为空 → ErrNoFingerprintMaterial；其他读取错误如实包装返回。
func ReadHostFingerprint(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", ErrNoFingerprintMaterial
		}
		return "", fmt.Errorf("读取宿主机指纹文件失败: %w", err)
	}
	fp := strings.TrimSpace(string(data))
	if fp == "" {
		return "", ErrNoFingerprintMaterial
	}
	return fp, nil
}
