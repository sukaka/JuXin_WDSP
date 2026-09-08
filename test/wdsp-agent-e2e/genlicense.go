// genlicense.go 生成 WDSP Agent E2E 验收用的临时离线授权（.lic）与
// wdsp_testkeys 测试构建使用的验签公钥环境行。
//
// 仅用于 test/wdsp-agent-e2e 本地验收：随机生成一次性 Ed25519 密钥对，
// 私钥随进程退出销毁，不落盘、不进入任何生产路径。
// 授权参数对齐 server/tests/license_helper_test.go 的公共测试授权：
// product=wdsp（门控不拒绝任何能力域）、永久有效、配额全 0（不限制）、不绑定机器指纹。
//
// 用法：go run genlicense.go -lic-out <path> -env-out <path> [-key-id <id>]
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	licOut := flag.String("lic-out", "", ".lic 文件输出路径（必填）")
	envOut := flag.String("env-out", "", "验签公钥 env 行输出路径（必填）")
	keyID := flag.String("key-id", "e2e-license-key", "payload key_id")
	flag.Parse()
	if *licOut == "" || *envOut == "" {
		fmt.Fprintln(os.Stderr, "需要 -lic-out 与 -env-out")
		os.Exit(2)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}

	// 签名输入 = json.Marshal(payload map)（Go map 键字典序紧凑序列化），
	// 与产品侧验签重构字节逐字节一致（口径来源：server/tests/license_helper_test.go）。
	payload := map[string]interface{}{
		"license_id":          "LIC-E2E-" + time.Now().UTC().Format("20060102150405"),
		"license_type":        "FORMAL",
		"product":             "wdsp",
		"customer":            "WDSP Agent E2E 本地验收",
		"issued_at":           time.Now().UTC().Format(time.RFC3339),
		"expires_at":          nil,
		"perpetual":           true,
		"machine_fingerprint": nil,
		"quotas": map[string]int64{
			"max_applications":  0,
			"max_api_endpoints": 0,
			"max_qps":           0,
		},
		"features": []string{"api", "waf"},
		"version":  1,
		"key_id":   *keyID,
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		fatal(err)
	}
	sig := ed25519.Sign(priv, canonical)
	file, err := json.Marshal(map[string]interface{}{
		"payload":   json.RawMessage(canonical),
		"signature": hex.EncodeToString(sig),
	})
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*licOut, file, 0o600); err != nil {
		fatal(err)
	}
	envLine := fmt.Sprintf("LICENSE_VENDOR_PUBLIC_KEY=%s:%s\n", *keyID, hex.EncodeToString(pub))
	if err := os.WriteFile(*envOut, []byte(envLine), 0o600); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "genlicense:", err)
	os.Exit(1)
}
