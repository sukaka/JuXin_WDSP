// Command rulepackverify 使用与管理后端完全一致的信任根、归档校验与静态安全门禁，
// 对离线 WAF 规则包（jiuzhang-wdsp-rulepack-YYYYMMDD.N.tar.gz）执行端到端自检。
// 供 ops/rulepack/build-rulepack.sh 发布前自检及交付前离线核验使用。
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/jiuzhang-waf/server/internal/rulepacks"
)

func main() {
	pkgPath := flag.String("package", "", "待校验的离线规则包 .tar.gz 路径（必填）")
	sysVer := flag.String("system-version", "", "用于测试 min_system_version 兼容性的当前系统版本（可选）")
	pubKeyFile := flag.String("pubkey", "", "可选：仅测试用外部 Ed25519 公钥 PEM 文件（缺省使用二进制内置生产公钥）")
	flag.Parse()

	if strings.TrimSpace(*pkgPath) == "" {
		fmt.Fprintln(os.Stderr, "error: --package is required")
		os.Exit(2)
	}

	var pub ed25519.PublicKey
	var err error
	if strings.TrimSpace(*pubKeyFile) != "" {
		pub, err = loadPublicKey(*pubKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: load pubkey: %v\n", err)
			os.Exit(1)
		}
	} else {
		pub, err = rulepacks.ReleasePublicKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: embedded release pubkey: %v\n", err)
			os.Exit(1)
		}
	}

	art, err := rulepacks.VerifyArchiveFileWithKey(*pkgPath, strings.TrimSpace(*sysVer), pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL archive/signature verify: %v\n", err)
		os.Exit(1)
	}

	tmpDir, err := os.MkdirTemp("", "rulepackverify-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := rulepacks.ExtractRulesToDir(*pkgPath, tmpDir); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL extract rules: %v\n", err)
		os.Exit(1)
	}
	staticRes, err := rulepacks.StaticGateCheckDir(tmpDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL static gate: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("OK rulepack=%s crs=%s files=%d confs=%d rules=%d cves=%d sha256=%s manifest_sha256=%s\n",
		art.Manifest.RulePackVersion,
		art.Manifest.CRSVersion,
		len(art.Manifest.Files),
		staticRes.CheckedConfFile,
		len(staticRes.Rules),
		len(staticRes.DetectedCVEs),
		art.FileSHA256,
		art.ManifestSHA256,
	)
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM file %s", path)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%s is not an Ed25519 public key", path)
	}
	return pub, nil
}
