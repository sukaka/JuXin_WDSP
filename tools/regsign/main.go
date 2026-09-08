// regsign 安全回归报告离线签名小工具（WDSP P1-04 R3 §6.2）。
//
// 定位：签名侧属受控验证服务；本工具仅提供独立的最小签名/验签/规范化能力，
// 供验证服务或管理员在隔离环境使用。私钥经命令行参数指向的文件读入，
// 不进入仓库、报告或被测容器；公钥登记值由 genkey 输出，经管理配置
// （system_settings security_regression:trusted_verify_keys）登记。
//
// 确定字节编码口径与 server/internal/regression/canonical.go 严格一致：
// UTF-8、对象键字典序、紧凑无空白、不转义 HTML、数字保留原文、重复键拒绝。
// 签名以 manifest 原文字节为准；服务端核验要求「再编码 == 原文」，因此签名前
// 必须用 canonicalize 产物（或对已规范文件直接 sign，工具会校验规范形）。
//
// 用法：
//
//	regsign genkey -key-id verifier-2026-09 -out verifier.key
//	regsign canonicalize -in manifest.raw.json -out manifest.json
//	regsign sign -key verifier.key -key-id verifier-2026-09 -manifest manifest.json
//	regsign verify -pubkey <base64> -manifest manifest.json -signature <base64>
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = cmdGenkey(os.Args[2:])
	case "canonicalize":
		err = cmdCanonicalize(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `regsign - 安全回归报告离线签名工具（Ed25519，确定字节编码）

子命令：
  genkey        -key-id <id> -out <私钥文件>          生成密钥对（私钥 0600；stdout 输出公钥登记 JSON）
  canonicalize  -in <输入.json> -out <输出.json>      输出规范形（签名/导入必须使用规范形字节）
  sign          -key <私钥文件> -key-id <id> -manifest <文件>
  verify        -pubkey <base64> -manifest <文件> -signature <base64>
`)
}

// ---------- 规范形（与 server/internal/regression/canonical.go 同口径） ----------

// canonicalJSON 校验无重复键并返回规范形字节。
func canonicalJSON(data []byte) ([]byte, error) {
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing content after JSON document")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// rejectDuplicateKeys 流式遍历 token，任一对象内重复键即拒绝。
func rejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func(depth int) error
	walk = func(depth int) error {
		if depth > 200 {
			return fmt.Errorf("nesting too deep")
		}
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch d {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := kt.(string)
				if !ok {
					return fmt.Errorf("non-string object key")
				}
				if _, dup := seen[key]; dup {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		case '[':
			for dec.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			if _, err := dec.Token(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected delimiter %q", d)
		}
		return nil
	}
	if err := walk(0); err != nil {
		if err == io.EOF {
			return fmt.Errorf("empty document")
		}
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing content")
	}
	return nil
}

// ---------- 密钥文件 ----------

// loadPrivateKey 读取私钥文件（单行 base64 的 64 字节 Ed25519 私钥；权限必须
// 不大于 0600，防误把共享可读文件当私钥）。
func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private key file %s must not be readable by group/others (mode %o)", path, st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key file")
	}
	return ed25519.PrivateKey(key), nil
}

// ---------- 子命令 ----------

func cmdGenkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ContinueOnError)
	keyID := fs.String("key-id", "", "key_id（登记与签名引用名）")
	out := fs.String("out", "", "私钥输出文件（0600 创建，已存在则拒绝覆盖）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" || *out == "" {
		return fmt.Errorf("-key-id 与 -out 均必填")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private key file: %w", err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv) + "\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	enrollment := map[string]any{
		"key_id":     *keyID,
		"algorithm":  "ed25519",
		"public_key": base64.StdEncoding.EncodeToString(pub),
		"status":     "ACTIVE",
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	fmt.Fprintln(os.Stderr, "私钥已写入", *out, "（0600）；以下为公钥登记条目，请经管理配置 security_regression:trusted_verify_keys 登记：")
	return enc.Encode(enrollment)
}

func cmdCanonicalize(args []string) error {
	fs := flag.NewFlagSet("canonicalize", flag.ContinueOnError)
	in := fs.String("in", "", "输入 JSON 文件")
	out := fs.String("out", "", "输出规范形文件（缺省写 stdout）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in 必填")
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	canon, err := canonicalJSON(data)
	if err != nil {
		return err
	}
	if *out == "" {
		_, err := os.Stdout.Write(append(canon, '\n'))
		return err
	}
	// 文件写精确规范形字节（不带尾换行——服务端按「再编码 == 原文」逐字节核对）
	return os.WriteFile(*out, canon, 0o644)
}

func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "私钥文件")
	keyID := fs.String("key-id", "", "key_id")
	manifest := fs.String("manifest", "", "manifest 文件（必须为规范形字节）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *keyID == "" || *manifest == "" {
		return fmt.Errorf("-key、-key-id、-manifest 均必填")
	}
	priv, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	canon, err := canonicalJSON(data)
	if err != nil {
		return err
	}
	if !bytes.Equal(canon, data) {
		return fmt.Errorf("manifest 不是规范形字节（请先 canonicalize；服务端将拒绝验签）")
	}
	sig := ed25519.Sign(priv, data)
	envelope := map[string]string{
		"algorithm": "ed25519",
		"key_id":    *keyID,
		"signature": base64.StdEncoding.EncodeToString(sig),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	pubB64 := fs.String("pubkey", "", "公钥 base64")
	manifest := fs.String("manifest", "", "manifest 文件")
	sigB64 := fs.String("signature", "", "签名 base64")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key")
	}
	sig, err := base64.StdEncoding.DecodeString(*sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature")
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	if canon, err := canonicalJSON(data); err != nil || !bytes.Equal(canon, data) {
		return fmt.Errorf("manifest 不是规范形字节")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
		return fmt.Errorf("signature verification FAILED")
	}
	fmt.Fprintln(os.Stdout, "OK")
	return nil
}
