package httpsensor

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

func TestProcessBodyDecompressionTruncation(t *testing.T) {
	const maxBodySize = 8
	plain := []byte(`{"payload":"long"}`)

	tests := []struct {
		name     string
		encoding string
		compress func([]byte) []byte
	}{
		{name: "gzip", encoding: "gzip", compress: gzipBytes},
		{name: "deflate", encoding: "deflate", compress: zlibBytes},
	}
	for _, tc := range tests {
		t.Run(tc.name+" over limit", func(t *testing.T) {
			res := processBody(tc.compress(plain), int64(len(plain)), false, map[string]string{
				"content-type":     "application/json",
				"content-encoding": tc.encoding,
			}, &Policy{Level: config.LevelL2, MaxBodySize: maxBodySize}, nil)

			if !res.truncated {
				t.Fatalf("解压输出超限后应标记 truncated: %+v", res)
			}
			if len(res.body) != maxBodySize {
				t.Fatalf("解压输出驻留内存超限: got %d, want %d", len(res.body), maxBodySize)
			}
		})

		t.Run(tc.name+" within limit", func(t *testing.T) {
			res := processBody(tc.compress(plain), int64(len(plain)), false, map[string]string{
				"content-type":     "application/json",
				"content-encoding": tc.encoding,
			}, &Policy{Level: config.LevelL2, MaxBodySize: len(plain)}, nil)

			if res.truncated {
				t.Fatalf("解压输出未超限不应标记 truncated: %+v", res)
			}
			if res.body != string(plain) {
				t.Fatalf("解压内容错误: got %q, want %q", res.body, plain)
			}
		})
	}
}

func TestProcessBodyPreservesCaptureTruncationAfterDecompression(t *testing.T) {
	plain := []byte(`{"ok":true}`)
	res := processBody(gzipBytes(plain), int64(len(plain)), true, map[string]string{
		"content-type":     "application/json",
		"content-encoding": "gzip",
	}, &Policy{Level: config.LevelL2, MaxBodySize: len(plain)}, nil)

	if !res.truncated {
		t.Fatalf("原始抓包已截断时不应被解压路径清除: %+v", res)
	}
	if res.body != string(plain) {
		t.Fatalf("解压内容错误: got %q, want %q", res.body, plain)
	}
}

func gzipBytes(in []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	_, _ = w.Write(in)
	_ = w.Close()
	return out.Bytes()
}

func zlibBytes(in []byte) []byte {
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	_, _ = w.Write(in)
	_ = w.Close()
	return out.Bytes()
}

func TestMaskingSecurityRegressions(t *testing.T) {
	def := config.DefaultMasking()

	t.Run("recursive JSON objects and arrays masked", func(t *testing.T) {
		body := `[{"user":"alice","auth":{"password":"p1","tokens":[{"token":"t1"}]}}]`
		got, n := maskBodyParams(body, "application/json", def.Params)
		if n != 2 || got == body {
			t.Fatalf("expected 2 masked fields, got n=%d body=%s", n, got)
		}
		if bytes.Contains([]byte(got), []byte("p1")) || bytes.Contains([]byte(got), []byte("t1")) {
			t.Fatalf("leaked plaintext secret in nested JSON/array: %s", got)
		}
	})

	t.Run("truncated unparseable JSON fail-closed redacted", func(t *testing.T) {
		body := `{"user":"alice","password":"super-secret-truncated`
		got, n := maskBodyParams(body, "application/json", def.Params)
		if n < 1 || bytes.Contains([]byte(got), []byte("super-secret")) {
			t.Fatalf("truncated JSON leaked plaintext: n=%d got=%q", n, got)
		}
	})

	t.Run("text/json and application/*+json masked", func(t *testing.T) {
		for _, mt := range []string{"text/json", "application/problem+json", "application/vnd.api+json"} {
			got, n := maskBodyParams(`{"nested":{"api_key":"k-secret"}}`, mt, def.Params)
			if n != 1 || bytes.Contains([]byte(got), []byte("k-secret")) {
				t.Fatalf("mediaType %s failed masking: n=%d got=%q", mt, n, got)
			}
		}
	})

	t.Run("application/graphql JSON and raw query masked", func(t *testing.T) {
		got1, n1 := maskBodyParams(`{"query":"mutation { login(password: \"gql-pass\") }","variables":{"token":"gql-tok"}}`, "application/graphql", def.Params)
		if n1 < 2 || bytes.Contains([]byte(got1), []byte("gql-pass")) || bytes.Contains([]byte(got1), []byte("gql-tok")) {
			t.Fatalf("graphql JSON leaked: n=%d got=%q", n1, got1)
		}
		got2, n2 := maskBodyParams(`mutation { login(user: "a", password: "raw-gql-secret") { id } }`, "application/graphql", def.Params)
		if n2 < 1 || bytes.Contains([]byte(got2), []byte("raw-gql-secret")) {
			t.Fatalf("raw graphql leaked: n=%d got=%q", n2, got2)
		}
	})

	t.Run("application/xml elements attributes and truncated tag masked", func(t *testing.T) {
		xmlBody := `<req api_key="attr-sec"><ns:password>elem-sec</ns:password><user>bob</user></req>`
		got, n := maskBodyParams(xmlBody, "application/xml", def.Params)
		if n != 2 || bytes.Contains([]byte(got), []byte("attr-sec")) || bytes.Contains([]byte(got), []byte("elem-sec")) {
			t.Fatalf("xml masking failed: n=%d got=%q", n, got)
		}
		truncXML := `<req><password>trunc-xml-secret`
		got2, n2 := maskBodyParams(truncXML, "application/xml", def.Params)
		if n2 < 1 || bytes.Contains([]byte(got2), []byte("trunc-xml-secret")) {
			t.Fatalf("truncated xml leaked: n=%d got=%q", n2, got2)
		}
	})

	t.Run("text/plain form kv and embedded JSON masked", func(t *testing.T) {
		got1, n1 := maskBodyParams("user=alice&password=plain-pass&%74oken=enc-tok", "text/plain", def.Params)
		if n1 != 2 || bytes.Contains([]byte(got1), []byte("plain-pass")) || bytes.Contains([]byte(got1), []byte("enc-tok")) {
			t.Fatalf("text/plain kv failed: n=%d got=%q", n1, got1)
		}
		got2, n2 := maskBodyParams("password: line-secret\nuser: bob", "text/plain", def.Params)
		if n2 != 1 || bytes.Contains([]byte(got2), []byte("line-secret")) {
			t.Fatalf("text/plain colon failed: n=%d got=%q", n2, got2)
		}
		got3, n3 := maskBodyParams(`{"secret":"json-in-plain"}`, "text/plain", def.Params)
		if n3 != 1 || bytes.Contains([]byte(got3), []byte("json-in-plain")) {
			t.Fatalf("text/plain JSON failed: n=%d got=%q", n3, got3)
		}
	})

	t.Run("URL-encoded query param names decoded before matching", func(t *testing.T) {
		got, n := MaskURI("/login?%70assword=s1&%74%6f%6b%65%6e=s2&ok=1", def.Params)
		if n != 2 || bytes.Contains([]byte(got), []byte("s1")) || bytes.Contains([]byte(got), []byte("s2")) {
			t.Fatalf("encoded query param not masked: n=%d got=%q", n, got)
		}
	})

	t.Run("multipart MaskModeDrop omits key completely", func(t *testing.T) {
		mp := "--B\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nsecret\r\n" +
			"--B\r\nContent-Disposition: form-data; name=\"user\"\r\n\r\nalice\r\n--B--\r\n"
		dropRule := config.MaskRule{Mode: config.MaskModeDrop, Names: []string{"password"}}
		var m int
		got, err := multipartSummary([]byte(mp), "multipart/form-data; boundary=B", dropRule, &m)
		if err != nil {
			t.Fatal(err)
		}
		if m != 1 || bytes.Contains([]byte(got), []byte(`"password"`)) || !bytes.Contains([]byte(got), []byte(`"user":"alice"`)) {
			t.Fatalf("MaskModeDrop must omit key from multipart summary: m=%d got=%s", m, got)
		}
	})

	t.Run("nil policy in MaskedRequestMessage and MaskedResponseMessage uses DefaultMasking", func(t *testing.T) {
		reqMsg := MaskedRequestMessage(MaskedRequestInput{
			Method:  "GET",
			Host:    "api.example.com",
			URI:     "/login?password=secret",
			Headers: map[string]string{"authorization": "Bearer secret"},
		}, nil, nil)
		if reqMsg.Headers["authorization"] != maskValue || bytes.Contains([]byte(reqMsg.URI), []byte("secret")) {
			t.Fatalf("nil policy failed to apply default masking on request: %+v", reqMsg)
		}
		respMsg := MaskedResponseMessage(MaskedResponseInput{
			Status:  200,
			Headers: map[string]string{"set-cookie": "sid=secret"},
		}, nil, nil)
		if respMsg.Headers["set-cookie"] != maskValue {
			t.Fatalf("nil policy failed to apply default masking on response: %+v", respMsg)
		}
	})

	t.Run("processBody strips NUL bytes", func(t *testing.T) {
		res := processBody([]byte("hello\x00world"), 11, false, map[string]string{
			"content-type": "text/plain",
		}, &Policy{Level: config.LevelL2, MaxBodySize: 1024, Masking: def}, nil)
		if bytes.Contains([]byte(res.body), []byte{0}) || res.body != "helloworld" {
			t.Fatalf("expected NUL bytes stripped, got %q", res.body)
		}
	})
}
