package response

import "testing"

func TestExtractErrorSignatures(t *testing.T) {
	// 5xx 状态签名
	sigs := ExtractErrorSignatures(500, nil)
	if len(sigs) != 1 || sigs[0] != "http_5xx" {
		t.Fatalf("5xx: %v", sigs)
	}
	// 4xx 无状态签名
	if sigs := ExtractErrorSignatures(404, nil); len(sigs) != 0 {
		t.Fatalf("4xx: %v", sigs)
	}
	// 堆栈/数据库特征
	body := []byte(`{"error":"java.lang.NullPointerException\n\tat com.example.App.run(App.java:42)"}`)
	sigs = ExtractErrorSignatures(500, body)
	found := map[string]bool{}
	for _, s := range sigs {
		found[s] = true
	}
	if !found["http_5xx"] || !found["stack.java_trace"] {
		t.Fatalf("java trace: %v", sigs)
	}
	sigs = ExtractErrorSignatures(200, []byte("Traceback (most recent call last):\n  File \"x.py\""))
	if len(sigs) != 1 || sigs[0] != "stack.python_traceback" {
		t.Fatalf("python: %v", sigs)
	}
	sigs = ExtractErrorSignatures(502, []byte("panic: runtime error: index out of range"))
	if len(sigs) != 2 || sigs[0] != "http_5xx" || sigs[1] != "stack.go_panic" {
		t.Fatalf("go panic: %v", sigs)
	}
	sigs = ExtractErrorSignatures(500, []byte(`{"detail":"SQLSTATE 42P01: relation does not exist"}`))
	if !containsSig(sigs, "db.sqlstate") {
		t.Fatalf("sqlstate: %v", sigs)
	}
	// 干净响应无签名
	if sigs := ExtractErrorSignatures(200, []byte(`{"ok":true}`)); len(sigs) != 0 {
		t.Fatalf("clean: %v", sigs)
	}
}

func containsSig(sigs []string, s string) bool {
	for _, x := range sigs {
		if x == s {
			return true
		}
	}
	return false
}
