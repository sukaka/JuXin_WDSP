package tests

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func stringReader(s string) io.Reader {
	return strings.NewReader(s)
}

func readJSON(t *testing.T, resp *http.Response, dst interface{}) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatalf("unmarshal json: %v (body: %s)", err, string(body))
	}
}

func readBodyString(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}
