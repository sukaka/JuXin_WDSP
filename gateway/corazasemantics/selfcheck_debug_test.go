package corazasemantics

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

func TestHarnessSelfCheck(t *testing.T) {
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
		"SecRuleEngine On\nSecRequestBodyAccess On\n"+detectRule))
	if err != nil {
		t.Fatalf("build waf: %v", err)
	}
	tx := waf.NewTransaction()
	defer tx.ProcessLogging()
	tx.ProcessConnection("10.1.2.3", 51234, "10.10.0.1", 8080)
	tx.ProcessURI("/api/orders", "POST", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.com")
	tx.SetServerName("example.com")
	tx.AddRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	tx.AddRequestHeader("Content-Length", "19")
	tx.ProcessRequestHeaders()
	it0, n, err := tx.WriteRequestBody([]byte("comment=' OR 1=1--"))
	t.Logf("write body it=%v n=%v err=%v", it0, n, err)
	it, err := tx.ProcessRequestBody()
	t.Logf("ProcessRequestBody interruption=%v err=%v", it, err)
	for _, mr := range tx.MatchedRules() {
		t.Logf("matched rule %d msg=%q tags=%v", mr.Rule().ID(), mr.Message(), mr.Rule().Tags())
	}
	_ = strings.TrimSpace("")
}
