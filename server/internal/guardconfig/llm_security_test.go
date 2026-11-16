package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeLLMSecurityPolicyLister struct {
	policies []gatewayconfig.GuardLLMSecurityPolicy
	err      error
}

func (f fakeLLMSecurityPolicyLister) ListEnabledSecurityPolicies(context.Context) ([]gatewayconfig.GuardLLMSecurityPolicy, error) {
	return f.policies, f.err
}

func TestLoadLLMSecurityPolicies(t *testing.T) {
	expected := []gatewayconfig.GuardLLMSecurityPolicy{{ID: "policy-1", ApplicationID: "app-1", Version: 2, Mode: "OBSERVE"}}
	p := &Provider{llmSecurityPolicies: fakeLLMSecurityPolicyLister{policies: expected}}
	got, err := p.loadLLMSecurityPolicies(context.Background())
	if err != nil || len(got) != 1 || got[0].Version != 2 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	p.llmSecurityPolicies = nil
	got, err = p.loadLLMSecurityPolicies(context.Background())
	if err != nil || got != nil {
		t.Fatalf("nil lister got=%+v err=%v", got, err)
	}
}

func TestLoadLLMSecurityPoliciesFailure(t *testing.T) {
	p := &Provider{llmSecurityPolicies: fakeLLMSecurityPolicyLister{err: errors.New("query failed")}}
	if _, err := p.loadLLMSecurityPolicies(context.Background()); err == nil {
		t.Fatal("query failure must fail the candidate publish")
	}
}
