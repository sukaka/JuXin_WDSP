package guardconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type failingFileComplianceLister struct{ err error }

func (f failingFileComplianceLister) ListEnabledFileComplianceRules(context.Context) ([]gatewayconfig.GuardFileComplianceRule, error) {
	return nil, f.err
}

func TestIsMissingLegacyTableErrorOnlyAcceptsMissingTable(t *testing.T) {
	if !isMissingLegacyTableError(errors.New(`ERROR: relation "api_file_compliance_rules" does not exist`), "api_file_compliance_rules") {
		t.Fatal("missing legacy table error should be tolerated")
	}
	for _, err := range []error{
		errors.New("database connection reset"),
		errors.New(`ERROR: relation "other_table" does not exist`),
	} {
		if isMissingLegacyTableError(err, "api_file_compliance_rules") {
			t.Fatalf("error %q must not be treated as missing legacy table", err)
		}
	}
}

func TestLoadAPIFileComplianceRulesStrictPropagatesRealQueryError(t *testing.T) {
	want := errors.New("database connection reset")
	p := &Provider{fileComplianceRules: failingFileComplianceLister{err: want}}
	_, err := p.loadAPIFileComplianceRulesStrict(context.Background())
	if err == nil || !strings.Contains(err.Error(), want.Error()) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}
