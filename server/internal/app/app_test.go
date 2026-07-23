package app

import (
	"testing"

	"github.com/jiuzhang-waf/server/internal/config"
)

func TestNewRejectsMissingMasterKeyInProduction(t *testing.T) {
	t.Setenv("JIUZHANG_MASTER_KEY", "")

	if _, err := New(&config.Config{Env: "prod"}, nil, nil); err == nil {
		t.Fatal("New() accepted production configuration without JIUZHANG_MASTER_KEY")
	}
}

func TestNewRejectsInvalidMasterKeyInProduction(t *testing.T) {
	t.Setenv("JIUZHANG_MASTER_KEY", "invalid")

	if _, err := New(&config.Config{Env: "prod"}, nil, nil); err == nil {
		t.Fatal("New() accepted an invalid production JIUZHANG_MASTER_KEY")
	}
}
