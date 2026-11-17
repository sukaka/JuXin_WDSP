package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/apidataflow"
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

func TestNewAPIDataflowReaderWithoutDependencies(t *testing.T) {
	reader := newAPIDataflowReader(nil, nil)
	if reader == nil {
		t.Fatal("newAPIDataflowReader() returned nil")
	}
	_, err := reader.Graph(context.Background(), apidataflow.GraphFilter{
		Start: time.Unix(0, 0),
		End:   time.Unix(1, 0),
	})
	if !errors.Is(err, apidataflow.ErrObservationDataPlane) {
		t.Fatalf("Graph() error = %v, want ErrObservationDataPlane", err)
	}
}
