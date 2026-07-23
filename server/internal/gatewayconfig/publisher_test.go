package gatewayconfig

import (
	"context"
	"errors"
	"testing"
)

type fakeGatewayConfigLoader struct {
	currentConfig string
	readErr       error
	loadErr       error
	loadCalls     int
}

func (f *fakeGatewayConfigLoader) GetCurrentConfig(context.Context) (string, error) {
	return f.currentConfig, f.readErr
}

func (f *fakeGatewayConfigLoader) LoadConfig(context.Context, string) error {
	f.loadCalls++
	return f.loadErr
}

func TestLoadGatewayConfigStopsWhenPreviousConfigCannotBeRead(t *testing.T) {
	loader := &fakeGatewayConfigLoader{readErr: errors.New("gateway unavailable")}

	if _, err := loadGatewayConfig(context.Background(), loader, `{"apps":{}}`); !errors.Is(err, errPreviousConfigRead) {
		t.Fatalf("loadGatewayConfig() error = %v, want errPreviousConfigRead", err)
	}
	if loader.loadCalls != 0 {
		t.Fatalf("LoadConfig() calls = %d, want 0", loader.loadCalls)
	}
}

func TestLoadGatewayConfigReturnsPreviousConfigWhenLoadFails(t *testing.T) {
	loadErr := errors.New("load rejected")
	loader := &fakeGatewayConfigLoader{
		currentConfig: `{"apps":{"old":{}}}`,
		loadErr:       loadErr,
	}

	previousConfig, err := loadGatewayConfig(context.Background(), loader, `{"apps":{"new":{}}}`)
	if !errors.Is(err, loadErr) {
		t.Fatalf("loadGatewayConfig() error = %v, want load error", err)
	}
	if previousConfig != loader.currentConfig {
		t.Fatalf("previous config = %q, want %q", previousConfig, loader.currentConfig)
	}
	if loader.loadCalls != 1 {
		t.Fatalf("LoadConfig() calls = %d, want 1", loader.loadCalls)
	}
}
