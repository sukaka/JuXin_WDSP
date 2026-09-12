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
		currentConfig: `{"apps":{"old":{}},"api_authz_models":[{"application_id":"orders","endpoint_key":"GET /orders/{id}","object_type":"order"}],"api_authz_object_hmac_key_hex":"current-hmac","api_authz_previous_valid":{"models":[{"application_id":"orders","endpoint_key":"GET /orders/{id}","object_type":"order"}],"policy_version":"authz-v1","object_hmac_key_hex":"current-hmac"}}`,
		loadErr:       loadErr,
	}

	previousConfig, err := loadGatewayConfig(context.Background(), loader, `{"apps":{"new":{}},"api_authz_models":[{"application_id":"orders","endpoint_key":"GET /orders/{id}","object_type":"order"}],"api_authz_object_hmac_key_hex":"candidate-hmac"}`)
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

func TestPublishRollbackFailureCode(t *testing.T) {
	tests := []struct {
		name          string
		operationCode string
		rollbackErr   error
		want          string
	}{
		{
			name:          "verify failure after successful rollback",
			operationCode: "VERIFY_FAILED",
			want:          "VERIFY_FAILED_ROLLED_BACK",
		},
		{
			name:          "verify failure after rollback failure",
			operationCode: "VERIFY_FAILED",
			rollbackErr:   errors.New("restore rejected"),
			want:          "ROLLBACK_FAILED",
		},
		{
			name:          "activation failure after successful rollback",
			operationCode: "SET_CURRENT_VERSION_FAILED",
			want:          "SET_CURRENT_VERSION_FAILED_ROLLED_BACK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := publishRollbackFailureCode(tt.operationCode, tt.rollbackErr); got != tt.want {
				t.Fatalf("publishRollbackFailureCode(%q, %v) = %q, want %q", tt.operationCode, tt.rollbackErr, got, tt.want)
			}
		})
	}
}
