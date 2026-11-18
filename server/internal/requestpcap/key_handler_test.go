package requestpcap

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

func TestKeyRotationRequiresPasswordAndAuditsReason(t *testing.T) {
	_, service, _ := newServiceFixture(t)
	master, err := encryption.NewWithKey(bytes.Repeat([]byte{31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := LoadOrCreateKeyring(filepath.Join(t.TempDir(), "private.key"), master)
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()
	oldKeyID := keyring.KeyID()
	spy := &requestAuditSpy{}
	handler := NewHandler(service, &requestUserStub{user: testActiveUser(t)}, spy).SetRotation(keyring.Rotate)
	request := authenticatedRequest(t, http.MethodPost, "/api/v1/request-pcap/keys/rotate", map[string]string{"reason": "定期密钥轮换", "password": "wrong"}, PermissionManage)
	response := newTestRecorder()
	handler.RotateKeys(response, request)
	if response.Code != http.StatusBadRequest || keyring.KeyID() != oldKeyID || spy.last().Result != audits.ResultFailure {
		t.Fatalf("wrong password changed key or missed failure audit: %d %+v", response.Code, spy.last())
	}
	request = authenticatedRequest(t, http.MethodPost, "/api/v1/request-pcap/keys/rotate", map[string]string{"reason": "定期密钥轮换", "password": handlerTestPassword}, PermissionManage)
	response = newTestRecorder()
	handler.RotateKeys(response, request)
	if response.Code != http.StatusOK || keyring.KeyID() == oldKeyID {
		t.Fatalf("valid key rotation failed: %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(spy.last().AfterSummary, "定期密钥轮换") || strings.Contains(spy.last().AfterSummary, handlerTestPassword) {
		t.Fatalf("key rotation audit has wrong reason or leaks password: %+v", spy.last())
	}
}
