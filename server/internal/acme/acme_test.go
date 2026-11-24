package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// ---------- 进程内 RFC 8555 Mock ACME CA（真实走 golang.org/x/crypto/acme.Client） ----------

type mockACMEServer struct {
	ts           *httptest.Server
	caKey        *ecdsa.PrivateKey
	caCert       *x509.Certificate
	challengeSrv *httptest.Server

	mu            sync.Mutex
	failChallenge bool
	nonceSeq      int
	orders        map[string]*mockACMEOrder
	authzs        map[string]*mockACMEAuthz
	certs         map[string][]byte
	issueCount    int
}

type mockACMEOrder struct {
	ID         string
	Domains    []string
	AuthzIDs   []string
	Status     string
	CertID     string
	ExpiresISO string
}

type mockACMEAuthz struct {
	ID      string
	Domain  string
	Token   string
	Status  string
	OrderID string
}

func newMockACMEServer(t *testing.T, challengeDir string) *mockACMEServer {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Mock ACME Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	m := &mockACMEServer{
		caKey:  caKey,
		caCert: caCert,
		orders: map[string]*mockACMEOrder{},
		authzs: map[string]*mockACMEAuthz{},
		certs:  map[string][]byte{},
	}

	// 模拟网关 :80 HTTP-01 应答器（读取 solver 写入的本地挑战目录）
	m.challengeSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const pfx = "/.well-known/acme-challenge/"
		if !strings.HasPrefix(r.URL.Path, pfx) {
			http.NotFound(w, r)
			return
		}
		tok := strings.TrimPrefix(r.URL.Path, pfx)
		data, err := os.ReadFile(filepath.Join(challengeDir, tok))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(data)
	}))
	t.Cleanup(m.challengeSrv.Close)

	m.ts = httptest.NewTLSServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.ts.Close)
	return m
}

func (m *mockACMEServer) nextNonce() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nonceSeq++
	return fmt.Sprintf("nonce-%d", m.nonceSeq)
}

func decodeJWSPayload(body []byte) ([]byte, error) {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	if env.Payload == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(env.Payload)
}

func (m *mockACMEServer) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Replay-Nonce", m.nextNonce())
	base := m.ts.URL

	switch {
	case r.URL.Path == "/directory":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   base + "/new-nonce",
			"newAccount": base + "/new-account",
			"newOrder":   base + "/new-order",
		})
	case r.URL.Path == "/new-nonce":
		w.WriteHeader(http.StatusOK)
	case r.URL.Path == "/new-account":
		raw, _ := io.ReadAll(r.Body)
		payload, _ := decodeJWSPayload(raw)
		var acctReq struct {
			OnlyReturnExisting bool `json:"onlyReturnExisting"`
		}
		_ = json.Unmarshal(payload, &acctReq)
		w.Header().Set("Location", base+"/acct/1")
		if acctReq.OnlyReturnExisting {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
	case r.URL.Path == "/new-order":
		raw, _ := io.ReadAll(r.Body)
		payload, _ := decodeJWSPayload(raw)
		var req struct {
			Identifiers []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"identifiers"`
		}
		_ = json.Unmarshal(payload, &req)
		m.mu.Lock()
		ordID := uuid.NewString()[:8]
		ord := &mockACMEOrder{
			ID:         ordID,
			Status:     "pending",
			ExpiresISO: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		}
		authzURLs := make([]string, 0, len(req.Identifiers))
		idents := make([]map[string]string, 0, len(req.Identifiers))
		for _, id := range req.Identifiers {
			aid := uuid.NewString()[:8]
			tok := "MockToken" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
			m.authzs[aid] = &mockACMEAuthz{
				ID:      aid,
				Domain:  id.Value,
				Token:   tok,
				Status:  "pending",
				OrderID: ordID,
			}
			ord.Domains = append(ord.Domains, id.Value)
			ord.AuthzIDs = append(ord.AuthzIDs, aid)
			authzURLs = append(authzURLs, base+"/authz/"+aid)
			idents = append(idents, map[string]string{"type": "dns", "value": id.Value})
		}
		m.orders[ordID] = ord
		m.mu.Unlock()

		w.Header().Set("Location", base+"/order/"+ordID)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":         ord.Status,
			"expires":        ord.ExpiresISO,
			"identifiers":    idents,
			"authorizations": authzURLs,
			"finalize":       base + "/finalize/" + ordID,
		})
	case strings.HasPrefix(r.URL.Path, "/authz/"):
		aid := strings.TrimPrefix(r.URL.Path, "/authz/")
		m.mu.Lock()
		a := m.authzs[aid]
		m.mu.Unlock()
		if a == nil {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     a.Status,
			"identifier": map[string]string{"type": "dns", "value": a.Domain},
			"challenges": []map[string]any{{
				"type":   "http-01",
				"url":    base + "/chal/" + aid,
				"token":  a.Token,
				"status": a.Status,
			}},
		})
	case strings.HasPrefix(r.URL.Path, "/chal/"):
		aid := strings.TrimPrefix(r.URL.Path, "/chal/")
		m.mu.Lock()
		a := m.authzs[aid]
		shouldFail := m.failChallenge
		m.mu.Unlock()
		if a == nil {
			http.NotFound(w, r)
			return
		}
		// 真实向 HTTP-01 应答器发起验证请求
		status := "valid"
		if shouldFail {
			status = "invalid"
		} else {
			resp, err := http.Get(m.challengeSrv.URL + "/.well-known/acme-challenge/" + a.Token)
			if err != nil || resp.StatusCode != http.StatusOK {
				status = "invalid"
			} else {
				body, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if !strings.HasPrefix(string(body), a.Token+".") {
					status = "invalid"
				}
			}
		}
		m.mu.Lock()
		a.Status = status
		ord := m.orders[a.OrderID]
		if ord != nil && status == "valid" {
			allValid := true
			for _, id := range ord.AuthzIDs {
				if m.authzs[id].Status != "valid" {
					allValid = false
					break
				}
			}
			if allValid {
				ord.Status = "ready"
			}
		} else if ord != nil && status == "invalid" {
			ord.Status = "invalid"
		}
		m.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type": "http-01", "url": base + "/chal/" + aid, "token": a.Token, "status": status,
		})
	case strings.HasPrefix(r.URL.Path, "/order/"):
		ordID := strings.TrimPrefix(r.URL.Path, "/order/")
		m.mu.Lock()
		ord := m.orders[ordID]
		m.mu.Unlock()
		if ord == nil {
			http.NotFound(w, r)
			return
		}
		resp := map[string]any{
			"status":   ord.Status,
			"finalize": base + "/finalize/" + ordID,
		}
		if ord.CertID != "" {
			resp["certificate"] = base + "/cert/" + ord.CertID
		}
		_ = json.NewEncoder(w).Encode(resp)
	case strings.HasPrefix(r.URL.Path, "/finalize/"):
		ordID := strings.TrimPrefix(r.URL.Path, "/finalize/")
		raw, _ := io.ReadAll(r.Body)
		payload, _ := decodeJWSPayload(raw)
		var finReq struct {
			CSR string `json:"csr"`
		}
		_ = json.Unmarshal(payload, &finReq)
		csrDER, err := base64.RawURLEncoding.DecodeString(finReq.CSR)
		if err != nil {
			http.Error(w, "bad csr", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			http.Error(w, "invalid csr", http.StatusBadRequest)
			return
		}

		m.mu.Lock()
		m.issueCount++
		serial := big.NewInt(int64(1000 + m.issueCount))
		leafTmpl := &x509.Certificate{
			SerialNumber: serial,
			Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
			DNSNames:     csr.DNSNames,
			NotBefore:    time.Now().Add(-5 * time.Minute),
			NotAfter:     time.Now().Add(90 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, m.caCert, csr.PublicKey, m.caKey)
		if err != nil {
			m.mu.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var pemBuf bytes.Buffer
		_ = pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		_ = pem.Encode(&pemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})

		certID := uuid.NewString()[:8]
		m.certs[certID] = pemBuf.Bytes()
		ord := m.orders[ordID]
		ord.Status = "valid"
		ord.CertID = certID
		m.mu.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":      "valid",
			"certificate": base + "/cert/" + certID,
		})
	case strings.HasPrefix(r.URL.Path, "/cert/"):
		certID := strings.TrimPrefix(r.URL.Path, "/cert/")
		m.mu.Lock()
		data := m.certs[certID]
		m.mu.Unlock()
		if len(data) == 0 {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(data)
	default:
		http.NotFound(w, r)
	}
}

// ---------- 内存测试替身 ----------

type memACMERepo struct {
	mu       sync.Mutex
	cfg      Config
	accounts map[string]*Account
	acctKeys map[uuid.UUID]crypto.Signer
	orders   map[uuid.UUID]*Order
}

func newMemACMERepo(dirURL string) *memACMERepo {
	return &memACMERepo{
		cfg: Config{
			Enabled:               true,
			Provider:              ProviderCustom,
			DirectoryURL:          dirURL,
			EffectiveDirectoryURL: dirURL,
			Email:                 "ops@example.com",
			TOSAgreed:             true,
			KeyType:               KeyTypeEC256,
			RenewBeforeDays:       30,
			AutoPublish:           true,
			Version:               1,
		},
		accounts: map[string]*Account{},
		acctKeys: map[uuid.UUID]crypto.Signer{},
		orders:   map[uuid.UUID]*Order{},
	}
}

func (r *memACMERepo) GetConfig(context.Context) (*Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := r.cfg
	return &cp, nil
}

func (r *memACMERepo) UpdateConfig(_ context.Context, in ConfigUpdateInput) (*Config, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if in.ExpectedVersion > 0 && in.ExpectedVersion != r.cfg.Version {
		return nil, ErrVersionConflict
	}
	r.cfg.Enabled = in.Enabled
	r.cfg.Provider = in.Provider
	r.cfg.DirectoryURL = in.DirectoryURL
	r.cfg.CustomDirectoryAllowlist = in.CustomDirectoryAllowlist
	r.cfg.Email = in.Email
	r.cfg.TOSAgreed = in.TOSAgreed
	r.cfg.EABKID = in.EABKID
	if in.ClearEABHMACKey {
		r.cfg.eabHMACKey = ""
		r.cfg.EABHMACConfigured = false
	} else if in.EABHMACKey != "" {
		r.cfg.eabHMACKey = in.EABHMACKey
		r.cfg.EABHMACConfigured = true
	}
	r.cfg.KeyType = in.KeyType
	r.cfg.RenewBeforeDays = in.RenewBeforeDays
	r.cfg.AutoPublish = in.AutoPublish
	r.cfg.Version++
	r.cfg.EffectiveDirectoryURL, _ = EffectiveDirectoryURL(r.cfg.Provider, r.cfg.DirectoryURL)
	cp := r.cfg
	return &cp, nil
}

func (r *memACMERepo) GetOrCreateAccount(_ context.Context, provider, directoryURL, email, eabKID string) (*Account, crypto.Signer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := directoryURL + "|" + email
	if a, ok := r.accounts[k]; ok {
		return a, r.acctKeys[a.ID], nil
	}
	signer, _, err := GenerateAccountKey()
	if err != nil {
		return nil, nil, err
	}
	a := &Account{ID: uuid.New(), Provider: provider, DirectoryURL: directoryURL, Email: email, EABKID: eabKID}
	r.accounts[k] = a
	r.acctKeys[a.ID] = signer
	return a, signer, nil
}

func (r *memACMERepo) UpdateAccountURI(_ context.Context, accountID uuid.UUID, uri string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, a := range r.accounts {
		if a.ID == accountID {
			a.AccountURI = uri
		}
	}
	return nil
}

func (r *memACMERepo) CreateOrder(_ context.Context, o *Order) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	o.ID = uuid.New()
	o.CreatedAt = time.Now().UTC()
	o.UpdatedAt = o.CreatedAt
	cp := *o
	r.orders[o.ID] = &cp
	return nil
}

func (r *memACMERepo) UpdateOrderProgress(_ context.Context, id uuid.UUID, status string, startedAt *time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o := r.orders[id]; o != nil {
		o.Status = status
		if startedAt != nil && o.StartedAt == nil {
			t := *startedAt
			o.StartedAt = &t
		}
		o.UpdatedAt = time.Now().UTC()
	}
	return nil
}

func (r *memACMERepo) FinishOrder(_ context.Context, id uuid.UUID, status string, certID, prevCertID, pubTaskID *uuid.UUID, errCode, errMsg string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if o := r.orders[id]; o != nil {
		o.Status = status
		if certID != nil {
			o.CertificateID = certID
		}
		if prevCertID != nil {
			o.PreviousCertificateID = prevCertID
		}
		if pubTaskID != nil {
			o.PublishTaskID = pubTaskID
		}
		o.ErrorCode = errCode
		o.ErrorMessage = errMsg
		now := time.Now().UTC()
		o.FinishedAt = &now
		o.UpdatedAt = now
	}
	return nil
}

func (r *memACMERepo) GetOrder(_ context.Context, id uuid.UUID) (*Order, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	o := r.orders[id]
	if o == nil {
		return nil, ErrOrderNotFound
	}
	cp := *o
	return &cp, nil
}

func (r *memACMERepo) HasActiveOrderForApp(_ context.Context, appID uuid.UUID) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.orders {
		if o.ApplicationID == appID && IsActiveOrderStatus(o.Status) {
			return true, nil
		}
	}
	return false, nil
}

func (r *memACMERepo) GetLatestOrderForApp(_ context.Context, appID uuid.UUID) (*Order, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var latest *Order
	for _, o := range r.orders {
		if o.ApplicationID == appID {
			if latest == nil || o.CreatedAt.After(latest.CreatedAt) {
				cp := *o
				latest = &cp
			}
		}
	}
	return latest, nil
}

func (r *memACMERepo) ListOrders(_ context.Context, f OrderFilter) ([]Order, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Order
	for _, o := range r.orders {
		if f.ApplicationID != nil && o.ApplicationID != *f.ApplicationID {
			continue
		}
		if f.Status != "" && o.Status != f.Status {
			continue
		}
		out = append(out, *o)
	}
	return out, int64(len(out)), nil
}

func (r *memACMERepo) MarkStaleOrdersFailed(context.Context, time.Duration) (int, error) {
	return 0, nil
}

type memAppRepo struct {
	mu      sync.Mutex
	apps    map[uuid.UUID]*applications.Application
	domains map[uuid.UUID][]applications.Domain
}

func (m *memAppRepo) GetByID(_ context.Context, id uuid.UUID) (*applications.Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.apps[id]
	if a == nil {
		return nil, applications.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (m *memAppRepo) ListDomains(_ context.Context, appID uuid.UUID) ([]applications.Domain, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]applications.Domain(nil), m.domains[appID]...), nil
}

func (m *memAppRepo) UpdateAutoSSLConfig(_ context.Context, appID uuid.UUID, enabled bool, challengeType string, renewBeforeDays *int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.apps[appID]
	if a == nil {
		return applications.ErrNotFound
	}
	a.AutoSSLEnabled = enabled
	a.AutoSSLChallengeType = challengeType
	a.AutoSSLRenewBeforeDays = renewBeforeDays
	return nil
}

func (m *memAppRepo) UpdateAutoSSLRuntimeState(_ context.Context, appID uuid.UUID, lastStatus, lastError string, failCount int, nextRetryAt, lastAttemptAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := m.apps[appID]
	if a == nil {
		return applications.ErrNotFound
	}
	a.AutoSSLLastStatus = lastStatus
	a.AutoSSLLastError = lastError
	a.AutoSSLFailCount = failCount
	a.AutoSSLNextRetryAt = nextRetryAt
	a.AutoSSLLastAttemptAt = lastAttemptAt
	return nil
}

func (m *memAppRepo) ListAutoSSLCandidates(context.Context) ([]applications.Application, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []applications.Application
	for _, a := range m.apps {
		if a.Status == applications.StatusActive && a.AutoSSLEnabled && a.DeploymentMode != applications.DeployModeMirror {
			out = append(out, *a)
		}
	}
	return out, nil
}

func (m *memAppRepo) HasAnyAutoSSLEnabled(context.Context) (bool, error) {
	list, _ := m.ListAutoSSLCandidates(context.Background())
	return len(list) > 0, nil
}

type memCertRepo struct {
	mu       sync.Mutex
	enc      *encryption.Service
	certs    map[uuid.UUID]*certificates.Certificate
	bindings map[uuid.UUID]uuid.UUID // appID -> certID
	refreshes int
}

func newMemCertRepo(t *testing.T) *memCertRepo {
	t.Helper()
	enc, err := encryption.NewWithKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return &memCertRepo{
		enc:      enc,
		certs:    map[uuid.UUID]*certificates.Certificate{},
		bindings: map[uuid.UUID]uuid.UUID{},
	}
}

func (m *memCertRepo) GetByID(_ context.Context, id uuid.UUID) (*certificates.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.certs[id]
	if c == nil {
		return nil, certificates.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (m *memCertRepo) GetApplicationCertificate(_ context.Context, appID uuid.UUID) (*certificates.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cid, ok := m.bindings[appID]
	if !ok {
		return nil, nil
	}
	c := m.certs[cid]
	if c == nil {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}

func (m *memCertRepo) ListApplicationIDs(_ context.Context, certID uuid.UUID) ([]uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []uuid.UUID
	for appID, cid := range m.bindings {
		if cid == certID {
			out = append(out, appID)
		}
	}
	return out, nil
}

func (m *memCertRepo) CreateManagedAndBind(_ context.Context, in certificates.ManagedIssueInput) (*certificates.Certificate, *uuid.UUID, error) {
	cert, parsed, err := certificates.ParseCertificatePEM(in.CertPEM)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(in.ChainPEM) != "" {
		if _, _, err := certificates.ParseCertificateChainPEM(in.ChainPEM); err != nil {
			return nil, nil, err
		}
	}
	if err := certificates.ValidatePrivateKeyPEM(in.KeyPEM, cert); err != nil {
		return nil, nil, err
	}
	if unmatched := certificates.MatchDomains(parsed, in.AppDomains); len(unmatched) > 0 {
		return nil, nil, fmt.Errorf("%w: %v", certificates.ErrDomainMismatch, unmatched)
	}
	if _, err := m.enc.Encrypt(in.KeyPEM); err != nil {
		return nil, nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	var prevID *uuid.UUID
	if existing, ok := m.bindings[in.ApplicationID]; ok {
		idCopy := existing
		prevID = &idCopy
	}
	sanJSON, _ := json.Marshal(parsed.SANDomains)
	now := time.Now().UTC()
	newCert := &certificates.Certificate{
		ID:                    uuid.New(),
		Name:                  in.NamePrefix + "-" + now.Format("20060102-150405"),
		CommonName:            parsed.CommonName,
		Issuer:                parsed.Issuer,
		NotBefore:             &parsed.NotBefore,
		NotAfter:              &parsed.NotAfter,
		FingerprintSHA256:     parsed.FingerprintSHA256,
		SANDomains:            sanJSON,
		Status:                certificates.StatusValid,
		ManagedBy:             certificates.ManagedByACME,
		ACMEProvider:          in.ACMEProvider,
		ACMEDirectoryURL:      in.ACMEDirectoryURL,
		AutoRenew:             in.AutoRenew,
		RenewBeforeDays:       in.RenewBeforeDays,
		ReplacesCertificateID: prevID,
	}
	m.certs[newCert.ID] = newCert
	m.bindings[in.ApplicationID] = newCert.ID

	if prevID != nil {
		if old := m.certs[*prevID]; old != nil && old.ManagedBy == certificates.ManagedByACME {
			old.Status = certificates.StatusReplaced
			old.AutoRenew = false
			old.SupersededBy = &newCert.ID
		}
	}
	cp := *newCert
	return &cp, prevID, nil
}

func (m *memCertRepo) RefreshStatus(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshes++
	return 0, nil
}

type fakePublisher struct {
	mu            sync.Mutex
	hasHTTP01     bool
	publishCount  int
	failNext      bool
}

func (p *fakePublisher) HasActiveACMEHTTP01Route(context.Context) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hasHTTP01, nil
}

func (p *fakePublisher) PublishSync(_ context.Context, _ gatewayconfig.PublishInput) (*gatewayconfig.PublishTask, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.publishCount++
	if p.failNext {
		p.failNext = false
		return &gatewayconfig.PublishTask{ID: uuid.New(), Status: gatewayconfig.TaskFailed, FailureMessage: "mock publish failure"}, nil
	}
	p.hasHTTP01 = true
	return &gatewayconfig.PublishTask{ID: uuid.New(), Status: gatewayconfig.TaskSuccess}, nil
}

type fakeAlertSink struct {
	mu        sync.Mutex
	raised    []string
	recovered int
}

func (a *fakeAlertSink) RaiseRenewalFailure(_ context.Context, title, msg string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.raised = append(a.raised, title+": "+msg)
	return nil
}

func (a *fakeAlertSink) RecoverRenewalFailure(context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.recovered++
	return nil
}

// ---------- 核心端到端测试 ----------

func TestAutoSSL_InitialIssueRenewAndDomainSync(t *testing.T) {
	dataDir := t.TempDir()
	solver := NewHTTP01Solver(nil, dataDir)
	ca := newMockACMEServer(t, solver.ChallengeDir())

	repo := newMemACMERepo(ca.ts.URL + "/directory")
	appID := uuid.New()
	apps := &memAppRepo{
		apps: map[uuid.UUID]*applications.Application{
			appID: {
				ID:             appID,
				Code:           "shop",
				Name:           "商城站点",
				Status:         applications.StatusActive,
				DeploymentMode: applications.DeployModeReverseProxy,
				AutoSSLEnabled: true,
			},
		},
		domains: map[uuid.UUID][]applications.Domain{
			appID: {{
				ID:                 uuid.New(),
				ApplicationID:      appID,
				Hostname:           "shop.example.com",
				NormalizedHostname: "shop.example.com",
				HTTPSEnabled:       true,
				Status:             "ACTIVE",
			}},
		},
	}
	certs := newMemCertRepo(t)
	pub := &fakePublisher{hasHTTP01: false}
	alerts := &fakeAlertSink{}

	issuer := NewIssuer()
	issuer.httpClientFactory = func(context.Context, string, string) (*http.Client, error) {
		return ca.ts.Client(), nil
	}
	svc := NewService(repo, apps, certs, pub, nil, solver, issuer, nil)
	svc.SetAlertSink(alerts)
	svc.publishRetryDelay = time.Millisecond

	now := time.Now().UTC()
	svc.nowFn = func() time.Time { return now }
	worker := NewWorker(svc, repo, apps, certs, nil, solver, time.Minute)

	// 1. 首次巡检：无证书 → 自动准备 :80 HTTP-01 + 申请 + 绑定 + 自动发布
	worker.RunOnce(context.Background())

	firstCert, _ := certs.GetApplicationCertificate(context.Background(), appID)
	if firstCert == nil {
		t.Fatal("expected initial ACME certificate to be issued and bound")
	}
	if firstCert.CommonName != "shop.example.com" || firstCert.ManagedBy != certificates.ManagedByACME {
		t.Fatalf("unexpected initial cert: %+v", firstCert)
	}
	// 首次需发布两次：1) 就绪 :80 HTTP-01 路由；2) 证书入库后发布上线 :443
	if pub.publishCount != 2 {
		t.Fatalf("publishCount=%d, want 2 (prep http01 + activate cert)", pub.publishCount)
	}
	if ca.issueCount != 1 {
		t.Fatalf("ca.issueCount=%d, want 1", ca.issueCount)
	}

	// 2. 再次巡检：证书有效期剩余 ~90 天（>30天）且域名完全覆盖 → 幂等跳过，不重复下单
	worker.RunOnce(context.Background())
	if ca.issueCount != 1 {
		t.Fatalf("should not reissue healthy cert; ca.issueCount=%d", ca.issueCount)
	}

	// 3. 时间推进至到期前 20 天（<= 30 天续约窗口）→ 触发 AUTO_RENEW
	now = firstCert.NotAfter.Add(-20 * 24 * time.Hour)
	worker.RunOnce(context.Background())

	renewedCert, _ := certs.GetApplicationCertificate(context.Background(), appID)
	if renewedCert == nil || renewedCert.ID == firstCert.ID {
		t.Fatalf("expected renewed immutable certificate row; got %+v", renewedCert)
	}
	if renewedCert.ReplacesCertificateID == nil || *renewedCert.ReplacesCertificateID != firstCert.ID {
		t.Fatalf("expected replaces_certificate_id=%s, got %v", firstCert.ID, renewedCert.ReplacesCertificateID)
	}
	oldCert, _ := certs.GetByID(context.Background(), firstCert.ID)
	if oldCert.Status != certificates.StatusReplaced || oldCert.AutoRenew {
		t.Fatalf("expected old cert marked REPLACED with auto_renew=false, got status=%s auto_renew=%v", oldCert.Status, oldCert.AutoRenew)
	}
	if pub.publishCount != 3 {
		t.Fatalf("expected auto publish on renewal; publishCount=%d, want 3", pub.publishCount)
	}

	// 4. 新增第二个 HTTPS 域名 → 触发 AUTO_DOMAIN_SYNC 补签多域名 SAN 证书
	now = time.Now().UTC()
	apps.mu.Lock()
	apps.domains[appID] = append(apps.domains[appID], applications.Domain{
		ID:                 uuid.New(),
		ApplicationID:      appID,
		Hostname:           "api.example.com",
		NormalizedHostname: "api.example.com",
		HTTPSEnabled:       true,
		Status:             "ACTIVE",
	})
	apps.mu.Unlock()

	worker.RunOnce(context.Background())
	sanCert, _ := certs.GetApplicationCertificate(context.Background(), appID)
	if sanCert == nil || sanCert.ID == renewedCert.ID {
		t.Fatal("expected domain-sync reissue covering newly added HTTPS domain")
	}
	var sans []string
	_ = json.Unmarshal(sanCert.SANDomains, &sans)
	if len(sans) != 2 {
		t.Fatalf("expected 2 SAN domains, got %v", sans)
	}
}

func TestAutoSSL_FailureBackoffAlertAndRecovery(t *testing.T) {
	dataDir := t.TempDir()
	solver := NewHTTP01Solver(nil, dataDir)
	ca := newMockACMEServer(t, solver.ChallengeDir())
	ca.failChallenge = true

	repo := newMemACMERepo(ca.ts.URL + "/directory")
	appID := uuid.New()
	apps := &memAppRepo{
		apps: map[uuid.UUID]*applications.Application{
			appID: {
				ID: appID, Code: "retry-app", Name: "重试站点",
				Status: applications.StatusActive, DeploymentMode: applications.DeployModeReverseProxy,
				AutoSSLEnabled: true,
			},
		},
		domains: map[uuid.UUID][]applications.Domain{
			appID: {{ID: uuid.New(), ApplicationID: appID, Hostname: "retry.example.com", NormalizedHostname: "retry.example.com", HTTPSEnabled: true, Status: "ACTIVE"}},
		},
	}
	certs := newMemCertRepo(t)
	pub := &fakePublisher{hasHTTP01: true}
	alerts := &fakeAlertSink{}

	issuer := NewIssuer()
	issuer.httpClientFactory = func(context.Context, string, string) (*http.Client, error) {
		return ca.ts.Client(), nil
	}
	svc := NewService(repo, apps, certs, pub, nil, solver, issuer, nil)
	svc.SetAlertSink(alerts)
	now := time.Now().UTC()
	svc.nowFn = func() time.Time { return now }
	worker := NewWorker(svc, repo, apps, certs, nil, solver, time.Minute)

	// 1. 验证失败 → 记录退避、触发高危告警
	worker.RunOnce(context.Background())
	appState, _ := apps.GetByID(context.Background(), appID)
	if appState.AutoSSLFailCount != 1 || appState.AutoSSLNextRetryAt == nil {
		t.Fatalf("expected fail_count=1 and next_retry_at set; got %+v", appState)
	}
	if len(alerts.raised) != 1 {
		t.Fatalf("expected 1 failure alert raised, got %d", len(alerts.raised))
	}

	// 2. 退避窗口内再次巡检 → 跳过不重复打 CA
	ca.failChallenge = false
	worker.RunOnce(context.Background())
	if ca.issueCount != 0 {
		t.Fatalf("should respect backoff before next_retry_at; issueCount=%d", ca.issueCount)
	}

	// 3. 退避到期后自动重试成功 → 清零失败计数并自动恢复告警
	now = appState.AutoSSLNextRetryAt.Add(time.Second)
	worker.RunOnce(context.Background())
	appState, _ = apps.GetByID(context.Background(), appID)
	if appState.AutoSSLFailCount != 0 || appState.AutoSSLNextRetryAt != nil || appState.AutoSSLLastStatus != OrderSucceeded {
		t.Fatalf("expected recovered app state; got %+v", appState)
	}
	if alerts.recovered != 1 {
		t.Fatalf("expected alert auto-recovered once, got %d", alerts.recovered)
	}
}

func TestAutoSSL_SecurityAndValidationGuards(t *testing.T) {
	ctx := context.Background()

	// 1. SSRF 校验：拒绝明文 http、回环、内网、云元数据
	for _, bad := range []string{
		"http://acme-v02.api.letsencrypt.org/directory",
		"https://127.0.0.1/directory",
		"https://10.0.0.5/directory",
		"https://169.254.169.254/latest/meta-data",
	} {
		if _, err := ValidateDirectoryURL(ctx, bad, ""); err == nil {
			t.Errorf("ValidateDirectoryURL(%q) expected error, got nil", bad)
		}
	}
	// 显式 allowlist 放行内网私有 CA，但云元数据仍硬拒绝
	if _, err := ValidateDirectoryURL(ctx, "https://10.0.0.5:14000/dir", "10.0.0.0/8"); err != nil {
		t.Errorf("allowlisted private CA should pass: %v", err)
	}
	if _, err := ValidateDirectoryURL(ctx, "https://169.254.169.254/dir", "169.254.0.0/16"); err == nil {
		t.Errorf("cloud metadata must stay hard-denied even with allowlist")
	}

	// 2. 泛域名与 MIRROR 模式拒绝开启自动 SSL
	repo := newMemACMERepo(DirectoryLetsEncrypt)
	repo.cfg.Provider = ProviderLetsEncrypt
	wildcardAppID := uuid.New()
	mirrorAppID := uuid.New()
	apps := &memAppRepo{
		apps: map[uuid.UUID]*applications.Application{
			wildcardAppID: {ID: wildcardAppID, Code: "wc", Status: applications.StatusActive, DeploymentMode: applications.DeployModeReverseProxy},
			mirrorAppID:   {ID: mirrorAppID, Code: "mr", Status: applications.StatusActive, DeploymentMode: applications.DeployModeMirror},
		},
		domains: map[uuid.UUID][]applications.Domain{
			wildcardAppID: {{ID: uuid.New(), ApplicationID: wildcardAppID, Hostname: "*.example.com", NormalizedHostname: "*.example.com", HTTPSEnabled: true, Status: "ACTIVE"}},
		},
	}
	svc := NewService(repo, apps, newMemCertRepo(t), nil, nil, NewHTTP01Solver(nil, t.TempDir()), NewIssuer(), nil)

	if _, err := svc.UpdateAppAutoSSL(ctx, wildcardAppID, true, ChallengeHTTP01, nil); !errors.Is(err, ErrWildcardHTTP01) {
		t.Fatalf("expected ErrWildcardHTTP01, got %v", err)
	}
	if _, err := svc.UpdateAppAutoSSL(ctx, mirrorAppID, true, ChallengeHTTP01, nil); !errors.Is(err, ErrMirrorUnsupported) {
		t.Fatalf("expected ErrMirrorUnsupported, got %v", err)
	}

	// 3. HTTP Handler 测试：不泄露 EAB HMAC 明文、乐观锁冲突返回 409
	h := NewHandler(svc, nil)
	principal := &authz.Principal{UserID: uuid.New(), Username: "secadmin"}
	putBody := `{"enabled":true,"provider":"CUSTOM","directory_url":"https://10.0.0.5:14000/dir","custom_directory_allowlist":"10.0.0.0/8","email":"ops@example.com","tos_agreed":true,"eab_kid":"kid-1","eab_hmac_key":"c2VjcmV0LWhtYWMta2V5","key_type":"EC256","renew_before_days":30,"auto_publish":true,"version":1}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/acme/config", strings.NewReader(putBody))
	req = req.WithContext(authz.WithPrincipal(req.Context(), principal))
	rec := httptest.NewRecorder()
	h.UpdateConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("UpdateConfig status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "c2VjcmV0LWhtYWMta2V5") {
		t.Fatalf("response must never echo EAB HMAC plaintext: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"eab_hmac_configured":true`) {
		t.Fatalf("expected eab_hmac_configured=true: %s", rec.Body.String())
	}
	// 旧版本号再次提交 → 409
	req2 := httptest.NewRequest(http.MethodPut, "/api/v1/certificates/acme/config", strings.NewReader(putBody))
	req2 = req2.WithContext(authz.WithPrincipal(req2.Context(), principal))
	rec2 := httptest.NewRecorder()
	h.UpdateConfig(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("expected 409 on stale version, got %d (%s)", rec2.Code, rec2.Body.String())
	}
}
