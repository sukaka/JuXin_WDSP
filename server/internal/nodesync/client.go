package nodesync

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultRequestTimeout = 30 * time.Second
	defaultUploadTimeout  = 30 * time.Minute
	maxResponseBodyBytes  = 16 << 20 // 16 MiB
)

// ClientConfig configures a nodesync Client.
type ClientConfig struct {
	Addr          string
	SecretHex     string
	SecretBytes   []byte
	NodeName      string
	TLSCAPEM      []byte
	TLSCertSHA256 string
	Timeout       time.Duration
	UploadTimeout time.Duration
	Resolver      IPResolver
	NowFunc       func() time.Time
}

// Client is a secure HMAC-authenticated HTTP(S) client for a single hasyncd peer node.
type Client struct {
	baseURL      string
	nodeName     string
	secret       []byte
	httpClient   *http.Client
	uploadClient *http.Client
	now          func() time.Time
}

// NewClient validates addr, secret, and TLS settings and constructs a secure Client.
func NewClient(cfg ClientConfig) (*Client, error) {
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	parsedURL, err := parseSyncAgentAddr(context.Background(), cfg.Addr, resolver)
	if err != nil {
		return nil, err
	}

	var secret []byte
	if len(cfg.SecretBytes) > 0 {
		if len(cfg.SecretBytes) < MinSecretBytes {
			return nil, fmt.Errorf("sync secret must be at least %d bytes", MinSecretBytes)
		}
		secret = append([]byte(nil), cfg.SecretBytes...)
	} else {
		secret, err = ParseSecretHex(cfg.SecretHex)
		if err != nil {
			return nil, err
		}
	}

	nodeName := strings.TrimSpace(cfg.NodeName)
	if nodeName == "" {
		nodeName = "control-plane"
	}
	if !isValidNodeHeader(nodeName) {
		return nil, fmt.Errorf("invalid node name %q", nodeName)
	}

	nowFn := cfg.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}

	tlsCfg, err := buildTLSConfig(parsedURL.Hostname(), cfg.TLSCAPEM, cfg.TLSCertSHA256, nowFn)
	if err != nil {
		return nil, err
	}

	reqTimeout := cfg.Timeout
	if reqTimeout <= 0 {
		reqTimeout = defaultRequestTimeout
	}
	upTimeout := cfg.UploadTimeout
	if upTimeout <= 0 {
		upTimeout = defaultUploadTimeout
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	newTransport := func() *http.Transport {
		return &http.Transport{
			DisableKeepAlives:     true,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig:       tlsCfg,
			DialContext:           safeDialContext(dialer, resolver),
		}
	}
	noRedirect := func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	upTransport := newTransport()
	upTransport.ResponseHeaderTimeout = upTimeout

	return &Client{
		baseURL:  parsedURL.Scheme + "://" + parsedURL.Host,
		nodeName: nodeName,
		secret:   secret,
		httpClient: &http.Client{
			Transport:     newTransport(),
			Timeout:       reqTimeout,
			CheckRedirect: noRedirect,
		},
		uploadClient: &http.Client{
			Transport:     upTransport,
			Timeout:       upTimeout,
			CheckRedirect: noRedirect,
		},
		now: nowFn,
	}, nil
}

// Addr returns the normalized base URL of the remote hasyncd agent.
func (c *Client) Addr() string {
	return c.baseURL
}

// Health calls GET /v1/health.
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	var out HealthResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/health", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status calls GET /v1/status.
func (c *Client) Status(ctx context.Context) (*StatusResponse, error) {
	var out StatusResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/status", nil, &out); err != nil {
		return nil, err
	}
	if out.Interfaces == nil {
		out.Interfaces = []InterfaceSnapshot{}
	}
	return &out, nil
}

// LoadCaddyConfig calls POST /v1/caddy/load with a validated JSON Caddy configuration.
func (c *Client) LoadCaddyConfig(ctx context.Context, configJSON []byte) (*CaddyLoadResponse, error) {
	if !json.Valid(configJSON) {
		return nil, errors.New("configJSON is not valid JSON")
	}
	respBody, statusCode, err := c.doRaw(ctx, http.MethodPost, "/v1/caddy/load", configJSON, "application/json")
	if err != nil {
		return nil, err
	}
	var out CaddyLoadResponse
	_ = json.Unmarshal(respBody, &out)
	if statusCode != http.StatusOK {
		msg := out.Error
		if msg == "" {
			msg = extractErrorMessage(respBody)
		}
		return &out, &APIError{StatusCode: statusCode, Message: msg, Body: truncateStr(string(respBody), 1024)}
	}
	return &out, nil
}

// GetCaddyConfigHash calls GET /v1/caddy/config-hash.
func (c *Client) GetCaddyConfigHash(ctx context.Context) (*CaddyConfigHashResponse, error) {
	var out CaddyConfigHashResponse
	if err := c.doJSON(ctx, http.MethodGet, "/v1/caddy/config-hash", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutSidecar calls PUT /v1/sidecars/{name} for an allowlisted sidecar config file.
func (c *Client) PutSidecar(ctx context.Context, name string, payload []byte) (*SidecarWriteResponse, error) {
	if !AllowedSidecarFile(name) {
		return nil, fmt.Errorf("sidecar file %q not in allowlist", name)
	}
	if !json.Valid(payload) {
		return nil, errors.New("sidecar payload is not valid JSON")
	}
	var out SidecarWriteResponse
	if err := c.doRawDecode(ctx, http.MethodPut, "/v1/sidecars/"+name, payload, "application/json", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteSidecar calls DELETE /v1/sidecars/{name} for an allowlisted sidecar config file.
func (c *Client) DeleteSidecar(ctx context.Context, name string) (*SidecarDeleteResponse, error) {
	if !AllowedSidecarFile(name) {
		return nil, fmt.Errorf("sidecar file %q not in allowlist", name)
	}
	var out SidecarDeleteResponse
	if err := c.doJSON(ctx, http.MethodDelete, "/v1/sidecars/"+name, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnsureFirewallPorts calls POST /v1/firewall/ensure.
func (c *Client) EnsureFirewallPorts(ctx context.Context, req FirewallEnsureRequest) (*FirewallEnsureResponse, error) {
	if len(req.Ports) == 0 {
		return nil, errors.New("ports must not be empty")
	}
	if len(req.Ports) > 64 {
		return nil, fmt.Errorf("too many firewall ports: %d (max 64)", len(req.Ports))
	}
	for _, p := range req.Ports {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("firewall port out of range: %d", p)
		}
	}
	var out FirewallEnsureResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/firewall/ensure", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UploadUpgradePackage streams a local upgrade package file to POST /v1/upgrades/packages.
// Pass 1 computes SHA-256 and verifies non-empty regular file without buffering into memory;
// Pass 2 rewinds and streams the file body directly over HTTP(S).
func (c *Client) UploadUpgradePackage(ctx context.Context, localPath string, remoteFilename string) (*UpgradePackageUploadResponse, error) {
	if strings.TrimSpace(localPath) == "" {
		return nil, errors.New("local package path is empty")
	}
	if strings.TrimSpace(remoteFilename) == "" {
		remoteFilename = filepath.Base(localPath)
	}
	if err := ValidatePackageFilename(remoteFilename); err != nil {
		return nil, err
	}

	f, err := os.Open(localPath)
	if err != nil {
		return nil, fmt.Errorf("open upgrade package: %w", err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat upgrade package: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("upgrade package must be a regular file")
	}
	if fi.Size() <= 0 {
		return nil, errors.New("upgrade package file is empty")
	}

	h := sha256.New()
	hashedBytes, err := io.Copy(h, f)
	if err != nil {
		return nil, fmt.Errorf("hash upgrade package: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind upgrade package: %w", err)
	}
	shaHex := hex.EncodeToString(h.Sum(nil))
	return c.UploadUpgradePackageReader(ctx, remoteFilename, f, hashedBytes, shaHex)
}

// UploadUpgradePackageReader streams r with a precomputed SHA-256 digest to POST /v1/upgrades/packages.
func (c *Client) UploadUpgradePackageReader(ctx context.Context, remoteFilename string, r io.Reader, size int64, sha256Hex string) (*UpgradePackageUploadResponse, error) {
	if err := ValidatePackageFilename(remoteFilename); err != nil {
		return nil, err
	}
	sha256Hex = strings.ToLower(strings.TrimSpace(sha256Hex))
	if !isLowerHex64(sha256Hex) {
		return nil, errors.New("sha256Hex must be 64 lowercase hex chars")
	}
	if r == nil {
		return nil, errors.New("package reader is nil")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/upgrades/packages", r)
	if err != nil {
		return nil, err
	}
	if size >= 0 {
		req.ContentLength = size
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(HeaderPackageFilename, remoteFilename)
	req.Header.Set(HeaderPackageSHA256, sha256Hex)
	if err := SignRequest(req, c.secret, c.nodeName, sha256Hex, c.now(), ""); err != nil {
		return nil, err
	}

	resp, err := c.uploadClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload upgrade package request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read upload response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    extractErrorMessage(respBody),
			Body:       truncateStr(string(respBody), 1024),
		}
	}
	var out UpgradePackageUploadResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode upload response: %w", err)
	}
	return &out, nil
}

// ExecuteUpgrade calls POST /v1/upgrades/execute.
func (c *Client) ExecuteUpgrade(ctx context.Context, req UpgradeExecuteRequest) (*UpgradeExecuteResponse, error) {
	jobID, err := ValidateUUID(req.JobID)
	if err != nil {
		return nil, err
	}
	if err := ValidatePackageFilename(req.PackageFile); err != nil {
		return nil, err
	}
	req.JobID = jobID
	req.PackageSHA256 = strings.ToLower(strings.TrimSpace(req.PackageSHA256))
	if !isLowerHex64(req.PackageSHA256) {
		return nil, errors.New("invalid package_sha256")
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = c.now().UTC()
	}
	var out UpgradeExecuteResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/upgrades/execute", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetUpgradeJobResult calls GET /v1/upgrades/jobs/{job_id}.
func (c *Client) GetUpgradeJobResult(ctx context.Context, jobID string) (*UpgradeJobResult, error) {
	normID, err := ValidateUUID(jobID)
	if err != nil {
		return nil, err
	}
	var out UpgradeJobResult
	if err := c.doJSON(ctx, http.MethodGet, "/v1/upgrades/jobs/"+normID, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, out any) error {
	var raw []byte
	var contentType string
	if reqBody != nil {
		var err error
		raw, err = json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		contentType = "application/json"
	}
	return c.doRawDecode(ctx, method, path, raw, contentType, out)
}

func (c *Client) doRawDecode(ctx context.Context, method, path string, body []byte, contentType string, out any) error {
	respBody, statusCode, err := c.doRaw(ctx, method, path, body, contentType)
	if err != nil {
		return err
	}
	if statusCode < 200 || statusCode >= 300 {
		return &APIError{
			StatusCode: statusCode,
			Message:    extractErrorMessage(respBody),
			Body:       truncateStr(string(respBody), 1024),
		}
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response for %s %s: %w", method, path, err)
		}
	}
	return nil
}

func (c *Client) doRaw(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, int, error) {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, 0, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	sum := sha256.Sum256(body)
	bodyHex := hex.EncodeToString(sum[:])
	if err := SignRequest(req, c.secret, c.nodeName, bodyHex, c.now(), ""); err != nil {
		return nil, 0, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("hasyncd %s %s failed: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes+1))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read response for %s %s: %w", method, path, err)
	}
	if int64(len(respBody)) > maxResponseBodyBytes {
		return nil, resp.StatusCode, fmt.Errorf("response for %s %s exceeds size limit", method, path)
	}
	return respBody, resp.StatusCode, nil
}

func buildTLSConfig(serverName string, caPEM []byte, certSHA256 string, nowFn func() time.Time) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
	}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("invalid TLS CA PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if pin := strings.TrimSpace(certSHA256); pin != "" {
		normalized := strings.ToLower(strings.ReplaceAll(pin, ":", ""))
		if !isLowerHex64(normalized) {
			return nil, errors.New("invalid TLS certificate SHA-256 fingerprint (expect 64 hex chars)")
		}
		expectedDigest, _ := hex.DecodeString(normalized)
		if len(caPEM) == 0 {
			// Direct leaf-certificate SHA-256 pinning (e.g. self-signed peer cert without CA).
			tlsCfg.InsecureSkipVerify = true
			tlsCfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("peer presented no TLS certificate")
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("parse peer TLS certificate: %w", err)
				}
				now := nowFn().UTC()
				if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
					return errors.New("pinned peer TLS certificate is expired or not yet valid")
				}
				got := sha256.Sum256(rawCerts[0])
				if !hmac.Equal(got[:], expectedDigest) {
					return errors.New("peer TLS certificate SHA-256 fingerprint mismatch")
				}
				return nil
			}
		} else {
			// Both CA verification AND leaf-certificate SHA-256 pinning enforced.
			tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("peer presented no TLS certificate")
				}
				got := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if !hmac.Equal(got[:], expectedDigest) {
					return errors.New("peer TLS certificate SHA-256 fingerprint mismatch")
				}
				return nil
			}
		}
	}
	return tlsCfg, nil
}

func extractErrorMessage(body []byte) string {
	var env struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err == nil && strings.TrimSpace(env.Error) != "" {
		return env.Error
	}
	return truncateStr(strings.TrimSpace(string(body)), 512)
}

func truncateStr(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen] + "...(truncated)"
	}
	return s
}
