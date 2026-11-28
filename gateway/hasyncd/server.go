package hasyncd

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	packageFilenameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(\.tar\.gz|\.run)$`)
	uuidRE            = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	versionTokenRE    = regexp.MustCompile(`^[0-9A-Za-z._+-]{1,64}$`)
)

// Server is the HMAC-authenticated HA node sync HTTP(S) sidecar server.
type Server struct {
	cfg               Config
	auth              *Authenticator
	caddy             *localCaddyClient
	packagesDir       string
	executorDir       string
	rulesDir          string
	rulePackVerifyKey ed25519.PublicKey
	geoIPDir          string
	maxPkgBytes       int64
	maxRulePackBytes  int64
	maxGeoIPBytes     int64
	rulePackMu        sync.RWMutex
	geoIPMu           sync.RWMutex
	now               func() time.Time
	handler           http.Handler
}

// NewServer validates configuration in fail-closed mode and constructs a Server.
func NewServer(cfg Config) (*Server, error) {
	cfg.NodeName = strings.TrimSpace(cfg.NodeName)
	if cfg.NodeName == "" {
		return nil, errors.New("node name (--node / GATEWAY_NODE_NAME) is required")
	}
	if !isValidNodeHeader(cfg.NodeName) {
		return nil, fmt.Errorf("invalid node name %q", cfg.NodeName)
	}
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	if strings.TrimSpace(cfg.CaddySocket) == "" {
		cfg.CaddySocket = DefaultCaddySocket
	}
	if strings.TrimSpace(cfg.SidecarDir) == "" {
		cfg.SidecarDir = DefaultSidecarDir
	}
	if strings.TrimSpace(cfg.HostctlDir) == "" {
		cfg.HostctlDir = DefaultHostctlDir
	}
	if strings.TrimSpace(cfg.UpgradesDir) == "" {
		cfg.UpgradesDir = DefaultUpgradesDir
	}
	if strings.TrimSpace(cfg.NodeIfacesLog) == "" {
		cfg.NodeIfacesLog = DefaultNodeIfacesLog
	}
	if strings.TrimSpace(cfg.HealthStampPath) == "" {
		cfg.HealthStampPath = DefaultHealthStampPath
	}
	if cfg.HealthStampPeriod <= 0 {
		cfg.HealthStampPeriod = DefaultHealthStampInterval
	}
	if (strings.TrimSpace(cfg.TLSCertFile) == "") != (strings.TrimSpace(cfg.TLSKeyFile) == "") {
		return nil, errors.New("both --tls-cert and --tls-key must be set together")
	}

	var secret []byte
	var err error
	if len(cfg.SecretBytes) > 0 {
		if len(cfg.SecretBytes) < MinSecretBytes {
			return nil, fmt.Errorf("secret bytes must be at least %d bytes", MinSecretBytes)
		}
		secret = append([]byte(nil), cfg.SecretBytes...)
	} else {
		secret, err = LoadSecretFile(cfg.SecretFile)
		if err != nil {
			return nil, err
		}
	}

	nowFn := cfg.NowFunc
	if nowFn == nil {
		nowFn = time.Now
	}
	auth, err := NewAuthenticator(secret, cfg.MaxNonceEntries, nowFn)
	if err != nil {
		return nil, err
	}

	packagesDir := strings.TrimSpace(cfg.UpgradePackagesDir)
	if packagesDir == "" {
		packagesDir = filepath.Join(cfg.UpgradesDir, "packages")
	}
	executorDir := strings.TrimSpace(cfg.UpgradeExecutorDir)
	if executorDir == "" {
		executorDir = filepath.Join(cfg.UpgradesDir, "executor")
	}
	maxPkgBytes := cfg.MaxPackageBytes
	if maxPkgBytes <= 0 {
		maxPkgBytes = DefaultMaxPackageSize
	}
	geoIPDir := strings.TrimSpace(cfg.GeoIPDir)
	if geoIPDir != "" {
		geoIPDir = filepath.Clean(geoIPDir)
	}
	cfg.GeoIPDir = geoIPDir

	var rulePackKey ed25519.PublicKey
	if len(cfg.RulePackVerifyKey) > 0 {
		if len(cfg.RulePackVerifyKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid RulePackVerifyKey length %d", len(cfg.RulePackVerifyKey))
		}
		rulePackKey = append(ed25519.PublicKey(nil), cfg.RulePackVerifyKey...)
	} else {
		rulePackKey, err = ReleaseRulePackPublicKey()
		if err != nil {
			return nil, fmt.Errorf("load embedded rulepack public key: %w", err)
		}
	}

	rulesDir := strings.TrimSpace(cfg.RulesDir)
	if rulesDir != "" {
		rulesDir = filepath.Clean(rulesDir)
	}
	maxRulePackBytes := cfg.MaxRulePackBytes
	if maxRulePackBytes <= 0 || maxRulePackBytes > MaxRulePackArchiveBytes {
		maxRulePackBytes = MaxRulePackArchiveBytes
	}

	s := &Server{
		cfg:               cfg,
		auth:              auth,
		caddy:             newLocalCaddyClient(cfg.CaddySocket),
		packagesDir:       filepath.Clean(packagesDir),
		executorDir:       filepath.Clean(executorDir),
		rulesDir:          rulesDir,
		rulePackVerifyKey: rulePackKey,
		geoIPDir:          geoIPDir,
		maxPkgBytes:       maxPkgBytes,
		maxRulePackBytes:  maxRulePackBytes,
		maxGeoIPBytes:     cfg.MaxGeoIPBytes,
		now:               nowFn,
	}
	s.handler = s.buildHandler()
	return s, nil
}

// Handler returns the HTTP handler (all routes require HMAC-SHA256 authentication).
func (s *Server) Handler() http.Handler {
	return s.handler
}

// Run starts the HTTP(S) server, refreshes the local health stamp file periodically,
// and performs graceful shutdown when ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	actualAddr := ln.Addr().String()

	httpSrv := &http.Server{
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}

	if strings.TrimSpace(s.cfg.TLSCertFile) != "" {
		cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("load tls keypair: %w", err)
		}
		httpSrv.TLSConfig = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}
		ln = tls.NewListener(ln, httpSrv.TLSConfig)
	}

	writeStamp := func() {
		stamp := HealthStamp{
			PID:       os.Getpid(),
			Node:      s.cfg.NodeName,
			Listen:    actualAddr,
			Ready:     true,
			UpdatedAt: s.now().UTC(),
		}
		if err := WriteHealthStamp(s.cfg.HealthStampPath, stamp); err != nil {
			log.Printf("[hasyncd] WARN: write health stamp failed: %v", err)
		}
	}
	writeStamp()
	defer func() { _ = os.Remove(s.cfg.HealthStampPath) }()

	bgCtx, bgCancel := context.WithCancel(ctx)
	defer bgCancel()
	go func() {
		healthTicker := time.NewTicker(s.cfg.HealthStampPeriod)
		pruneTicker := time.NewTicker(30 * time.Second)
		defer healthTicker.Stop()
		defer pruneTicker.Stop()
		for {
			select {
			case <-bgCtx.Done():
				return
			case <-healthTicker.C:
				writeStamp()
			case <-pruneTicker.C:
				s.auth.PruneNonces()
			}
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("[hasyncd] listening on %s node=%s tls=%v", actualAddr, s.cfg.NodeName, httpSrv.TLSConfig != nil)
		if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		return <-errCh
	}
}

func (s *Server) buildHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")

		// Reject raw path traversal or double slashes before routing.
		if hasUnsafeRequestPath(r) {
			writeJSONError(w, http.StatusBadRequest, "unsafe request path")
			return
		}

		// ALL endpoints require HMAC-SHA256 authentication.
		authInfo, err := s.auth.VerifyHeaders(r)
		if err != nil {
			switch {
			case errors.Is(err, ErrNonceCacheFull):
				writeJSONError(w, http.StatusTooManyRequests, err.Error())
			default:
				writeJSONError(w, http.StatusUnauthorized, err.Error())
			}
			return
		}

		path := r.URL.Path
		switch {
		case path == "/v1/health":
			if r.Method != http.MethodGet {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleHealth(w, r, authInfo)
		case path == "/v1/status":
			if r.Method != http.MethodGet {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleStatus(w, r, authInfo)
		case path == "/v1/caddy/load":
			if r.Method != http.MethodPost {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleCaddyLoad(w, r, authInfo)
		case path == "/v1/caddy/config-hash":
			if r.Method != http.MethodGet {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleCaddyConfigHash(w, r, authInfo)
		case strings.HasPrefix(path, "/v1/sidecars/"):
			name := strings.TrimPrefix(path, "/v1/sidecars/")
			if name == "" || strings.Contains(name, "/") {
				writeJSONError(w, http.StatusBadRequest, "invalid sidecar name")
				return
			}
			switch r.Method {
			case http.MethodPut:
				s.handleSidecarPut(w, r, authInfo, name)
			case http.MethodDelete:
				s.handleSidecarDelete(w, r, authInfo, name)
			default:
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
		case path == "/v1/firewall/ensure":
			if r.Method != http.MethodPost {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleFirewallEnsure(w, r, authInfo)
		case path == "/v1/upgrades/packages":
			if r.Method != http.MethodPost {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleUpgradePackageUpload(w, r, authInfo)
		case path == "/v1/upgrades/execute":
			if r.Method != http.MethodPost {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleUpgradeExecute(w, r, authInfo)
		case strings.HasPrefix(path, "/v1/upgrades/jobs/"):
			jobID := strings.TrimPrefix(path, "/v1/upgrades/jobs/")
			if jobID == "" || strings.Contains(jobID, "/") {
				writeJSONError(w, http.StatusBadRequest, "invalid job_id")
				return
			}
			if r.Method != http.MethodGet {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleUpgradeJobResult(w, r, authInfo, jobID)
		case path == "/v1/rulepacks/stage":
			if r.Method != http.MethodPost {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleRulePackStage(w, r, authInfo)
		case path == "/v1/rulepacks/status":
			if r.Method != http.MethodGet {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleRulePackStatus(w, r, authInfo)
		case path == "/v1/rulepacks/activate":
			if r.Method != http.MethodPost {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleRulePackActivate(w, r, authInfo)
		case strings.HasPrefix(path, "/v1/rulepacks/releases/"):
			ver := strings.TrimPrefix(path, "/v1/rulepacks/releases/")
			if ver == "" || strings.Contains(ver, "/") {
				writeJSONError(w, http.StatusBadRequest, "invalid rulepack version")
				return
			}
			if r.Method != http.MethodDelete {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleRulePackDeleteRelease(w, r, authInfo, ver)
		case path == "/v1/geoip/status":
			if r.Method != http.MethodGet {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleGeoIPStatus(w, r, authInfo)
		case strings.HasPrefix(path, "/v1/geoip/slots/"):
			slot := strings.TrimPrefix(path, "/v1/geoip/slots/")
			if slot == "" || strings.Contains(slot, "/") {
				writeJSONError(w, http.StatusBadRequest, "invalid geoip slot")
				return
			}
			if r.Method != http.MethodPut {
				writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			s.handleGeoIPSlotPut(w, r, authInfo, slot)
		default:
			writeJSONError(w, http.StatusNotFound, "not found")
		}
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	if _, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, 1024); !ok {
		return
	}
	resp := HealthResponse{
		Node:           s.cfg.NodeName,
		Version:        resolveVersion(s.cfg.Version, s.cfg.VersionFile),
		CaddyReachable: s.caddy.Ping(r.Context()),
		HostctlReady:   checkHostctlReady(s.cfg.HostctlDir),
		UpgradeReady:   s.checkUpgradeReady(),
		RulePackReady:  s.checkRulePackReady(),
		Now:            s.now().UTC(),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	if _, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, 1024); !ok {
		return
	}
	var (
		caddyReachable bool
		configHash     string
		policyVersion  string
	)
	if cfgBytes, err := s.caddy.GetConfig(r.Context()); err == nil {
		if hash, herr := CanonicalBusinessConfigHash(cfgBytes); herr == nil {
			caddyReachable = true
			configHash = hash
			policyVersion = ExtractPolicyVersion(cfgBytes)
		}
	}

	haVipStatus, haVipMtime := readStatusJSONWithMtime(filepath.Join(s.cfg.SidecarDir, haVipStatusFileName))
	netStatus, netMtime := readStatusJSONWithMtime(filepath.Join(s.cfg.SidecarDir, networkStatusFileName))
	ifaces := readInterfacesTail(s.cfg.NodeIfacesLog)

	resp := StatusResponse{
		Node:               s.cfg.NodeName,
		Version:            resolveVersion(s.cfg.Version, s.cfg.VersionFile),
		PolicyVersion:      policyVersion,
		ConfigHash:         configHash,
		CaddyReachable:     caddyReachable,
		HaVipStatus:        haVipStatus,
		HaVipStatusMtime:   haVipMtime,
		NetworkStatus:      netStatus,
		NetworkStatusMtime: netMtime,
		Interfaces:         ifaces,
		CollectedAt:        s.now().UTC(),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCaddyLoad(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	body, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, MaxCaddyLoadBytes)
	if !ok {
		return
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid caddy config JSON object")
		return
	}
	caddyStatus, errMsg, err := s.caddy.LoadConfig(r.Context(), body)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, CaddyLoadResponse{
			OK:          false,
			CaddyStatus: caddyStatus,
			Error:       sanitizeCaddyError([]byte(err.Error())),
		})
		return
	}
	if caddyStatus != http.StatusOK {
		httpStatus := http.StatusBadGateway
		if caddyStatus >= 400 && caddyStatus < 500 {
			httpStatus = http.StatusBadRequest
		}
		writeJSON(w, httpStatus, CaddyLoadResponse{
			OK:          false,
			CaddyStatus: caddyStatus,
			Error:       errMsg,
		})
		return
	}
	writeJSON(w, http.StatusOK, CaddyLoadResponse{
		OK:          true,
		CaddyStatus: caddyStatus,
	})
}

func (s *Server) handleCaddyConfigHash(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	if _, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, 1024); !ok {
		return
	}
	cfgBytes, err := s.caddy.GetConfig(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, sanitizeCaddyError([]byte(err.Error())))
		return
	}
	hash, err := CanonicalBusinessConfigHash(cfgBytes)
	if err != nil {
		writeJSONError(w, http.StatusBadGateway, "invalid caddy config json")
		return
	}
	writeJSON(w, http.StatusOK, CaddyConfigHashResponse{
		ConfigHash:    hash,
		PolicyVersion: ExtractPolicyVersion(cfgBytes),
	})
}

func (s *Server) handleSidecarPut(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth, name string) {
	mode, allowed := AllowedSidecarMode(name)
	if !allowed {
		writeJSONError(w, http.StatusBadRequest, "sidecar file not in allowlist")
		return
	}
	body, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, MaxSidecarBytes)
	if !ok {
		return
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		writeJSONError(w, http.StatusBadRequest, "sidecar payload must be a valid JSON object")
		return
	}
	if err := checkNotSymlinkIfExists(s.cfg.SidecarDir); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "sidecar directory unsafe")
		return
	}
	createdSidecarDir := false
	if _, err := os.Lstat(s.cfg.SidecarDir); errors.Is(err, fs.ErrNotExist) {
		createdSidecarDir = true
	}
	if err := os.MkdirAll(s.cfg.SidecarDir, 0o770); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to prepare sidecar directory")
		return
	}
	if createdSidecarDir {
		if err := os.Chmod(s.cfg.SidecarDir, 0o770); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to chmod sidecar directory")
			return
		}
	} else if fi, err := os.Lstat(s.cfg.SidecarDir); err == nil && fi.Mode().Perm() != 0o770 {
		_ = os.Chmod(s.cfg.SidecarDir, 0o770)
	}
	targetPath := filepath.Join(s.cfg.SidecarDir, name)
	if err := checkNotSymlinkIfExists(targetPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "sidecar target path unsafe")
		return
	}
	if err := writeBytesAtomic(s.cfg.SidecarDir, targetPath, "."+name+".*", body, mode); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("write sidecar failed: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, SidecarWriteResponse{
		OK:     true,
		Name:   name,
		Size:   len(body),
		SHA256: authInfo.BodySHA256,
	})
}

func (s *Server) handleSidecarDelete(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth, name string) {
	if _, allowed := AllowedSidecarMode(name); !allowed {
		writeJSONError(w, http.StatusBadRequest, "sidecar file not in allowlist")
		return
	}
	if _, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, 1024); !ok {
		return
	}
	if err := checkNotSymlinkIfExists(s.cfg.SidecarDir); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "sidecar directory unsafe")
		return
	}
	targetPath := filepath.Join(s.cfg.SidecarDir, name)
	fi, err := os.Lstat(targetPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeJSON(w, http.StatusOK, SidecarDeleteResponse{
				OK:      true,
				Name:    name,
				Deleted: false,
			})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "stat sidecar file failed")
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		writeJSONError(w, http.StatusInternalServerError, "sidecar target path unsafe")
		return
	}
	if err := os.Remove(targetPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		writeJSONError(w, http.StatusInternalServerError, "remove sidecar file failed")
		return
	}
	writeJSON(w, http.StatusOK, SidecarDeleteResponse{
		OK:      true,
		Name:    name,
		Deleted: true,
	})
}

func (s *Server) handleFirewallEnsure(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	body, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, MaxJSONControlBytes)
	if !ok {
		return
	}
	var req FirewallEnsureRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid firewall ensure JSON")
		return
	}
	if len(req.Ports) == 0 {
		writeJSONError(w, http.StatusBadRequest, "ports must not be empty")
		return
	}
	if len(req.Ports) > MaxFirewallPorts {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("too many firewall ports (max %d)", MaxFirewallPorts))
		return
	}
	for _, p := range req.Ports {
		if p < 1 || p > 65535 {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid port %d (must be 1..65535)", p))
			return
		}
	}
	if req.RequestID != "" && !isSafeHostctlSegment(strings.TrimSpace(req.RequestID)) {
		writeJSONError(w, http.StatusBadRequest, "invalid request_id")
		return
	}
	if !isSafeHostctlTextField(strings.TrimSpace(req.RequestedBy)) || !isSafeHostctlTextField(strings.TrimSpace(req.UserID)) {
		writeJSONError(w, http.StatusBadRequest, "invalid requested_by or user_id")
		return
	}

	finalPath, reqID, ports, err := writeFirewallEnsureFlag(
		s.cfg.HostctlDir, req.Ports, req.RequestID, req.RequestedBy, req.UserID, s.now().UTC(),
	)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, fmt.Sprintf("write hostctl firewall flag failed: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, FirewallEnsureResponse{
		OK:        true,
		File:      filepath.Base(finalPath),
		Ports:     ports,
		RequestID: reqID,
	})
}

func (s *Server) handleUpgradePackageUpload(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	filename := strings.TrimSpace(r.Header.Get(HeaderPackageFilename))
	if err := ValidatePackageFilename(filename); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if pkgSHA := strings.TrimSpace(r.Header.Get(HeaderPackageSHA256)); pkgSHA != "" {
		if !isValidHexToken(pkgSHA, 64, 64, true) || !hmac.Equal([]byte(pkgSHA), []byte(authInfo.BodySHA256)) {
			writeJSONError(w, http.StatusBadRequest, "X-JZ-Package-SHA256 does not match X-JZ-Body-SHA256")
			return
		}
	}

	// Extend deadlines for multi-gigabyte streaming uploads, restoring on return.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(30 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Minute))
	defer func() {
		_ = rc.SetReadDeadline(time.Now().Add(30 * time.Second))
		_ = rc.SetWriteDeadline(time.Now().Add(60 * time.Second))
	}()

	if err := ensureSafeDir(s.packagesDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("prepare packages dir failed: %v", err))
		return
	}
	finalPath := filepath.Join(s.packagesDir, filename)
	if err := checkNotSymlinkIfExists(finalPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "package target path unsafe")
		return
	}

	tmp, err := os.CreateTemp(s.packagesDir, ".pkg-upload-*.tmp")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "create temp package file failed")
		return
	}
	tmpName := tmp.Name()
	cleaned := false
	cleanup := func() {
		if !cleaned {
			cleaned = true
			_ = os.Remove(tmpName)
		}
	}
	defer cleanup()

	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		writeJSONError(w, http.StatusInternalServerError, "chmod temp package failed")
		return
	}

	hasher := sha256.New()
	limited := io.LimitReader(r.Body, s.maxPkgBytes+1)
	written, err := io.Copy(tmp, io.TeeReader(limited, hasher))
	if err != nil {
		_ = tmp.Close()
		writeJSONError(w, http.StatusBadRequest, "read package stream failed")
		return
	}
	if written > s.maxPkgBytes {
		_ = tmp.Close()
		writeJSONError(w, http.StatusRequestEntityTooLarge, "upgrade package exceeds maximum allowed size")
		return
	}
	if written == 0 {
		_ = tmp.Close()
		writeJSONError(w, http.StatusBadRequest, "upgrade package body is empty")
		return
	}

	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if !hmac.Equal([]byte(actualSHA), []byte(authInfo.BodySHA256)) {
		_ = tmp.Close()
		writeJSONError(w, http.StatusUnauthorized, "body sha256 mismatch")
		return
	}

	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		writeJSONError(w, http.StatusInternalServerError, "fsync package failed")
		return
	}
	if err := tmp.Close(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "close package failed")
		return
	}
	if err := checkNotSymlinkIfExists(finalPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "package target path unsafe")
		return
	}
	if err := os.Rename(tmpName, finalPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "commit package file failed")
		return
	}
	cleaned = true

	writeJSON(w, http.StatusOK, UpgradePackageUploadResponse{
		OK:       true,
		Filename: filename,
		Size:     written,
		SHA256:   actualSHA,
	})
}

func (s *Server) handleUpgradeExecute(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth) {
	body, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, MaxJSONControlBytes)
	if !ok {
		return
	}
	var req UpgradeExecuteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid upgrade execute JSON")
		return
	}
	jobID, err := ValidateUUID(req.JobID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ValidatePackageFilename(req.PackageFile); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	pkgSHA := strings.ToLower(strings.TrimSpace(req.PackageSHA256))
	if !isValidHexToken(pkgSHA, 64, 64, true) {
		writeJSONError(w, http.StatusBadRequest, "invalid package_sha256")
		return
	}
	req.VersionFrom = strings.TrimSpace(req.VersionFrom)
	req.VersionTo = strings.TrimSpace(req.VersionTo)
	if !versionTokenRE.MatchString(req.VersionFrom) || !versionTokenRE.MatchString(req.VersionTo) {
		writeJSONError(w, http.StatusBadRequest, "invalid version_from or version_to")
		return
	}
	if req.RequestedAt.IsZero() {
		req.RequestedAt = s.now().UTC()
	} else {
		req.RequestedAt = req.RequestedAt.UTC()
	}
	req.JobID = jobID
	req.PackageSHA256 = pkgSHA

	pkgPath := filepath.Join(s.packagesDir, req.PackageFile)
	pfi, err := os.Lstat(pkgPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeJSONError(w, http.StatusNotFound, "upgrade package file not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "stat upgrade package failed")
		return
	}
	if pfi.Mode()&os.ModeSymlink != 0 || !pfi.Mode().IsRegular() {
		writeJSONError(w, http.StatusBadRequest, "upgrade package path is not a regular file")
		return
	}
	actualSHA, err := computeFileSHA256(pkgPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "hash upgrade package failed")
		return
	}
	if !hmac.Equal([]byte(actualSHA), []byte(pkgSHA)) {
		writeJSONError(w, http.StatusBadRequest, "upgrade package sha256 mismatch")
		return
	}

	jobsDir := filepath.Join(s.executorDir, "jobs")
	if err := ensureSafeDir(jobsDir, 0o750); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("prepare executor jobs dir failed: %v", err))
		return
	}
	jobPath := filepath.Join(jobsDir, jobID+".json")
	if err := checkNotSymlinkIfExists(jobPath); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "executor job path unsafe")
		return
	}
	payload, err := json.Marshal(req)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "marshal executor request failed")
		return
	}
	if err := writeBytesAtomic(jobsDir, jobPath, ".job-*.tmp", payload, 0o640); err != nil {
		writeJSONError(w, http.StatusInternalServerError, fmt.Sprintf("write executor job failed: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, UpgradeExecuteResponse{
		OK:     true,
		JobID:  jobID,
		Status: "QUEUED",
	})
}

func (s *Server) handleUpgradeJobResult(w http.ResponseWriter, r *http.Request, authInfo VerifiedAuth, rawJobID string) {
	if _, ok := readAndVerifyBody(w, r, authInfo.BodySHA256, 1024); !ok {
		return
	}
	jobID, err := ValidateUUID(rawJobID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	resultPath := filepath.Join(s.executorDir, "results", jobID+".json")
	fi, err := os.Lstat(resultPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeJSON(w, http.StatusOK, UpgradeJobResult{
				Pending: true,
				JobID:   jobID,
			})
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "stat executor result failed")
		return
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() {
		writeJSONError(w, http.StatusInternalServerError, "executor result path unsafe")
		return
	}
	f, err := os.Open(resultPath)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "open executor result failed")
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxJSONControlBytes+1))
	if err != nil || int64(len(raw)) > MaxJSONControlBytes {
		writeJSONError(w, http.StatusInternalServerError, "read executor result failed")
		return
	}
	var res UpgradeJobResult
	if err := json.Unmarshal(raw, &res); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "parse executor result failed")
		return
	}
	if strings.ToLower(strings.TrimSpace(res.JobID)) != jobID {
		writeJSONError(w, http.StatusInternalServerError, "executor result job_id mismatch")
		return
	}
	if res.Status != "SUCCESS" && res.Status != "FAILED" {
		writeJSONError(w, http.StatusInternalServerError, "executor result status invalid")
		return
	}
	res.Pending = false
	res.JobID = jobID
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) checkUpgradeReady() bool {
	if s.packagesDir == "" || s.executorDir == "" {
		return false
	}
	pkgOK := checkNonSymlinkDir(s.packagesDir) == nil
	execOK := checkNonSymlinkDir(s.executorDir) == nil
	if pkgOK && execOK {
		return true
	}
	// If subdirs haven't been created yet, accept an existing non-symlink UpgradesDir parent
	// provided neither subdir is a symlink or non-directory.
	if s.cfg.UpgradesDir != "" && checkNonSymlinkDir(s.cfg.UpgradesDir) == nil {
		return isMissingOrSafeDir(s.packagesDir) && isMissingOrSafeDir(s.executorDir)
	}
	return false
}

// ValidatePackageFilename enforces strict safe upgrade package filenames
// matching [A-Za-z0-9][A-Za-z0-9._-]*(.tar.gz|.run) with no slashes or "..".
func ValidatePackageFilename(name string) error {
	if name == "" || len(name) > 255 {
		return errors.New("package filename must be 1..255 characters")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return errors.New("package filename contains unsafe path characters")
	}
	if filepath.Base(name) != name {
		return errors.New("package filename must not contain path separators")
	}
	if !packageFilenameRE.MatchString(name) {
		return errors.New("package filename must match [A-Za-z0-9][A-Za-z0-9._-]*(.tar.gz|.run)")
	}
	return nil
}

// ValidateUUID validates a standard UUID string and returns its lowercase canonical form.
func ValidateUUID(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if !uuidRE.MatchString(trimmed) {
		return "", errors.New("invalid UUID job_id")
	}
	return strings.ToLower(trimmed), nil
}

func readAndVerifyBody(w http.ResponseWriter, r *http.Request, expectedSHA256 string, maxBytes int64) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return nil, false
	}
	if int64(len(body)) > maxBytes {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "request body exceeds maximum size")
		return nil, false
	}
	if !VerifyBodySHA256(body, expectedSHA256) {
		writeJSONError(w, http.StatusUnauthorized, "body sha256 mismatch")
		return nil, false
	}
	return body, true
}

func hasUnsafeRequestPath(r *http.Request) bool {
	for _, p := range []string{r.URL.Path, r.URL.RawPath} {
		if p == "" {
			continue
		}
		if strings.Contains(p, "//") || strings.Contains(p, "\\") || strings.Contains(p, "..") {
			return true
		}
		for i := 0; i < len(p); i++ {
			if p[i] < 0x20 || p[i] == 0x7f {
				return true
			}
		}
	}
	return false
}

func writeBytesAtomic(dir, targetPath, tmpPattern string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, tmpPattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, targetPath)
}

func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func checkNonSymlinkDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("path must not be a symlink")
	}
	if !fi.IsDir() {
		return errors.New("path must be a directory")
	}
	return nil
}

func isMissingOrSafeDir(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	return fi.Mode()&os.ModeSymlink == 0 && fi.IsDir()
}

func checkNotSymlinkIfExists(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("target path must not be a symlink")
	}
	return nil
}

func ensureSafeDir(dir string, mode os.FileMode) error {
	if err := checkNotSymlinkIfExists(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return err
	}
	return checkNonSymlinkDir(dir)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}
