// packages.go 跨平台 Agent 安装包安全分发与机器引导端点（跨平台契约 §5）。
//
// 安全红线：
//   - 严禁匿名暴露安装包与安装脚本：
//     * 管理端（/api/v1/traffic/agents/packages*）走既有会话 + RBAC（traffic.agents.view）；
//     * 机器引导端（/api/v1/agents/bootstrap/*）强制要求 Authorization: Bearer wdt_<64hex>
//       指向 ACTIVE 状态的 Enrollment Token（只读校验不消耗，enroll 成功才原子消耗；
//       严禁接受 URL Query 中的 token）；
//   - 严格防路径穿越与符号链接：仅按白名单 (os, arch, format) 查 manifest.json 索引，
//     并逐项通过 os.Lstat 校验目标位于配置根目录内且为常规文件、大小匹配；
//   - 安装脚本通过 go:embed 内嵌自仓库受控源，响应附带 X-WDSP-SHA256 与 Cache-Control: no-store。
package agents

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

//go:embed scripts/install-agent.sh scripts/install-agent.ps1
var embeddedBootstrapScripts embed.FS

// EnrollmentTokenChecker 只读校验一次性注册令牌是否处于 ACTIVE 状态（不消耗令牌）。
type EnrollmentTokenChecker interface {
	IsEnrollmentTokenActive(ctx context.Context, tokenHash string, now time.Time) (bool, error)
}

// PackageItem manifest.json 单条安装包描述。
type PackageItem struct {
	OS       string `json:"os"`
	Distro   string `json:"distro"`
	Arch     string `json:"arch"`
	Format   string `json:"format"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	SHA256   string `json:"sha256"`
}

// PackageManifest 安装包目录清单（manifest.json）。
type PackageManifest struct {
	Version  string        `json:"version"`
	BuiltAt  string        `json:"built_at"`
	Packages []PackageItem `json:"packages"`
}

// PackagesResponse 管理端 GET /api/v1/traffic/agents/packages 响应体。
type PackagesResponse struct {
	Available bool          `json:"available"`
	Version   string        `json:"version"`
	BuiltAt   string        `json:"built_at"`
	Packages  []PackageItem `json:"packages"`
}

var (
	safePkgFilenamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sha256HexPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

const maxManifestBytes = 1 << 20

func validPackageOS(v string) bool {
	return v == "linux" || v == "darwin" || v == "windows"
}

func validPackageArch(v string) bool {
	return v == "amd64" || v == "arm64"
}

func validPackageFormat(v string) bool {
	switch v {
	case "rpm", "deb", "pkg", "targz", "zip":
		return true
	default:
		return false
	}
}

// PackageStore 安全读取挂载目录中的多平台 Agent 安装包清单与文件。
type PackageStore struct {
	dir string
}

// NewPackageStore 创建安装包仓库（dir 为空时永远返回不可用）。
func NewPackageStore(dir string) *PackageStore {
	return &PackageStore{dir: strings.TrimSpace(dir)}
}

// LoadManifest 读取并逐项复核 manifest.json；目录缺失/无有效清单返回 (nil, false)。
func (s *PackageStore) LoadManifest() (*PackageManifest, bool) {
	if s == nil || s.dir == "" {
		return nil, false
	}
	dirInfo, err := os.Lstat(s.dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, false
	}
	manifestPath := filepath.Join(s.dir, "manifest.json")
	mInfo, err := os.Lstat(manifestPath)
	if err != nil || !mInfo.Mode().IsRegular() || mInfo.Size() > maxManifestBytes {
		return nil, false
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, false
	}
	var m PackageManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		slog.Warn("traffic agent packages manifest parse failed", "path", manifestPath, "err", err)
		return nil, false
	}
	valid := make([]PackageItem, 0, len(m.Packages))
	for _, item := range m.Packages {
		item.OS = strings.ToLower(strings.TrimSpace(item.OS))
		item.Distro = strings.ToLower(strings.TrimSpace(item.Distro))
		item.Arch = strings.ToLower(strings.TrimSpace(item.Arch))
		item.Format = strings.ToLower(strings.TrimSpace(item.Format))
		item.SHA256 = strings.ToLower(strings.TrimSpace(item.SHA256))
		if !validPackageOS(item.OS) || !validPackageArch(item.Arch) || !validPackageFormat(item.Format) {
			continue
		}
		if !safePkgFilenamePattern.MatchString(item.Filename) || filepath.Base(item.Filename) != item.Filename {
			continue
		}
		if !sha256HexPattern.MatchString(item.SHA256) || item.Size <= 0 {
			continue
		}
		fullPath, ok := s.safeRegularFile(item.Filename, item.Size)
		if !ok || fullPath == "" {
			continue
		}
		valid = append(valid, item)
	}
	m.Packages = valid
	return &m, len(valid) > 0
}

func (s *PackageStore) safeRegularFile(filename string, expectedSize int64) (string, bool) {
	if !safePkgFilenamePattern.MatchString(filename) || filepath.Base(filename) != filename {
		return "", false
	}
	cleanDir := filepath.Clean(s.dir)
	full := filepath.Join(cleanDir, filename)
	if filepath.Dir(full) != cleanDir {
		return "", false
	}
	fi, err := os.Lstat(full)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&os.ModeSymlink != 0 {
		return "", false
	}
	if expectedSize > 0 && fi.Size() != expectedSize {
		return "", false
	}
	return full, true
}

// Resolve 查找目标平台安装包，返回清单项与安全绝对路径。
func (s *PackageStore) Resolve(osName, arch, format string) (PackageItem, string, error) {
	if !validPackageOS(osName) || !validPackageArch(arch) || !validPackageFormat(format) {
		return PackageItem{}, "", ErrInvalidPackageQuery
	}
	m, ok := s.LoadManifest()
	if !ok {
		return PackageItem{}, "", ErrPackageNotFound
	}
	for _, item := range m.Packages {
		if item.OS == osName && item.Arch == arch && item.Format == format {
			full, exists := s.safeRegularFile(item.Filename, item.Size)
			if !exists {
				return PackageItem{}, "", ErrPackageNotFound
			}
			return item, full, nil
		}
	}
	return PackageItem{}, "", ErrPackageNotFound
}

var (
	ErrInvalidPackageQuery = errors.New("invalid agent package parameters")
	ErrPackageNotFound     = errors.New("agent package not found")
)

func servePackageFile(w http.ResponseWriter, r *http.Request, item PackageItem, fullPath string) error {
	f, err := os.Open(fullPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return ErrPackageNotFound
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, item.Filename))
	w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	w.Header().Set("X-WDSP-SHA256", item.SHA256)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, f)
	}
	return nil
}

// ---------- 管理端接口（会话 + RBAC：traffic.agents.view） ----------

// SetPackageDir 配置跨平台 Agent 安装包目录。
func (h *Handler) SetPackageDir(dir string) *Handler {
	h.pkgStore = NewPackageStore(dir)
	return h
}

// ListPackages GET /api/v1/traffic/agents/packages：返回服务端已部署的跨平台安装包清单。
func (h *Handler) ListPackages(w http.ResponseWriter, r *http.Request) {
	m, ok := h.pkgStore.LoadManifest()
	if !ok || m == nil {
		response.JSON(w, r, http.StatusOK, PackagesResponse{
			Available: false,
			Packages:  []PackageItem{},
		})
		return
	}
	response.JSON(w, r, http.StatusOK, PackagesResponse{
		Available: true,
		Version:   m.Version,
		BuiltAt:   m.BuiltAt,
		Packages:  m.Packages,
	})
}

// DownloadPackage GET /api/v1/traffic/agents/packages/{os}/{arch}/{format}：管理端离线包直链下载。
func (h *Handler) DownloadPackage(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	osName := strings.ToLower(strings.TrimSpace(r.PathValue("os")))
	arch := strings.ToLower(strings.TrimSpace(r.PathValue("arch")))
	format := strings.ToLower(strings.TrimSpace(r.PathValue("format")))
	item, fullPath, err := h.pkgStore.Resolve(osName, arch, format)
	if err != nil {
		if errors.Is(err, ErrInvalidPackageQuery) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "非法的平台/架构/格式参数")
			return
		}
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "目标平台安装包不可用")
		return
	}
	detailJSON, _ := json.Marshal(map[string]any{
		"os":     item.OS,
		"arch":   item.Arch,
		"format": item.Format,
		"sha256": item.SHA256,
	})
	h.recordAudit(r, p, "download", "agent_package", item.Filename, item.Filename,
		"", string(detailJSON), audits.ResultSuccess, audits.RiskLow)
	if err := servePackageFile(w, r, item, fullPath); err != nil {
		h.adminInternal(w, r, err)
	}
}

// ---------- 机器引导端点（ACTIVE Enrollment Token Header 只读鉴权，不消耗 Token） ----------

// SetPackageDir 配置跨平台 Agent 安装包目录。
func (h *MachineHandler) SetPackageDir(dir string) *MachineHandler {
	h.pkgStore = NewPackageStore(dir)
	return h
}

// SetEnrollmentTokenChecker 注入只读令牌校验器（默认自动使用 h.store）。
func (h *MachineHandler) SetEnrollmentTokenChecker(c EnrollmentTokenChecker) *MachineHandler {
	h.tokenChecker = c
	return h
}

func (h *MachineHandler) enrollmentTokenChecker() EnrollmentTokenChecker {
	if h.tokenChecker != nil {
		return h.tokenChecker
	}
	if c, ok := h.store.(EnrollmentTokenChecker); ok {
		return c
	}
	return nil
}

// authenticateBootstrapToken 校验 Authorization: Bearer wdt_<64hex> 指向 ACTIVE 注册令牌。
// 只读校验不消耗令牌；严禁接受 URL Query 中的令牌。
func (h *MachineHandler) authenticateBootstrapToken(w http.ResponseWriter, r *http.Request) bool {
	// 明确拒绝将令牌放在 URL query 中（防止进入代理/访问日志）
	if r.URL.Query().Get("token") != "" || r.URL.Query().Get("enrollment_token") != "" {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "禁止通过 URL 参数传递注册令牌，请使用 Authorization: Bearer 请求头")
		return false
	}
	authzHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authzHeader, "Bearer ") {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "缺少有效的注册令牌认证头")
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(authzHeader, "Bearer "))
	if !enrollmentTokenPattern.MatchString(token) {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "注册令牌无效、已过期、已使用或已撤销")
		return false
	}
	checker := h.enrollmentTokenChecker()
	if checker == nil {
		machineInternal(w, r, errors.New("enrollment token checker is not configured"))
		return false
	}
	active, err := checker.IsEnrollmentTokenActive(r.Context(), HashSecret(token), h.now())
	if err != nil {
		machineInternal(w, r, err)
		return false
	}
	if !active {
		machineError(w, http.StatusUnauthorized, mcUnauthenticated, "注册令牌无效、已过期、已使用或已撤销")
		return false
	}
	return true
}

// BootstrapManifest GET /api/v1/agents/bootstrap/manifest：返回安装包清单（需 ACTIVE 注册令牌）。
func (h *MachineHandler) BootstrapManifest(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateBootstrapToken(w, r) {
		return
	}
	m, ok := h.pkgStore.LoadManifest()
	if !ok || m == nil {
		machineError(w, http.StatusNotFound, mcNotFound, "服务端尚未挂载跨平台 Agent 安装包")
		return
	}
	machineJSON(w, http.StatusOK, m)
}

// BootstrapScript GET /api/v1/agents/bootstrap/script/{os}：返回平台受控安装脚本（需 ACTIVE 注册令牌）。
func (h *MachineHandler) BootstrapScript(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateBootstrapToken(w, r) {
		return
	}
	osName := strings.ToLower(strings.TrimSpace(r.PathValue("os")))
	var embedPath, filename string
	switch osName {
	case "linux", "darwin":
		embedPath = "scripts/install-agent.sh"
		filename = "install-agent.sh"
	case "windows":
		embedPath = "scripts/install-agent.ps1"
		filename = "install-agent.ps1"
	default:
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "os 须为 linux/darwin/windows 之一")
		return
	}
	data, err := embeddedBootstrapScripts.ReadFile(embedPath)
	if err != nil {
		machineInternal(w, r, err)
		return
	}
	sum := sha256.Sum256(data)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, filename))
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.Header().Set("X-WDSP-SHA256", hex.EncodeToString(sum[:]))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(data)
	}
}

// BootstrapPackage GET /api/v1/agents/bootstrap/packages/{os}/{arch}/{format}：流式分发安装包（需 ACTIVE 注册令牌）。
func (h *MachineHandler) BootstrapPackage(w http.ResponseWriter, r *http.Request) {
	if !h.authenticateBootstrapToken(w, r) {
		return
	}
	osName := strings.ToLower(strings.TrimSpace(r.PathValue("os")))
	arch := strings.ToLower(strings.TrimSpace(r.PathValue("arch")))
	format := strings.ToLower(strings.TrimSpace(r.PathValue("format")))
	item, fullPath, err := h.pkgStore.Resolve(osName, arch, format)
	if err != nil {
		if errors.Is(err, ErrInvalidPackageQuery) {
			machineError(w, http.StatusBadRequest, mcInvalidArgument, "非法的平台/架构/格式参数")
			return
		}
		machineError(w, http.StatusNotFound, mcNotFound, "目标平台安装包不可用")
		return
	}
	if err := servePackageFile(w, r, item, fullPath); err != nil {
		machineInternal(w, r, err)
	}
}
