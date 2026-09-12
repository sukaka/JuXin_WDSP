// upload.go 升级包上传：multipart 流式落盘 + 服务端自算 SHA-256/大小 + 登记。
package upgrades

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// DefaultMaxPackageBytes 升级包上传大小上限默认值（4GiB；离线包实测 175MB~563MB）。
const DefaultMaxPackageBytes int64 = 4 << 30

// multipartFormOverhead multipart 表单字段开销上限（version/manifest 等字段）。
const multipartFormOverhead int64 = 1 << 20

// SetUploadDir 配置升级包存储目录与上传大小上限；目录不存在时创建（0o750）。
// dir 为空时上传接口不可用（返回 503）。
func (h *Handler) SetUploadDir(dir string, maxBytes int64) *Handler {
	if dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			// 装配期失败不静默：上传接口届时报错，此处仅尽力创建
			dir = ""
		}
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPackageBytes
	}
	h.packagesDir = dir
	h.maxUploadBytes = maxBytes
	return h
}

// UploadPackage POST /api/v1/upgrades/packages/upload：multipart 上传升级包，
// 服务端落盘并自算 SHA-256/大小后登记（字段：file、signature、version_from、version_to 必需，
// signature 为整包 detached Ed25519 签名的 base64，manifest 可选 JSON 字符串）。
// 只有固定信任根、签名和归档 manifest 全部验证通过才登记为 VERIFIED。
// 权限：upgrades.execute。
func (h *Handler) UploadPackage(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if h.packagesDir == "" {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "升级包上传目录未配置")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxUploadBytes+multipartFormOverhead)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("请求格式错误或文件超过大小限制（%d 字节）", h.maxUploadBytes))
		return
	}
	signatureText := strings.TrimSpace(r.FormValue("signature"))
	if signatureText == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"缺少升级包签名（multipart 字段名 signature，base64 Ed25519）")
		return
	}
	signature, err := base64.StdEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != ed25519.SignatureSize {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "升级包签名格式无效")
		return
	}
	f, header, err := r.FormFile("file")
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少升级包文件（multipart 字段名 file）")
		return
	}
	defer func() { _ = f.Close() }()

	fileName := filepath.Base(strings.TrimSpace(header.Filename))
	if fileName == "" || fileName == "." || len(fileName) > 255 || strings.ContainsRune(fileName, 0) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "文件名无效（不允许为空、路径分隔符或超过255字符）")
		return
	}

	// 磁盘余量预检（Content-Length 含表单开销，作保守下界）
	if r.ContentLength > 0 {
		if free := DiskFreeBytes(h.packagesDir); free >= 0 && free < r.ContentLength {
			response.Error(w, r, http.StatusInsufficientStorage, response.CodeInvalidArgument, "服务端磁盘空间不足，无法接收升级包")
			return
		}
	}

	// 流式写入临时文件，同步计算 SHA-256 与字节数
	tmp, err := os.CreateTemp(h.packagesDir, ".upload-*")
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	hw := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(tmp, hw), f)
	closeErr := tmp.Close()
	if copyErr != nil || closeErr != nil {
		cleanup()
		var mbErr *http.MaxBytesError
		if errors.As(copyErr, &mbErr) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("文件超过大小限制（%d 字节）", h.maxUploadBytes))
			return
		}
		response.InternalError(w, r, firstErr(copyErr, closeErr))
		return
	}
	if size == 0 {
		cleanup()
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "升级包文件内容为空")
		return
	}
	if size > h.maxUploadBytes {
		cleanup()
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("文件超过大小限制（%d 字节）", h.maxUploadBytes))
		return
	}
	hash := hex.EncodeToString(hw.Sum(nil))
	target := filepath.Join(h.packagesDir, fileName)

	// 同名文件处理（按目标文件名互斥串行化，防同名并发上传 TOCTOU 竞态互相覆盖）：
	// 已存在且内容一致则复用，不一致则冲突，不存在则 rename 落盘
	if err := h.finalizeUpload(target, tmpPath, hash); err != nil {
		cleanup()
		if errors.Is(err, errUploadNameConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
				"同名升级包文件已存在且内容不同，请更换文件名或先清理服务端目录")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := writeSignatureSidecar(target, signature); err != nil {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"升级包签名旁车文件无法安全登记："+err.Error())
		return
	}

	// 同哈希去重：已登记过则拒绝（保留已写文件供排查）
	if existing, err := h.store.FindPackageByHash(r.Context(), hash); err == nil {
		h.recordAudit(r, p, "upload_package", existing.ID.String(), fileName, audits.ResultFailure, audits.RiskMedium, "相同哈希的升级包已登记")
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			fmt.Sprintf("相同哈希的升级包已登记（%s，%s → %s）", existing.FileName, existing.VersionFrom, existing.VersionTo))
		return
	} else if !errors.Is(err, ErrNotFound) {
		response.InternalError(w, r, err)
		return
	}

	var manifest json.RawMessage
	if raw := strings.TrimSpace(r.FormValue("manifest")); raw != "" {
		manifest = json.RawMessage(raw)
	}
	req := &registerPackageRequest{
		FileName:    fileName,
		VersionFrom: r.FormValue("version_from"),
		VersionTo:   r.FormValue("version_to"),
		FileHash:    hash,
		FileSize:    size,
		Manifest:    manifest,
	}
	pkg, validationErr := buildPackage(req, p.UserID)
	if validationErr == nil {
		if h.artifactVerifier == nil {
			validationErr = errors.New("升级包验签器未配置")
		} else if err := h.artifactVerifier(target, pkg); err != nil {
			validationErr = fmt.Errorf("升级包签名或归档内容验证失败: %w", err)
		} else {
			pkg.Status = PackageVerified
		}
	}
	if err := h.store.CreatePackage(r.Context(), pkg); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if validationErr != nil {
		// 登记信息不自洽：删除已落盘文件，仅保留 REJECTED 登记记录作证据
		_ = os.Remove(target)
		_ = os.Remove(target + ".sig")
		h.recordAudit(r, p, "upload_package", pkg.ID.String(), pkg.FileName, audits.ResultFailure, audits.RiskMedium, validationErr.Error())
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"package": pkg,
			"message": "升级包校验未通过，已登记为 REJECTED：" + validationErr.Error(),
		})
		return
	}
	h.recordAudit(r, p, "upload_package", pkg.ID.String(), pkg.FileName, audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"package": pkg})
}

// writeSignatureSidecar 以 O_EXCL 创建旁车签名，避免并发上传覆盖既有签名。
// 同一文件与同一签名可幂等复用；不同签名一律冲突。
func writeSignatureSidecar(path string, signature []byte) error {
	if len(signature) != ed25519.SignatureSize {
		return errors.New("签名长度无效")
	}
	sidecar := path + ".sig"
	encoded := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
	f, err := os.OpenFile(sidecar, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, writeErr := f.Write(encoded); writeErr != nil {
			_ = f.Close()
			_ = os.Remove(sidecar)
			return writeErr
		}
		if syncErr := f.Sync(); syncErr != nil {
			_ = f.Close()
			_ = os.Remove(sidecar)
			return syncErr
		}
		return f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	existing, readErr := os.ReadFile(sidecar)
	if readErr != nil {
		return readErr
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(existing)))
	if decodeErr != nil || !bytes.Equal(decoded, signature) {
		return errors.New("已存在不同的签名")
	}
	return nil
}

// errUploadNameConflict 同名升级包文件已存在且内容不同（finalizeUpload 返回，映射 409）。
var errUploadNameConflict = errors.New("upload name conflict")

// finalizeUpload 同名冲突判定与原子落盘，在按目标文件名互斥的临界区内执行
// （审查 LOW-S14：同名并发上传 check-then-rename 存在 TOCTOU 竞态，可能互相覆盖
// 导致登记哈希与最终落盘文件不符；进程内串行化后冲突方如实返回 409）。
// 目标存在且哈希一致→复用现有文件（删除临时文件）；不存在→rename 落盘；
// 存在且哈希不同→errUploadNameConflict；其余 stat 错误如实返回。
func (h *Handler) finalizeUpload(target, tmpPath, hash string) error {
	mu := h.uploadLock(target)
	mu.Lock()
	defer mu.Unlock()
	existingHash, _, statErr := hashFileStreaming(target)
	switch {
	case statErr == nil:
		if existingHash != hash {
			return errUploadNameConflict
		}
		return os.Remove(tmpPath) // 内容一致，复用现有文件
	case os.IsNotExist(statErr):
		return os.Rename(tmpPath, target)
	default:
		return statErr
	}
}

// hashFileStreaming 流式计算文件 SHA-256 与大小。
func hashFileStreaming(path string) (string, int64, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	hw := sha256.New()
	size, err := io.Copy(hw, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hw.Sum(nil)), size, nil
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return errors.New("unknown error")
}
