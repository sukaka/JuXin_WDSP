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
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// DefaultMaxPackageBytes 升级包上传大小上限默认值（4GiB；离线包实测 175MB~563MB）。
const DefaultMaxPackageBytes int64 = 4 << 30

// DefaultUploadTimeout 单次升级包上传的读写期限；不扩大其他接口的默认 30 秒限制。
const DefaultUploadTimeout = 10 * time.Minute

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
// 服务端落盘并自算 SHA-256/大小后登记。
// 表单字段：仅 file 必填；signature/version_from/version_to/manifest/scheduled_at 全部可选。
//   - 验签：包内含 manifest.sig（对包内 manifest.json 原始字节的 Ed25519 签名）时使用内嵌验签；
//     无内嵌签名时回落旧行为，要求 multipart signature（对整包字节的 detached 签名）。
//   - 版本：优先取包内 manifest.json 的 version_from/version_to（执行器协议字段）；
//     表单同名字段与包内不一致返回 400；旧格式包（无版本字段）须由表单提供。
//   - target_schema_version：优先取包内 manifest.json，表单 manifest 字段可覆盖。
//   - scheduled_at：可选定时执行时间（RFC3339 且必须带时区，now+2 分钟 ~ now+90 天，
//     非法 400）；不传则 VERIFIED 后立即自动执行，传了则创建 SCHEDULED 定时任务到点自动开始。
//
// 只有固定信任根、签名和归档 manifest 全部验证通过才登记为 VERIFIED；
// VERIFIED 后自动创建升级执行（等同 POST /api/v1/upgrades），创建失败时包保持
// VERIFIED 并以 warning 说明可手动执行。权限：upgrades.execute。
func (h *Handler) UploadPackage(w http.ResponseWriter, r *http.Request) {
	controller := http.NewResponseController(w)
	defer func() {
		_ = controller.SetReadDeadline(time.Time{})
		_ = controller.SetWriteDeadline(time.Time{})
	}()
	if err := controller.SetReadDeadline(time.Now().Add(h.uploadTimeout)); err != nil {
		slog.Error("upgrade upload read deadline unsupported", "error", err)
		response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError, "当前环境不支持上传期限控制")
		return
	}
	if err := controller.SetWriteDeadline(time.Now().Add(h.uploadTimeout)); err != nil {
		slog.Error("upgrade upload write deadline unsupported", "error", err)
		response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError, "当前环境不支持上传期限控制")
		return
	}
	p := authz.PrincipalFrom(r.Context())
	if h.packagesDir == "" {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "升级包上传目录未配置")
		return
	}
	if h.registrar == nil {
		response.InternalError(w, r, errors.New("升级包登记存储未配置"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, h.maxUploadBytes+multipartFormOverhead)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("请求格式错误或文件超过大小限制（%d 字节）", h.maxUploadBytes))
		return
	}
	// signature 可选：包内无 manifest.sig 时必填（下文判定）；提供时必须格式合法
	signatureText := strings.TrimSpace(r.FormValue("signature"))
	var signature []byte
	if signatureText != "" {
		sig, err := base64.StdEncoding.DecodeString(signatureText)
		if err != nil || len(sig) != ed25519.SignatureSize {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "升级包签名格式无效")
			return
		}
		signature = sig
	}
	formVersionFrom := strings.TrimSpace(r.FormValue("version_from"))
	formVersionTo := strings.TrimSpace(r.FormValue("version_to"))
	formManifest := strings.TrimSpace(r.FormValue("manifest"))
	// scheduled_at 可选：空串 = 不传（VERIFIED 后立即自动执行）；
	// 传了则校验 RFC3339（必须带时区）与时间窗（now+2 分钟 ~ now+90 天），非法 400
	var scheduledAt *time.Time
	if text := strings.TrimSpace(r.FormValue("scheduled_at")); text != "" {
		t, err := ParseScheduledAt(text, time.Now())
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		scheduledAt = &t
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

	// 包内 manifest 解析（不替代信任边界验签；不可解析时按旧格式处理，
	// 登记阶段的 artifactVerifier 会如实 REJECT）
	info, _ := readPackageManifestInfoFile(tmpPath)

	// 版本来源：包内 manifest 优先；表单与包内交叉校验，不一致 400
	versionFrom, versionTo, versionErr := resolveUploadVersions(formVersionFrom, formVersionTo, info)
	if versionErr != nil {
		cleanup()
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, versionErr.Error())
		return
	}

	// 验签模式：包内含 manifest.sig → 内嵌验签；否则回落旧行为（必须提供 multipart signature）
	embedded := info != nil && info.hasEmbeddedSig
	if !embedded && len(signature) == 0 {
		cleanup()
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"缺少升级包签名：包内无 manifest.sig 时须通过 multipart 字段 signature 提供整包 detached Ed25519 签名（base64）")
		return
	}

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
	if !embedded && len(signature) > 0 {
		if err := writeSignatureSidecar(target, signature); err != nil {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
				"升级包签名旁车文件无法安全登记："+err.Error())
			return
		}
	}

	// 同哈希去重：已登记过则拒绝（保留已写文件供排查）
	if existing, err := h.registrar.FindPackageByHash(r.Context(), hash); err == nil {
		h.recordAudit(r, p, "upload_package", existing.ID.String(), fileName, audits.ResultFailure, audits.RiskMedium, "相同哈希的升级包已登记")
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			fmt.Sprintf("相同哈希的升级包已登记（%s，%s → %s）", existing.FileName, existing.VersionFrom, existing.VersionTo))
		return
	} else if !errors.Is(err, ErrNotFound) {
		response.InternalError(w, r, err)
		return
	}

	req := &registerPackageRequest{
		FileName:    fileName,
		VersionFrom: versionFrom,
		VersionTo:   versionTo,
		FileHash:    hash,
		FileSize:    size,
		Manifest:    mergeStoredManifest(info, formManifest),
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
	if validationErr != nil {
		// 校验/验签失败一律以 REJECTED 落库留证（与响应文案一致）
		pkg.Status = PackageRejected
	}
	if err := h.registrar.CreatePackage(r.Context(), pkg); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if validationErr != nil {
		// 登记信息不自洽或验签失败：删除已落盘文件，仅保留 REJECTED 登记记录作证据
		_ = os.Remove(target)
		_ = os.Remove(target + ".sig")
		slog.Error("upgrade package validation failed",
			"package_id", pkg.ID, "file_name", pkg.FileName, "error", validationErr)
		h.recordAudit(r, p, "upload_package", pkg.ID.String(), pkg.FileName, audits.ResultFailure, audits.RiskHigh, validationErr.Error())
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"package": pkg,
			"message": "升级包校验未通过，已登记为 REJECTED：" + validationErr.Error(),
		})
		return
	}
	h.recordAudit(r, p, "upload_package", pkg.ID.String(), pkg.FileName, audits.ResultSuccess, audits.RiskMedium, "")

	// 验证通过自动创建升级执行（等同 POST /api/v1/upgrades）；指定 scheduled_at 时
	// 创建定时任务（SCHEDULED，到点自动开始），否则立即执行。
	// 创建失败不影响登记结果：包保持 VERIFIED，warning 说明可手动执行。
	resp := map[string]interface{}{"package": pkg}
	action := "auto_execute"
	var job *Job
	var execErr error
	if scheduledAt != nil {
		action = "schedule"
		job, execErr = h.autoSchedule(r, p, pkg, *scheduledAt)
	} else {
		job, execErr = h.autoExecute(r, p, pkg)
	}
	if execErr != nil {
		slog.Error("auto create upgrade execution failed",
			"package_id", pkg.ID, "file_name", pkg.FileName, "action", action, "error", execErr)
		h.recordAudit(r, p, action, pkg.ID.String(), pkg.FileName, audits.ResultFailure, audits.RiskHigh, execErr.Error())
		resp["execution"] = nil
		resp["warning"] = "升级包已验证通过并登记为 VERIFIED，但自动创建升级执行失败：" + execErr.Error() +
			"；可通过 POST /api/v1/upgrades 手动执行"
	} else {
		h.recordAudit(r, p, action, job.ID.String(), pkg.FileName, audits.ResultSuccess, audits.RiskHigh, "")
		resp["execution"] = job
	}
	response.JSON(w, r, http.StatusOK, resp)
}

// autoExecute 通过升级服务创建执行（与 Execute 接口同一入口）。
func (h *Handler) autoExecute(r *http.Request, p *authz.Principal, pkg *Package) (*Job, error) {
	if h.executor == nil {
		return nil, errors.New("升级执行服务未配置")
	}
	return h.executor.Execute(r.Context(), pkg.ID, p.UserID, response.RequestIDFrom(r))
}

// autoSchedule 通过升级服务创建定时执行（SCHEDULED，到点由调度器自动开始）。
func (h *Handler) autoSchedule(r *http.Request, p *authz.Principal, pkg *Package, scheduledAt time.Time) (*Job, error) {
	if h.executor == nil {
		return nil, errors.New("升级执行服务未配置")
	}
	return h.executor.Schedule(r.Context(), pkg.ID, p.UserID, response.RequestIDFrom(r), scheduledAt)
}

// resolveUploadVersions 解析登记版本号：包内 manifest 的 version_from/version_to 优先；
// 表单字段与包内不一致时报错；旧格式包（无版本字段）须由表单提供。
func resolveUploadVersions(formFrom, formTo string, info *packageManifestInfo) (string, string, error) {
	from, to := formFrom, formTo
	if info != nil {
		if info.versionFrom != "" {
			if formFrom != "" && formFrom != info.versionFrom {
				return "", "", fmt.Errorf("表单 version_from（%s）与包内 manifest（%s）不一致", formFrom, info.versionFrom)
			}
			from = info.versionFrom
		}
		if info.versionTo != "" {
			if formTo != "" && formTo != info.versionTo {
				return "", "", fmt.Errorf("表单 version_to（%s）与包内 manifest（%s）不一致", formTo, info.versionTo)
			}
			to = info.versionTo
		}
	}
	if from == "" || to == "" {
		return "", "", errors.New("缺少版本信息：包内 manifest 未声明 version_from/version_to 时须通过表单提供 version_from 与 version_to")
	}
	return from, to, nil
}

// mergeStoredManifest 计算登记的 manifest：优先包内 manifest.json 原始字节；
// 表单 manifest 字段可覆盖 target_schema_version；包内不可解析时沿用表单值。
func mergeStoredManifest(info *packageManifestInfo, formManifest string) json.RawMessage {
	var base []byte
	if info != nil {
		base = info.raw
	}
	if formManifest == "" {
		return base
	}
	if len(base) == 0 {
		return json.RawMessage(formManifest)
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return json.RawMessage(formManifest)
	}
	var override map[string]json.RawMessage
	if err := json.Unmarshal([]byte(formManifest), &override); err != nil {
		// 非法表单 manifest 原样下传，由 buildPackage 如实拒绝
		return json.RawMessage(formManifest)
	}
	if v, ok := override["target_schema_version"]; ok {
		merged["target_schema_version"] = v
	}
	out, err := json.Marshal(merged)
	if err != nil {
		return json.RawMessage(formManifest)
	}
	return out
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
