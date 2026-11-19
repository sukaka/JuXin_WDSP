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

// multipartFormOverhead multipart 表单字段开销上限（version/manifest 等字段）。
const multipartFormOverhead int64 = 1 << 20

// maxFormFieldBytes 单个非文件表单字段大小上限。
const maxFormFieldBytes int64 = 64 << 10

// maxConcurrentUploads 同时允许的升级包上传并发上限，避免并发大包写满磁盘。
const maxConcurrentUploads = 2

// defaultDiskCheckInterval 流式上传期间周期复检磁盘剩余空间的字节步长（16MiB）。
const defaultDiskCheckInterval int64 = 16 << 20

// minStreamFreeBytes 流式落盘时保留的最低磁盘余量（16MiB），防止写满磁盘。
const minStreamFreeBytes int64 = 16 << 20

// uploadRequestTimeout 仅覆盖升级包上传请求的读写期限，避免全局 30 秒超时中断大文件上传。
const uploadRequestTimeout = 10 * time.Minute

// defaultConnDeadline 上传响应完成后恢复到正常有界期限，避免 keep-alive 连接保持 10 分钟长超时。
const defaultConnDeadline = 30 * time.Second

func extendUploadRequestDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(uploadRequestTimeout)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
}

func restoreUploadRequestDeadlines(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(defaultConnDeadline)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
}

func validatePackageFileName(name string) error {
	if name == "" || len(name) > 255 {
		return errors.New("文件名不能为空且不超过255字符")
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return errors.New("文件名不允许包含路径分隔符")
	}
	if name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return errors.New("文件名不允许以点号开头或为特殊目录名")
	}
	if strings.HasSuffix(strings.ToLower(name), ".sig") {
		return errors.New("文件名不允许以 .sig 结尾")
	}
	return nil
}

func (h *Handler) acquireUploadSlot() (func(), bool) {
	h.uploadSemOnce.Do(func() {
		if h.uploadSem == nil {
			h.uploadSem = make(chan struct{}, maxConcurrentUploads)
		}
	})
	select {
	case h.uploadSem <- struct{}{}:
		return func() { <-h.uploadSem }, true
	default:
		return nil, false
	}
}

func (h *Handler) diskFree(dir string) int64 {
	if h.diskFreeFn != nil {
		return h.diskFreeFn(dir)
	}
	return DiskFreeBytes(dir)
}

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

// UploadPackage POST /api/v1/upgrades/packages/upload：multipart 流式上传升级包，
// 服务端直接流式落盘到 packagesDir 临时目录并自算 SHA-256/大小后验签登记。
// 表单字段：仅 file 必填；signature/version_from/version_to/manifest/scheduled_at 全部可选。
//   - 验签：包内含 manifest.sig（对包内 manifest.json 原始字节的 Ed25519 签名）时使用内嵌验签；
//     无内嵌签名时回落旧行为，要求 multipart signature（对整包字节的 detached 签名）。
//   - 版本：优先取包内 manifest.json 的 version_from/version_to（执行器协议字段）；
//     表单同名字段与包内不一致返回 400；旧格式包（无版本字段）须由表单提供。
//   - target_schema_version：优先取包内 manifest.json，表单 manifest 字段可覆盖。
//   - scheduled_at：可选定时执行时间（RFC3339 且必须带时区，now+2 分钟 ~ now+90 天，
//     非法 400）；不传则 VERIFIED 后立即自动执行，传了则创建 SCHEDULED 定时任务到点自动开始。
//
// 只有固定信任根、签名和归档 manifest 全部在临时文件上验证通过后才原子移入目标路径并登记为 VERIFIED；
// VERIFIED 后自动创建升级执行（等同 POST /api/v1/upgrades），创建失败时包保持
// VERIFIED 并以 warning 说明可手动执行。权限：upgrades.execute。
func (h *Handler) UploadPackage(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if h.packagesDir == "" {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "升级包上传目录未配置")
		return
	}
	if h.registrar == nil {
		response.InternalError(w, r, errors.New("升级包登记存储未配置"))
		return
	}
	releaseSlot, ok := h.acquireUploadSlot()
	if !ok {
		w.Header().Set("Retry-After", "5")
		response.Error(w, r, http.StatusTooManyRequests, response.CodeRateLimited, "当前并发上传任务数已达上限，请稍后重试")
		return
	}
	defer releaseSlot()

	extendUploadRequestDeadlines(w)
	defer restoreUploadRequestDeadlines(w)

	maxUpload := h.maxUploadBytes
	if maxUpload <= 0 {
		maxUpload = DefaultMaxPackageBytes
	}

	// 磁盘余量预检（Content-Length 含表单开销，作保守下界；未知长度时检查最低保留余量）
	if free := h.diskFree(h.packagesDir); free >= 0 {
		if (r.ContentLength > 0 && free < r.ContentLength) || free < minStreamFreeBytes {
			response.Error(w, r, http.StatusInsufficientStorage, response.CodeInvalidArgument, "服务端磁盘空间不足，无法接收升级包")
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUpload+multipartFormOverhead)
	mr, err := r.MultipartReader()
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			fmt.Sprintf("请求格式错误或文件超过大小限制（%d 字节）", maxUpload))
		return
	}

	var (
		signatureText   string
		formVersionFrom string
		formVersionTo   string
		formManifest    string
		scheduledAtText string
		formBytesRead   int64

		hasFile    bool
		fileName   string
		stageDir   string
		stagedPath string
		hash       string
		size       int64
	)
	defer func() {
		if stageDir != "" {
			_ = os.RemoveAll(stageDir)
		}
	}()

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var mbErr *http.MaxBytesError
			if errors.As(err, &mbErr) {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					fmt.Sprintf("文件超过大小限制（%d 字节）", maxUpload))
				return
			}
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "multipart 请求格式错误")
			return
		}
		name := part.FormName()
		if name != "file" {
			raw, readErr := io.ReadAll(io.LimitReader(part, maxFormFieldBytes+1))
			_ = part.Close()
			if readErr != nil {
				var mbErr *http.MaxBytesError
				if errors.As(readErr, &mbErr) {
					response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
						fmt.Sprintf("文件超过大小限制（%d 字节）", maxUpload))
					return
				}
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "读取表单字段失败")
				return
			}
			if int64(len(raw)) > maxFormFieldBytes {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "表单字段超出大小限制")
				return
			}
			formBytesRead += int64(len(raw))
			if formBytesRead > multipartFormOverhead {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "表单字段总大小超出限制")
				return
			}
			val := strings.TrimSpace(string(raw))
			switch name {
			case "signature":
				signatureText = val
			case "version_from":
				formVersionFrom = val
			case "version_to":
				formVersionTo = val
			case "manifest":
				formManifest = val
			case "scheduled_at":
				scheduledAtText = val
			}
			continue
		}

		if hasFile {
			_ = part.Close()
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅允许上传单个升级包文件")
			return
		}
		hasFile = true
		fileName = strings.TrimSpace(part.FileName())
		if err := validatePackageFileName(fileName); err != nil {
			_ = part.Close()
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "文件名无效："+err.Error())
			return
		}

		stageDir, err = os.MkdirTemp(h.packagesDir, ".upload-*")
		if err != nil {
			_ = part.Close()
			response.InternalError(w, r, err)
			return
		}
		stagedPath = filepath.Join(stageDir, fileName)
		stagedFile, err := os.OpenFile(stagedPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			_ = part.Close()
			response.InternalError(w, r, err)
			return
		}

		var streamErr error
		size, hash, streamErr = h.streamUploadFile(stagedFile, part, maxUpload)
		closeErr := stagedFile.Close()
		_ = part.Close()
		if streamErr != nil || closeErr != nil {
			cause := firstErr(streamErr, closeErr)
			var mbErr *http.MaxBytesError
			switch {
			case errors.Is(cause, errUploadTooLarge), errors.As(cause, &mbErr):
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					fmt.Sprintf("文件超过大小限制（%d 字节）", maxUpload))
			case errors.Is(cause, errUploadDiskFull):
				response.Error(w, r, http.StatusInsufficientStorage, response.CodeInvalidArgument, "服务端磁盘空间不足，上传已中止")
			default:
				response.InternalError(w, r, cause)
			}
			return
		}
	}

	if !hasFile {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少升级包文件（multipart 字段名 file）")
		return
	}
	if size == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "升级包文件内容为空")
		return
	}

	// signature 可选：包内无 manifest.sig 时必填（下文判定）；提供时必须格式合法
	var signature []byte
	if signatureText != "" {
		sig, err := base64.StdEncoding.DecodeString(signatureText)
		if err != nil || len(sig) != ed25519.SignatureSize {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "升级包签名格式无效")
			return
		}
		signature = sig
	}

	// scheduled_at 可选：空串 = 不传（VERIFIED 后立即自动执行）；
	// 传了则校验 RFC3339（必须带时区）与时间窗（now+2 分钟 ~ now+90 天），非法 400
	var scheduledAt *time.Time
	if scheduledAtText != "" {
		t, err := ParseScheduledAt(scheduledAtText, time.Now())
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		scheduledAt = &t
	}

	// 包内 manifest 解析（不替代信任边界验签；不可解析时按旧格式处理，
	// 登记阶段的 artifactVerifier 会如实 REJECT）
	info, _ := readPackageManifestInfoFile(stagedPath)

	// 版本来源：包内 manifest 优先；表单与包内交叉校验，不一致 400
	versionFrom, versionTo, versionErr := resolveUploadVersions(formVersionFrom, formVersionTo, info)
	if versionErr != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, versionErr.Error())
		return
	}

	// 验签模式：包内含 manifest.sig → 内嵌验签；否则回落旧行为（必须提供 multipart signature）
	embedded := info != nil && info.hasEmbeddedSig
	if !embedded && len(signature) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"缺少升级包签名：包内无 manifest.sig 时须通过 multipart 字段 signature 提供整包 detached Ed25519 签名（base64）")
		return
	}
	if !embedded && len(signature) > 0 {
		if _, err := writeSignatureSidecarTracked(stagedPath, signature); err != nil {
			response.InternalError(w, r, err)
			return
		}
	}

	req := &registerPackageRequest{
		FileName:    fileName,
		VersionFrom: versionFrom,
		VersionTo:   versionTo,
		FileHash:    hash,
		FileSize:    size,
		Manifest:    mergeStoredManifest(info, formManifest),
	}

	target := filepath.Join(h.packagesDir, fileName)
	mu := h.uploadLock(target)
	mu.Lock()
	locked := true
	unlock := func() {
		if locked {
			locked = false
			mu.Unlock()
		}
	}
	defer unlock()

	// 同哈希去重：已 VERIFIED 登记过则拒绝（临时目录由 defer 清理，不留孤儿文件）
	if existing, err := h.registrar.FindPackageByHash(r.Context(), hash); err == nil {
		h.recordAudit(r, p, "upload_package", existing.ID.String(), fileName, audits.ResultFailure, audits.RiskMedium, "相同哈希的升级包已登记")
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			fmt.Sprintf("相同哈希的升级包已登记（%s，%s → %s）", existing.FileName, existing.VersionFrom, existing.VersionTo))
		return
	} else if !errors.Is(err, ErrNotFound) {
		response.InternalError(w, r, err)
		return
	}

	// 检查目标文件名冲突（仍在锁内、移动前检查，不触碰已有文件）
	reusedTarget := false
	existingHash, _, statErr := hashFileStreaming(target)
	switch {
	case statErr == nil:
		if existingHash != hash {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
				"同名升级包文件已存在且内容不同，请更换文件名或先清理服务端目录")
			return
		}
		reusedTarget = true
	case os.IsNotExist(statErr):
	default:
		response.InternalError(w, r, statErr)
		return
	}
	reusedSig := false
	if !embedded && len(signature) > 0 {
		existingSig, err := readExistingSignature(target + ".sig")
		if err != nil {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
				"升级包签名旁车文件无法安全登记："+err.Error())
			return
		}
		if existingSig != nil {
			if !bytes.Equal(existingSig, signature) {
				response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
					"升级包签名旁车文件无法安全登记：已存在不同的签名")
				return
			}
			reusedSig = true
		}
	}

	// 在临时文件上完成全部校验与验签，绝不在移入目标路径前/失败时删除已有 target
	pkg, validationErr := buildPackage(req, p.UserID)
	if validationErr == nil {
		if h.artifactVerifier == nil {
			validationErr = errors.New("升级包验签器未配置")
		} else if err := h.artifactVerifier(stagedPath, pkg); err != nil {
			validationErr = fmt.Errorf("升级包签名或归档内容验证失败: %w", err)
		} else {
			pkg.Status = PackageVerified
		}
	}
	if validationErr != nil {
		// 校验/验签失败一律以 REJECTED 落库留证；临时文件由 defer 清理，绝不删除已有 target
		pkg.Status = PackageRejected
		if err := h.registrar.CreatePackage(r.Context(), pkg); err != nil {
			response.InternalError(w, r, err)
			return
		}
		slog.Error("upgrade package validation failed",
			"package_id", pkg.ID, "file_name", pkg.FileName, "error", validationErr)
		h.recordAudit(r, p, "upload_package", pkg.ID.String(), pkg.FileName, audits.ResultFailure, audits.RiskHigh, validationErr.Error())
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"package": pkg,
			"message": "升级包校验未通过，已登记为 REJECTED：" + validationErr.Error(),
		})
		return
	}

	// 校验全部通过后才原子移入目标路径并登记 VERIFIED
	movedTarget := false
	movedSig := false
	rollbackMoved := func() {
		if movedSig {
			_ = os.Remove(target + ".sig")
		}
		if movedTarget {
			_ = os.Remove(target)
		}
	}
	if !reusedTarget {
		if err := os.Rename(stagedPath, target); err != nil {
			response.InternalError(w, r, err)
			return
		}
		movedTarget = true
	}
	if !embedded && len(signature) > 0 && !reusedSig {
		if err := os.Rename(stagedPath+".sig", target+".sig"); err != nil {
			rollbackMoved()
			response.InternalError(w, r, err)
			return
		}
		movedSig = true
	}
	if err := h.registrar.CreatePackage(r.Context(), pkg); err != nil {
		rollbackMoved()
		response.InternalError(w, r, err)
		return
	}
	unlock()

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

var (
	errUploadTooLarge = errors.New("upload file exceeds maximum size")
	errUploadDiskFull = errors.New("insufficient disk space during upload")
)

func (h *Handler) streamUploadFile(dst *os.File, src io.Reader, maxBytes int64) (int64, string, error) {
	checkInterval := h.diskCheckInterval
	if checkInterval <= 0 {
		checkInterval = defaultDiskCheckInterval
	}
	hw := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	var sinceCheck int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxBytes {
				return total, "", errUploadTooLarge
			}
			chunk := buf[:n]
			if _, werr := dst.Write(chunk); werr != nil {
				return total, "", werr
			}
			hw.Write(chunk)
			sinceCheck += int64(n)
			if sinceCheck >= checkInterval {
				sinceCheck = 0
				if free := h.diskFree(h.packagesDir); free >= 0 && free < minStreamFreeBytes {
					return total, "", errUploadDiskFull
				}
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return total, "", rerr
		}
	}
	if err := dst.Sync(); err != nil {
		return total, "", err
	}
	return total, hex.EncodeToString(hw.Sum(nil)), nil
}

func readExistingSignature(sidecar string) ([]byte, error) {
	raw, err := os.ReadFile(sidecar)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("已存在格式非法的签名")
	}
	return decoded, nil
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
	_, err := writeSignatureSidecarTracked(path, signature)
	return err
}

func writeSignatureSidecarTracked(path string, signature []byte) (bool, error) {
	if len(signature) != ed25519.SignatureSize {
		return false, errors.New("签名长度无效")
	}
	sidecar := path + ".sig"
	encoded := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
	f, err := os.OpenFile(sidecar, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if _, writeErr := f.Write(encoded); writeErr != nil {
			_ = f.Close()
			_ = os.Remove(sidecar)
			return false, writeErr
		}
		if syncErr := f.Sync(); syncErr != nil {
			_ = f.Close()
			_ = os.Remove(sidecar)
			return false, syncErr
		}
		return true, f.Close()
	}
	if !errors.Is(err, os.ErrExist) {
		return false, err
	}
	existing, readErr := os.ReadFile(sidecar)
	if readErr != nil {
		return false, readErr
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(existing)))
	if decodeErr != nil || !bytes.Equal(decoded, signature) {
		return false, errors.New("已存在不同的签名")
	}
	return false, nil
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
