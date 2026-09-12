// storage.go 受控本地证据存储适配器（S0 契约 #5 / 任务书 §7.1：P0-01 服务端
// 受控存储不存在，由本任务提供双方共用的受控本地存储适配器，不引入外部服务）。
//
// 纪律：
//   - 对象 ID 由服务端生成（UUID），存储路径由 ID 派生，调用方不能指定路径；
//   - 写入仅经 Register（流式 sha256 + 类别限额 + 原子 rename），读取为只读
//     服务端接口（Open），不暴露任意路径/URL，无删除 API（保留期清理由运维
//     在文件层执行并须同步将引用报告标记证据不完整——见 store 层 gate 判定
//     对对象缺失的处理）；
//   - 目录权限 0700，文件 0444（登记后不可改写——原子 rename 只发生一次，
//     已登记对象重写等于篡改，直接拒绝）。
package regression

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// EvidenceObject 已登记对象元数据（数据库行镜像）。
type EvidenceObject struct {
	ID          uuid.UUID `json:"id"`
	Kind        string    `json:"kind"`
	SHA256      string    `json:"sha256"`
	SizeBytes   int64     `json:"size_bytes"`
	StoragePath string    `json:"-"`
	State       string    `json:"state"`
	UploadedBy  string    `json:"uploaded_by"`
	CreatedAt   string    `json:"created_at"`
}

// ObjectStore 受控对象元数据存取（*Store 实现；单测可注入 fake）。
type ObjectStore interface {
	InsertObject(ctx context.Context, obj EvidenceObject) error
	GetObject(ctx context.Context, id uuid.UUID) (*EvidenceObject, error)
}

// LocalEvidenceStore 受控本地存储适配器。
type LocalEvidenceStore struct {
	root string
	meta ObjectStore
}

// NewLocalEvidenceStore 创建适配器（root 不存在则按 0700 创建）。
func NewLocalEvidenceStore(root string, meta ObjectStore) (*LocalEvidenceStore, error) {
	if root == "" {
		return nil, fmt.Errorf("evidence store root required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create evidence store root: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("chmod evidence store root: %w", err)
	}
	return &LocalEvidenceStore{root: root, meta: meta}, nil
}

// pathFor 对象 ID 派生存储路径（两级前缀分片，避免单目录过大；ID 服务端生成，
// 调用方无法影响路径）。
func (s *LocalEvidenceStore) pathFor(id uuid.UUID) string {
	h := id.String()
	return filepath.Join(s.root, h[:2], h)
}

// Register 受控写入登记：流式哈希 + 类别限额（超限额即拒绝并清理临时文件），
// 临时文件 0600 写入校验后 0444 原子改名；元数据落库失败清理文件，不留半份。
// 返回登记完成的对象（sha256/size 由服务端计算，调用方无法声明）。
func (s *LocalEvidenceStore) Register(ctx context.Context, kind, uploadedBy string, r io.Reader) (*EvidenceObject, error) {
	if !ValidKind(kind) {
		return nil, fmt.Errorf("invalid object kind %q", kind)
	}
	id := uuid.New()
	final := s.pathFor(id)
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return nil, fmt.Errorf("create shard dir: %w", err)
	}
	tmp := final + ".tmp-" + uuid.NewString()
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create temp object: %w", err)
	}
	cleanup := func() { _ = os.Remove(tmp) }
	limit := kindLimit(kind)
	h := sha256.New()
	w := io.MultiWriter(f, h)
	// 限额+1 探测超限（流式，不全量读入内存）
	n, err := io.Copy(w, io.LimitReader(r, limit+1))
	if err != nil {
		_ = f.Close()
		cleanup()
		return nil, fmt.Errorf("write object: %w", err)
	}
	if n > limit {
		_ = f.Close()
		cleanup()
		return nil, fmt.Errorf("%w: kind %s limit %d bytes", ErrObjectLimit, kind, limit)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return nil, fmt.Errorf("close object: %w", err)
	}
	if err := os.Chmod(tmp, 0o444); err != nil {
		cleanup()
		return nil, fmt.Errorf("freeze object: %w", err)
	}
	if err := os.Rename(tmp, final); err != nil {
		cleanup()
		return nil, fmt.Errorf("commit object: %w", err)
	}
	rel, err := filepath.Rel(s.root, final)
	if err != nil {
		_ = os.Remove(final)
		return nil, err
	}
	obj := EvidenceObject{
		ID:          id,
		Kind:        kind,
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		SizeBytes:   n,
		StoragePath: rel,
		State:       ObjectRegistered,
		UploadedBy:  uploadedBy,
	}
	if s.meta != nil {
		if err := s.meta.InsertObject(ctx, obj); err != nil {
			_ = os.Remove(final)
			return nil, fmt.Errorf("register object metadata: %w", err)
		}
	}
	return &obj, nil
}

// Open 只读打开已登记对象（先校验登记状态与落盘哈希，再返回 Reader；
// 校验失败不返回任何内容——未知/越权对象 ID 不能泄露原始文件）。
// 返回 (reader, 元数据, 错误)；调用方负责 Close。
func (s *LocalEvidenceStore) Open(ctx context.Context, id uuid.UUID) (io.ReadCloser, *EvidenceObject, error) {
	if s.meta == nil {
		return nil, nil, fmt.Errorf("object metadata store not wired")
	}
	obj, err := s.meta.GetObject(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if obj.State != ObjectRegistered && obj.State != ObjectConsumed {
		return nil, nil, fmt.Errorf("%w: object %s state %s", ErrNotFound, id, obj.State)
	}
	full := filepath.Join(s.root, obj.StoragePath)
	// 防御路径越界：登记路径必须位于受控 root 内
	cleanRoot := filepath.Clean(s.root)
	cleanFull := filepath.Clean(full)
	if rel, err := filepath.Rel(cleanRoot, cleanFull); err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == "../" || filepath.IsAbs(rel) {
		return nil, nil, fmt.Errorf("evidence object path escapes store root")
	}
	// 先落盘哈希校验再返回内容
	sum, size, err := hashFile(full)
	if err != nil {
		return nil, nil, fmt.Errorf("read evidence object: %w", err)
	}
	if sum != obj.SHA256 || size != obj.SizeBytes {
		return nil, nil, fmt.Errorf("%w: stored content differs from registered hash", ErrHashMismatch)
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, nil, fmt.Errorf("open evidence object: %w", err)
	}
	return f, obj, nil
}

// ReadAll 只读读取并校验小对象（manifest/分块等限额内对象；PERF 大对象请用 Open 流式处理）。
func (s *LocalEvidenceStore) ReadAll(ctx context.Context, id uuid.UUID) ([]byte, *EvidenceObject, error) {
	rc, obj, err := s.Open(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, kindLimit(obj.Kind)+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > kindLimit(obj.Kind) {
		return nil, nil, fmt.Errorf("%w: kind %s", ErrObjectLimit, obj.Kind)
	}
	return data, obj, nil
}

// ObjectIntact 证据对象落盘完整性核对（存在 + 大小与登记一致；完整哈希校验在
// 导入与 Open 时执行，门禁路径只做廉价存在性核对）。实现 ObjectExistenceChecker。
func (s *LocalEvidenceStore) ObjectIntact(ctx context.Context, id uuid.UUID) (bool, error) {
	if s.meta == nil {
		return false, fmt.Errorf("object metadata store not wired")
	}
	obj, err := s.meta.GetObject(ctx, id)
	if err != nil {
		return false, err
	}
	full := filepath.Join(s.root, obj.StoragePath)
	cleanRoot := filepath.Clean(s.root)
	if rel, err := filepath.Rel(cleanRoot, filepath.Clean(full)); err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == "../" || filepath.IsAbs(rel) {
		return false, fmt.Errorf("evidence object path escapes store root")
	}
	st, err := os.Stat(full)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return st.Size() == obj.SizeBytes, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			return "", 0, fmt.Errorf("%w: %v", ErrNotFound, pe.Err)
		}
		return "", 0, err
	}
	defer f.Close()
	var h hash.Hash = sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}
