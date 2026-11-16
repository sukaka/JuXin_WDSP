// fileobs.go 文件传输观测入库（P1-04 文件资产采集通路）。
// 事件 JSONL 中的 file_observations → UPSERT api_file_assets
// （去重键 endpoint_key×direction×filename×identity_fingerprint，见迁移 000061）。
//
// 脱敏与归一纪律：
//   - 观测包含元数据、敏感类型标签及完整内容指纹（content_sha256）；截断/流式内容不生成指纹，正文不经由此通路；
//   - client_ip 按掩码纪律落库（IPv4 /24、IPv6 /64 前缀；精确关联走事件来源指纹）；
//   - sensitive_types 为扩展名高置信分类与内容检测数据类型标签的并集，不含匹配值。
package apiruntime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FileObservation 采集端镜像（与网关 dsctx.FileObservation JSON 字段一致）。
// 旧版网关事件无 file_observations 键，json 缺省解析为 nil，全程容忍缺失。
type FileObservation struct {
	Direction      string   `json:"direction"`
	FileName       string   `json:"filename"`
	Extension      string   `json:"extension"`
	MIME           string   `json:"mime"`
	Size           int64    `json:"size"`
	ContentSHA256  string   `json:"content_sha256,omitempty"`
	SensitiveTypes []string `json:"sensitive_types,omitempty"`
}

// 文件观测列宽（迁移 000061：filename VARCHAR(128)、extension VARCHAR(16)、mime VARCHAR(128)）。
// 网关提取期已截断；采集端再截断一次兜底（旧版/异常网关直送超长值的防御）。
const (
	maxFileObsNameLen = 128
	maxFileObsExtLen  = 16
	maxFileObsMIMELen = 128
)

// sensitiveFileTypeByExt 敏感文件扩展名词表 v1（§106 敏感文件统计的判定来源之一）。
// 仅按后缀启发式粗分类，词表保守只收高置信类别：凭据材料 / 数据库备份 / 数据导出；
// 内容级类型由显式 file 位置的值级规则提供，统一经 mergeFileSensitivity 合并。
var sensitiveFileTypeByExt = map[string]string{
	"pem":  "credential_file",
	"key":  "credential_file",
	"p12":  "credential_file",
	"pfx":  "credential_file",
	"jks":  "credential_file",
	"kdbx": "credential_file",
	"env":  "credential_file",
	"sql":  "database_backup",
	"bak":  "database_backup",
	"dump": "database_backup",
	"csv":  "data_export",
	"xls":  "data_export",
	"xlsx": "data_export",
}

// classifyFileSensitivity 由扩展名推导敏感类型标签（词表外返回空切片 = 非敏感口径）。
func classifyFileSensitivity(extension string) []string {
	if t, ok := sensitiveFileTypeByExt[strings.ToLower(strings.TrimSpace(extension))]; ok {
		return []string{t}
	}
	return []string{}
}

// maskClientIP 客户端 IP 掩码（IPv4 /24、IPv6 /64 前缀；非法输入归一为空串）。
func maskClientIP(ip string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	bits := 24
	if addr.Is6() {
		bits = 64
	}
	return netip.PrefixFrom(addr, bits).Masked().Addr().String()
}

// FileObsRecorder 文件观测入库接口（*FileObsStore 实现，可为 nil）。
type FileObsRecorder interface {
	RecordFileObservations(ctx context.Context, rec *Record) error
}

// FileObsStore pgx 实现。
type FileObsStore struct {
	db DBTX
}

// NewFileObsStore 创建文件观测写入方。
func NewFileObsStore(db *pgxpool.Pool) *FileObsStore {
	return &FileObsStore{db: db}
}

// WithDB 返回绑定到给定句柄的浅拷贝（W22 批次事务化，语义同 Store.WithDB）。
func (s *FileObsStore) WithDB(db DBTX) *FileObsStore {
	return &FileObsStore{db: db}
}

// RecordFileObservations 把一条事件携带的文件观测 UPSERT 进 api_file_assets（幂等聚合）：
// 去重键命中则 transfer_count+1、last_seen=GREATEST、first_seen=LEAST（乱序事件不回退
// 首见时间）；endpoint_id 按 endpoint_key 点查（未匹配留 NULL，与 findings 同一纪律）。
// 缺失容忍：endpoint_key 空 / 无观测 / 方向非法 / 文件名空的观测逐条跳过。
func (s *FileObsStore) RecordFileObservations(ctx context.Context, rec *Record) error {
	if s == nil || s.db == nil || rec == nil || rec.EndpointKey == "" || len(rec.FileObservations) == 0 {
		return nil
	}
	// endpoint_id 点查（本记录内所有观测共用一次解析）
	var endpointID *uuid.UUID
	var eid uuid.UUID
	err := s.db.QueryRow(ctx, `SELECT id FROM api_endpoints WHERE endpoint_key=$1`, rec.EndpointKey).Scan(&eid)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return fmt.Errorf("resolve endpoint for file obs: %w", err)
	default:
		endpointID = &eid
	}
	occurredAt := rec.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC() // 防御：正常路径网关必带事件时间
	}
	maskedIP := maskClientIP(rec.ClientIP)
	for _, o := range rec.FileObservations {
		dir := strings.ToUpper(strings.TrimSpace(o.Direction))
		if dir != "UPLOAD" && dir != "DOWNLOAD" {
			continue // 方向非法（旧版/异常网关值），跳过不污染词表
		}
		name := truncateRunes(strings.TrimSpace(o.FileName), maxFileObsNameLen)
		if name == "" {
			continue // 无文件名不产生资产行（下载侧无 filename 本就不产出观测，双保险）
		}
		ext := truncateRunes(strings.ToLower(o.Extension), maxFileObsExtLen)
		mimeType := truncateRunes(strings.ToLower(o.MIME), maxFileObsMIMELen)
		sensitive, _ := json.Marshal(mergeFileSensitivity(ext, o.SensitiveTypes))
		if _, err := s.db.Exec(ctx, `
INSERT INTO api_file_assets
  (endpoint_id, endpoint_key, direction, filename, extension, mime, size_bytes, sha256,
   identity_fingerprint, client_ip_masked, sensitive_types, first_seen, last_seen, transfer_count)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$11,1)
ON CONFLICT (endpoint_key, direction, filename, identity_fingerprint) DO UPDATE SET
  endpoint_id    = COALESCE(EXCLUDED.endpoint_id, api_file_assets.endpoint_id),
  extension      = EXCLUDED.extension,
  mime           = EXCLUDED.mime,
  size_bytes     = EXCLUDED.size_bytes,
  sha256         = COALESCE(EXCLUDED.sha256, api_file_assets.sha256),
  client_ip_masked = EXCLUDED.client_ip_masked,
  sensitive_types = (
    SELECT COALESCE(jsonb_agg(label ORDER BY label), '[]'::jsonb)
    FROM (
      SELECT jsonb_array_elements_text(api_file_assets.sensitive_types) AS label
      UNION
      SELECT jsonb_array_elements_text(EXCLUDED.sensitive_types) AS label
    ) merged
  ),
  first_seen     = LEAST(api_file_assets.first_seen, EXCLUDED.first_seen),
  last_seen      = GREATEST(api_file_assets.last_seen, EXCLUDED.last_seen),
  transfer_count = api_file_assets.transfer_count + 1,
  updated_at     = now()`,
			endpointID, rec.EndpointKey, dir, name, ext, mimeType, o.Size,
			normalizedFileSHA256(o.ContentSHA256), rec.IdentityFingerprint, maskedIP, string(sensitive), occurredAt); err != nil {
			return fmt.Errorf("upsert file asset %s %s: %w", dir, name, err)
		}
	}
	return nil
}
