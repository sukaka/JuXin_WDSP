// types.go 文件资产实体、统计聚合类型与查询过滤（handler 与 store 共用）。
package apifiles

import (
	"time"

	"github.com/google/uuid"
)

// 方向（api_file_assets.direction CHECK 对齐）：
// UPLOAD = 请求侧 multipart 文件上传；DOWNLOAD = 响应侧文件下载。
const (
	DirectionUpload   = "UPLOAD"
	DirectionDownload = "DOWNLOAD"
)

// 设置键（system_settings api_data 组，种子见迁移 000061）。
const (
	SettingsGroup                    = "api_data"
	SettingsKeyBulkDownloadThreshold = "file_bulk_download_threshold"
	// DefaultBulkDownloadThreshold 同身份批量下载默认阈值（近 1h 不同文件数）。
	DefaultBulkDownloadThreshold = 50
)

// 批量下载判定窗口（§107 子集：近 1 小时）。
const bulkDownloadWindow = time.Hour

// 看板/列表窗口与 TOP 上限（与 apigeo 同口径纪律）。
const (
	ListDefaultDays = 7
	ListMaxDays     = 30
	topLimit        = 10
)

// FileAsset 文件资产行（api_file_assets）。
type FileAsset struct {
	ID                  uuid.UUID  `json:"id"`
	EndpointID          *uuid.UUID `json:"endpoint_id"` // 未归属为 NULL
	EndpointKey         string     `json:"endpoint_key"`
	Direction           string     `json:"direction"`
	FileName            string     `json:"filename"`
	Extension           string     `json:"extension"`
	MIME                string     `json:"mime"`
	SizeBytes           int64      `json:"size_bytes"`
	SHA256              *string    `json:"sha256"`               // 预留：网关观测不含内容哈希，当前恒 NULL
	IdentityFingerprint string     `json:"identity_fingerprint"` // 匿名流量为空串
	ClientIPMasked      string     `json:"client_ip_masked"`
	SensitiveTypes      []string   `json:"sensitive_types"`
	FirstSeen           time.Time  `json:"first_seen"`
	LastSeen            time.Time  `json:"last_seen"`
	TransferCount       int        `json:"transfer_count"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// AssetFilter 列表过滤（枚举值已在 handler 层归一校验；时间窗按 last_seen 口径）。
type AssetFilter struct {
	Days          int
	Direction     string
	MIME          string // 精确匹配（入库已归一：主类型小写无参数）
	Extension     string // 精确匹配（小写）
	EndpointKey   string // 精确匹配
	SensitiveOnly bool   // 仅 sensitive_types 非空的敏感文件
	Page          int
	PageSize      int
}

// StatsSummary §106 汇总：上传/下载计数（资产数与传输次数双口径）+ 敏感文件计数。
type StatsSummary struct {
	UploadAssets       int64 `json:"upload_assets"`        // 上传方向不同文件资产数
	DownloadAssets     int64 `json:"download_assets"`      // 下载方向不同文件资产数
	UploadTransfers    int64 `json:"upload_transfers"`     // 上传传输次数（transfer_count 求和，近似口径）
	DownloadTransfers  int64 `json:"download_transfers"`   // 下载传输次数
	SensitiveFileCount int64 `json:"sensitive_file_count"` // sensitive_types 非空的资产数
}

// FileTopStat File TOP（按传输次数聚合；同名文件跨身份/端点归并）。
type FileTopStat struct {
	FileName   string `json:"filename"`
	Direction  string `json:"direction"`
	Transfers  int64  `json:"transfers"`
	Identities int64  `json:"identities"` // 涉及身份数（匿名计 1 个空串口径）
}

// IPTopStat IP TOP（掩码口径，与落库一致）。
type IPTopStat struct {
	ClientIPMasked string `json:"client_ip_masked"`
	Transfers      int64  `json:"transfers"`
	Files          int64  `json:"files"` // 涉及不同文件资产数
}

// AccountTopStat Account TOP（身份指纹；匿名空串归为 anonymous 展示键）。
type AccountTopStat struct {
	IdentityFingerprint string `json:"identity_fingerprint"` // 空串 = 匿名
	Transfers           int64  `json:"transfers"`
	Files               int64  `json:"files"`
}

// APITopStat API TOP（端点维度）。
type APITopStat struct {
	EndpointKey string `json:"endpoint_key"`
	Transfers   int64  `json:"transfers"`
	Files       int64  `json:"files"`
}

// StatsData §106 文件统计（窗口按 last_seen 口径，与列表明细同窗口）。
type StatsData struct {
	Days        int              `json:"days"`
	Summary     StatsSummary     `json:"summary"`
	TopFiles    []FileTopStat    `json:"top_files"`
	TopIPs      []IPTopStat      `json:"top_ips"`
	TopAccounts []AccountTopStat `json:"top_accounts"`
	TopAPIs     []APITopStat     `json:"top_apis"`
}

// BulkDownloadStat 同身份批量下载候选（riskStore 查询行）：
// 近窗口内某身份指纹下载的不同文件数与传输次数。
type BulkDownloadStat struct {
	IdentityFingerprint string
	DistinctFiles       int64
	Transfers           int64
}

// clampDays 归一窗口（1..ListMaxDays，默认 ListDefaultDays）。
func clampDays(days int) int {
	if days <= 0 {
		return ListDefaultDays
	}
	if days > ListMaxDays {
		return ListMaxDays
	}
	return days
}

// validDirection 枚举校验（handler 查询参数白名单）。
func validDirection(s string) bool { return s == DirectionUpload || s == DirectionDownload }
