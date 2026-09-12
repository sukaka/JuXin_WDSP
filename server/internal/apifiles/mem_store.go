// mem_store.go 文件资产内存仓储：与 SQL Store 相同业务语义，
// 供包内单测与无库环境驱动真实 Handler / RiskSweeper.SweepOnce。
package apifiles

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemStore 进程内仓储（实现 Repository + riskStore）。
type MemStore struct {
	mu     sync.Mutex
	assets []FileAsset
}

// NewMemStore 创建空内存仓储。
func NewMemStore() *MemStore { return &MemStore{} }

// 确保 *MemStore 同时实现只读与风险查询接口。
var (
	_ Repository = (*MemStore)(nil)
	_ riskStore  = (*MemStore)(nil)
)

// addAsset 追加一条资产行（包内单测造数辅助）。
func (m *MemStore) addAsset(a FileAsset) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assets = append(m.assets, a)
}

// ListAssets 明细分页（内存镜像；窗口语义同 SQL 的 CURRENT_DATE 口径，
// 内存实现以 now 为锚——单测造数均用相对时间，口径差异不影响断言）。
func (m *MemStore) ListAssets(_ context.Context, f AssetFilter) ([]FileAsset, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if f.Page <= 0 {
		f.Page = 1
	}
	if f.PageSize <= 0 {
		f.PageSize = 20
	}
	since := time.Now().UTC().AddDate(0, 0, -(clampDays(f.Days) - 1)).Truncate(24 * time.Hour)
	matched := []FileAsset{}
	for _, a := range m.assets {
		if a.LastSeen.Before(since) {
			continue
		}
		if f.Direction != "" && a.Direction != f.Direction {
			continue
		}
		if f.MIME != "" && a.MIME != f.MIME {
			continue
		}
		if f.Extension != "" && a.Extension != f.Extension {
			continue
		}
		if f.EndpointKey != "" && a.EndpointKey != f.EndpointKey {
			continue
		}
		if f.SensitiveOnly && len(a.SensitiveTypes) == 0 {
			continue
		}
		matched = append(matched, a)
	}
	sort.Slice(matched, func(i, j int) bool {
		if matched[i].LastSeen.Equal(matched[j].LastSeen) {
			return matched[i].ID.String() > matched[j].ID.String()
		}
		return matched[i].LastSeen.After(matched[j].LastSeen)
	})
	total := int64(len(matched))
	start := (f.Page - 1) * f.PageSize
	if start >= len(matched) {
		return []FileAsset{}, total, nil
	}
	end := start + f.PageSize
	if end > len(matched) {
		end = len(matched)
	}
	return matched[start:end], total, nil
}

// Stats 统计聚合（内存镜像，语义同 SQL：同窗口汇总与四类 TOP）。
func (m *MemStore) Stats(_ context.Context, days int) (*StatsData, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	days = clampDays(days)
	out := &StatsData{
		Days:        days,
		TopFiles:    []FileTopStat{},
		TopIPs:      []IPTopStat{},
		TopAccounts: []AccountTopStat{},
		TopAPIs:     []APITopStat{},
	}
	since := time.Now().UTC().AddDate(0, 0, -(days - 1)).Truncate(24 * time.Hour)

	type fileAgg struct {
		direction  string
		transfers  int64
		identities map[string]bool
	}
	files := map[string]*fileAgg{} // filename + \x1f + direction
	ips := map[string]*keyAgg{}
	accounts := map[string]*keyAgg{}
	apis := map[string]*keyAgg{}
	for _, a := range m.assets {
		if a.LastSeen.Before(since) {
			continue
		}
		switch a.Direction {
		case DirectionUpload:
			out.Summary.UploadAssets++
			out.Summary.UploadTransfers += int64(a.TransferCount)
		case DirectionDownload:
			out.Summary.DownloadAssets++
			out.Summary.DownloadTransfers += int64(a.TransferCount)
		}
		if len(a.SensitiveTypes) > 0 {
			out.Summary.SensitiveFileCount++
		}
		fk := a.FileName + "\x1f" + a.Direction
		fa := files[fk]
		if fa == nil {
			fa = &fileAgg{direction: a.Direction, identities: map[string]bool{}}
			files[fk] = fa
		}
		fa.transfers += int64(a.TransferCount)
		fa.identities[a.IdentityFingerprint] = true
		for k, m := range map[string]map[string]*keyAgg{
			a.ClientIPMasked: ips, a.IdentityFingerprint: accounts, a.EndpointKey: apis,
		} {
			ka := m[k]
			if ka == nil {
				ka = &keyAgg{}
				m[k] = ka
			}
			ka.transfers += int64(a.TransferCount)
			ka.files++
		}
	}

	fileKeys := make([]string, 0, len(files))
	for k := range files {
		fileKeys = append(fileKeys, k)
	}
	sort.Slice(fileKeys, func(i, j int) bool {
		fi, fj := files[fileKeys[i]], files[fileKeys[j]]
		if fi.transfers != fj.transfers {
			return fi.transfers > fj.transfers
		}
		return fileKeys[i] < fileKeys[j]
	})
	for i, k := range fileKeys {
		if i >= topLimit {
			break
		}
		name := k[:len(k)-len(files[k].direction)-1]
		out.TopFiles = append(out.TopFiles, FileTopStat{
			FileName: name, Direction: files[k].direction,
			Transfers: files[k].transfers, Identities: int64(len(files[k].identities)),
		})
	}
	// 三组 keyAgg TOP（传输次数降序、键升序，封顶 topLimit；与 SQL ORDER BY 口径一致）
	out.TopIPs = []IPTopStat{}
	for _, k := range sortedAggKeys(ips) {
		out.TopIPs = append(out.TopIPs, IPTopStat{ClientIPMasked: k, Transfers: ips[k].transfers, Files: ips[k].files})
	}
	out.TopAccounts = []AccountTopStat{}
	for _, k := range sortedAggKeys(accounts) {
		out.TopAccounts = append(out.TopAccounts, AccountTopStat{IdentityFingerprint: k, Transfers: accounts[k].transfers, Files: accounts[k].files})
	}
	out.TopAPIs = []APITopStat{}
	for _, k := range sortedAggKeys(apis) {
		out.TopAPIs = append(out.TopAPIs, APITopStat{EndpointKey: k, Transfers: apis[k].transfers, Files: apis[k].files})
	}
	return out, nil
}

// keyAgg TOP 聚合桶（IP/Account/API 共用：传输次数 + 涉及文件资产数）。
type keyAgg struct {
	transfers int64
	files     int64
}

// sortedAggKeys keyAgg 键排序（传输次数降序、键升序，封顶 topLimit）。
func sortedAggKeys(in map[string]*keyAgg) []string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if in[keys[i]].transfers != in[keys[j]].transfers {
			return in[keys[i]].transfers > in[keys[j]].transfers
		}
		return keys[i] < keys[j]
	})
	if len(keys) > topLimit {
		keys = keys[:topLimit]
	}
	return keys
}

// BulkDownloadCandidates 内存镜像：近 window 下载方向按身份聚合，
// 不同文件数（DISTINCT filename 口径）严格大于阈值的候选；匿名空串不参与。
func (m *MemStore) BulkDownloadCandidates(_ context.Context, window time.Duration, threshold int) ([]BulkDownloadStat, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	since := time.Now().UTC().Add(-window)
	type agg struct {
		names     map[string]bool
		transfers int64
	}
	byIdentity := map[string]*agg{}
	for _, a := range m.assets {
		if a.Direction != DirectionDownload || a.IdentityFingerprint == "" || a.LastSeen.Before(since) {
			continue
		}
		ga := byIdentity[a.IdentityFingerprint]
		if ga == nil {
			ga = &agg{names: map[string]bool{}}
			byIdentity[a.IdentityFingerprint] = ga
		}
		ga.names[a.FileName] = true
		ga.transfers += int64(a.TransferCount)
	}
	out := []BulkDownloadStat{}
	for id, ga := range byIdentity {
		if int64(len(ga.names)) > int64(threshold) {
			out = append(out, BulkDownloadStat{
				IdentityFingerprint: id, DistinctFiles: int64(len(ga.names)), Transfers: ga.transfers,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DistinctFiles != out[j].DistinctFiles {
			return out[i].DistinctFiles > out[j].DistinctFiles
		}
		return out[i].IdentityFingerprint < out[j].IdentityFingerprint
	})
	return out, nil
}
