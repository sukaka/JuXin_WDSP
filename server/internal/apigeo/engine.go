// engine.go 统一 GeoIP 查询引擎：融合 ip2region（XDB v2/v3，国内省市与运营商精准）与
// DB-IP Lite / MaxMind MMDB（海外城市、经纬度与 IPv6 精准），向安全事件、访问日志、
// 攻击大屏、报告与数据出境看板提供统一、并发安全、纯内存零网络 I/O 的归属地查询能力。
package apigeo

import (
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// GeoInfo 标准化 IP 归属地响应结构（API 与事件/日志富化共用）。
type GeoInfo struct {
	IP          string   `json:"ip"`
	Scope       string   `json:"scope"` // PUBLIC / INTERNAL / INVALID
	CountryCode string   `json:"country_code,omitempty"`
	Country     string   `json:"country,omitempty"`
	Province    string   `json:"province,omitempty"`
	City        string   `json:"city,omitempty"`
	ISP         string   `json:"isp,omitempty"`
	Label       string   `json:"label"`
	Latitude    *float64 `json:"latitude,omitempty"`
	Longitude   *float64 `json:"longitude,omitempty"`
	Source      string   `json:"source,omitempty"`
}

// GeoLookup 统一归属地查询接口（嵌入 CountryLookup，可直接注入出境判定、态势、报告、事件与访问日志）。
type GeoLookup interface {
	CountryLookup
	LookupGeo(ipRaw string) *GeoInfo
	Enabled() bool
	Sources() []string
}

// Engine 统一只读 GeoIP 引擎（常驻内存，并发安全）。
type Engine struct {
	xdbV4       *XDB
	xdbV6       *XDB
	cityMMDB    *MMDB // 优先官方 DB-IP City Lite（双栈或 IPv4）
	cityV6MMDB  *MMDB // 专用 IPv6 城市库（如仓库归档 city-ipv6.mmdb）
	countryMMDB *MMDB // 国家码回退库（DB-IP Country Lite / country.mmdb）
	sources     []string
}

// EngineOptions 手动构造引擎（供单测与显式装配使用）。
type EngineOptions struct {
	XDBv4       *XDB
	XDBv6       *XDB
	CityMMDB    *MMDB
	CityV6MMDB  *MMDB
	CountryMMDB *MMDB
}

// NewEngine 根据已解析的底层库实例构造统一引擎。
func NewEngine(opts EngineOptions) *Engine {
	e := &Engine{
		xdbV4:       opts.XDBv4,
		xdbV6:       opts.XDBv6,
		cityMMDB:    opts.CityMMDB,
		cityV6MMDB:  opts.CityV6MMDB,
		countryMMDB: opts.CountryMMDB,
	}
	if e.xdbV4 != nil {
		e.sources = append(e.sources, "ip2region_v4")
	}
	if e.xdbV6 != nil {
		e.sources = append(e.sources, "ip2region_v6")
	}
	if e.cityMMDB != nil {
		e.sources = append(e.sources, "dbip_city")
	}
	if e.cityV6MMDB != nil && e.cityV6MMDB != e.cityMMDB {
		e.sources = append(e.sources, "dbip_city_v6")
	}
	if e.countryMMDB != nil {
		e.sources = append(e.sources, "country_mmdb")
	}
	return e
}

// DefaultSearchDirs 返回默认 GeoIP 数据目录搜索顺序（高优先级在前）：
// 1. <dataDir>/geoip（运维热更新/覆盖目录，优先级最高）
// 2. /app/assets/geoip（容器镜像默认内置目录）
// 3. ./assets/geoip（本地后端工作目录）
// 4. ../web/public/assets/geo（本地开发复用前端静态目录）
func DefaultSearchDirs(dataDir string) []string {
	var dirs []string
	if strings.TrimSpace(dataDir) != "" {
		dirs = append(dirs, filepath.Join(dataDir, "geoip"))
	}
	dirs = append(dirs,
		"/app/assets/geoip",
		filepath.Join("assets", "geoip"),
		filepath.Join("..", "web", "public", "assets", "geo"),
	)
	return dirs
}

// OpenEngine 按优先级扫描候选目录，自动加载可用的 ip2region XDB 与 DB-IP / MMDB 文件。
// 所有库均缺失时返回空引擎（Enabled()==false），调用方按降级口径处理，不阻塞进程启动。
func OpenEngine(dirs ...string) *Engine {
	var opts EngineOptions
	seenDirs := make(map[string]bool, len(dirs))
	var validDirs []string
	for _, d := range dirs {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		clean := filepath.Clean(d)
		if seenDirs[clean] {
			continue
		}
		seenDirs[clean] = true
		if info, err := os.Stat(clean); err == nil && info.IsDir() {
			validDirs = append(validDirs, clean)
		}
	}

	if path := findFirstMatch(validDirs, []string{"ip2region_v4.xdb", "ip2region.xdb"}); path != "" {
		if x, err := OpenXDB(path); err != nil {
			slog.Warn("geoip load xdb v4 failed", "path", path, "error", err)
		} else if x.IPVersion() == 4 {
			opts.XDBv4 = x
		} else {
			slog.Warn("geoip xdb v4 unexpected ip_version", "path", path, "ip_version", x.IPVersion())
		}
	}

	if path := findFirstMatch(validDirs, []string{"ip2region_v6.xdb"}); path != "" {
		if x, err := OpenXDB(path); err != nil {
			slog.Warn("geoip load xdb v6 failed", "path", path, "error", err)
		} else if x.IPVersion() == 6 {
			opts.XDBv6 = x
		} else {
			slog.Warn("geoip xdb v6 unexpected ip_version", "path", path, "ip_version", x.IPVersion())
		}
	}

	if path := findFirstMatch(validDirs, []string{"dbip-city-lite*.mmdb", "city.mmdb", "GeoLite2-City.mmdb"}); path != "" {
		if m, err := OpenMMDB(path); err != nil {
			slog.Warn("geoip load city mmdb failed", "path", path, "error", err)
		} else {
			opts.CityMMDB = m
		}
	}

	// 若尚未加载支持 IPv6 的城市库，继续查找专用 city-ipv6.mmdb
	if opts.CityMMDB == nil || opts.CityMMDB.meta.ipVersion != 6 {
		if path := findFirstMatch(validDirs, []string{"city-ipv6.mmdb"}); path != "" {
			if m, err := OpenMMDB(path); err != nil {
				slog.Warn("geoip load city-ipv6 mmdb failed", "path", path, "error", err)
			} else {
				opts.CityV6MMDB = m
			}
		}
	}

	if path := findFirstMatch(validDirs, []string{"dbip-country-lite*.mmdb", "country.mmdb", "GeoLite2-Country.mmdb"}); path != "" {
		if m, err := OpenMMDB(path); err != nil {
			slog.Warn("geoip load country mmdb failed", "path", path, "error", err)
		} else {
			opts.CountryMMDB = m
		}
	}

	e := NewEngine(opts)
	if e.Enabled() {
		slog.Info("geoip engine initialized", "sources", e.Sources())
	} else {
		slog.Warn("geoip engine degraded: no geoip database files found", "search_dirs", validDirs)
	}
	return e
}

// findFirstMatch 按目录优先级与模式优先级查找第一个存在且非空的文件；
// 同目录通配命中多文件（如按月命名的 dbip-city-lite-2026-11.mmdb）时按文件名倒序选最新。
func findFirstMatch(dirs []string, patterns []string) string {
	for _, dir := range dirs {
		for _, pat := range patterns {
			matches, err := filepath.Glob(filepath.Join(dir, pat))
			if err != nil || len(matches) == 0 {
				continue
			}
			sort.Sort(sort.Reverse(sort.StringSlice(matches)))
			for _, p := range matches {
				if info, statErr := os.Stat(p); statErr == nil && !info.IsDir() && info.Size() > 0 {
					return p
				}
			}
		}
	}
	return ""
}

// Enabled 至少加载了一个离线 GeoIP 库即返回 true。
func (e *Engine) Enabled() bool {
	if e == nil {
		return false
	}
	return e.xdbV4 != nil || e.xdbV6 != nil || e.cityMMDB != nil || e.cityV6MMDB != nil || e.countryMMDB != nil
}

// Sources 返回当前生效的数据源名称副本（不含宿主机路径，可安全返回给前端）。
func (e *Engine) Sources() []string {
	if e == nil || len(e.sources) == 0 {
		return []string{}
	}
	out := make([]string, len(e.sources))
	copy(out, e.sources)
	return out
}

// LookupCountry 实现 CountryLookup 接口，返回 ISO 3166-1 alpha-2 国家码。
func (e *Engine) LookupCountry(ip netip.Addr) (string, error) {
	if e == nil || !ip.IsValid() {
		return "", nil
	}
	ip = ip.Unmap()

	if ip.Is4() {
		// 国内及港澳台由 ip2region 优先精确区分 CN/HK/MO/TW
		var xdbCode string
		if e.xdbV4 != nil {
			rec, err := e.xdbV4.Lookup(ip)
			if err != nil {
				return "", err
			}
			if rec != nil {
				xdbCode = rec.CountryCode
				if isGreaterChina(xdbCode) {
					return xdbCode, nil
				}
			}
		}
		if e.cityMMDB != nil {
			code, err := e.cityMMDB.LookupCountry(ip)
			if err != nil {
				return "", err
			}
			if code != "" {
				return code, nil
			}
		}
		if e.countryMMDB != nil {
			code, err := e.countryMMDB.LookupCountry(ip)
			if err != nil {
				return "", err
			}
			if code != "" {
				return code, nil
			}
		}
		return xdbCode, nil
	}

	// IPv6：优先 ip2region_v6（大中华区） → cityMMDB / cityV6MMDB → countryMMDB → ip2region_v6
	var xdbCode string
	if e.xdbV6 != nil {
		rec, err := e.xdbV6.Lookup(ip)
		if err != nil {
			return "", err
		}
		if rec != nil {
			xdbCode = rec.CountryCode
			if isGreaterChina(xdbCode) {
				return xdbCode, nil
			}
		}
	}
	if m := e.v6CityMMDB(); m != nil {
		code, err := m.LookupCountry(ip)
		if err != nil {
			return "", err
		}
		if code != "" {
			return code, nil
		}
	}
	if e.countryMMDB != nil {
		code, err := e.countryMMDB.LookupCountry(ip)
		if err != nil {
			return "", err
		}
		if code != "" {
			return code, nil
		}
	}
	return xdbCode, nil
}

// LookupGeo 查询单条 IP 完整归属地（含国家/省/市/运营商/中文展示标签/经纬度）。
// 始终返回非 nil（非法 IP 标 INVALID、内网/保留 IP 标 INTERNAL「内网地址」），查询异常记录告警并降级，不中断业务。
func (e *Engine) LookupGeo(ipRaw string) *GeoInfo {
	trimmed := strings.TrimSpace(ipRaw)
	if trimmed == "" {
		return &GeoInfo{IP: "", Scope: IPScopeInvalid}
	}
	addr, err := netip.ParseAddr(trimmed)
	if err != nil {
		return &GeoInfo{IP: trimmed, Scope: IPScopeInvalid}
	}
	addr = addr.Unmap()
	canonical := addr.String()
	if isInternalAddr(addr) {
		return &GeoInfo{
			IP:     canonical,
			Scope:  IPScopeInternal,
			Label:  "内网地址",
			Source: "internal",
		}
	}
	if e == nil || !e.Enabled() {
		return &GeoInfo{IP: canonical, Scope: IPScopePublic}
	}

	var xdbRec *XDBRecord
	var cityLoc *MMDBLocation
	var countryLoc *MMDBLocation

	if addr.Is4() {
		if e.xdbV4 != nil {
			if rec, err := e.xdbV4.Lookup(addr); err != nil {
				slog.Warn("geoip xdb v4 lookup failed", "ip", canonical, "error", err)
			} else {
				xdbRec = rec
			}
		}
		if e.cityMMDB != nil {
			if loc, err := e.cityMMDB.LookupLocation(addr); err != nil {
				slog.Warn("geoip city mmdb lookup failed", "ip", canonical, "error", err)
			} else {
				cityLoc = loc
			}
		}
	} else {
		if e.xdbV6 != nil {
			if rec, err := e.xdbV6.Lookup(addr); err != nil {
				slog.Warn("geoip xdb v6 lookup failed", "ip", canonical, "error", err)
			} else {
				xdbRec = rec
			}
		}
		if m := e.v6CityMMDB(); m != nil {
			if loc, err := m.LookupLocation(addr); err != nil {
				slog.Warn("geoip city v6 mmdb lookup failed", "ip", canonical, "error", err)
			} else {
				cityLoc = loc
			}
		}
	}

	if e.countryMMDB != nil {
		if loc, err := e.countryMMDB.LookupLocation(addr); err != nil {
			slog.Warn("geoip country mmdb lookup failed", "ip", canonical, "error", err)
		} else {
			countryLoc = loc
		}
	}

	return mergeGeoInfo(canonical, xdbRec, cityLoc, countryLoc)
}

func (e *Engine) v6CityMMDB() *MMDB {
	if e.cityMMDB != nil && e.cityMMDB.meta.ipVersion == 6 {
		return e.cityMMDB
	}
	return e.cityV6MMDB
}

func mergeGeoInfo(ip string, xdbRec *XDBRecord, cityLoc, countryLoc *MMDBLocation) *GeoInfo {
	out := &GeoInfo{
		IP:    ip,
		Scope: IPScopePublic,
	}

	// 1. 决定国家码：大中华区信 ip2region；海外优先 DB-IP 城市库 → ip2region → 国家库
	if xdbRec != nil && isGreaterChina(xdbRec.CountryCode) {
		out.CountryCode = xdbRec.CountryCode
	} else if cityLoc != nil && cityLoc.CountryCode != "" {
		out.CountryCode = cityLoc.CountryCode
	} else if xdbRec != nil && xdbRec.CountryCode != "" {
		out.CountryCode = xdbRec.CountryCode
	} else if countryLoc != nil && countryLoc.CountryCode != "" {
		out.CountryCode = countryLoc.CountryCode
	}

	usedXDB := false
	usedCityMMDB := false
	usedCountryMMDB := false

	// 2. 按国内外场景融合省、市、运营商与经纬度
	if isGreaterChina(out.CountryCode) {
		if xdbRec != nil {
			out.Province = xdbRec.Province
			out.City = xdbRec.City
			out.ISP = xdbRec.ISP
			usedXDB = true
		}
		if cityLoc != nil {
			if out.Province == "" && cityLoc.Province != "" {
				out.Province = cityLoc.Province
				usedCityMMDB = true
			}
			if out.City == "" && cityLoc.City != "" {
				out.City = cityLoc.City
				usedCityMMDB = true
			}
		}
		// 中国省市坐标优先走精确行政区坐标表（避免 DB-IP 对国内部分 DNS/云 IP 误标城市）
		if lon, lat, ok := lookupCNCoord(out.Province, out.City); ok {
			out.Longitude = ptrFloat64(lon)
			out.Latitude = ptrFloat64(lat)
		} else if cityLoc != nil && cityLoc.HasCoord {
			out.Longitude = ptrFloat64(cityLoc.Longitude)
			out.Latitude = ptrFloat64(cityLoc.Latitude)
			usedCityMMDB = true
		}
	} else {
		if cityLoc != nil {
			out.Province = cityLoc.Province
			out.City = cityLoc.City
			if cityLoc.HasCoord {
				out.Longitude = ptrFloat64(cityLoc.Longitude)
				out.Latitude = ptrFloat64(cityLoc.Latitude)
			}
			usedCityMMDB = true
		}
		if xdbRec != nil {
			if out.Province == "" && xdbRec.Province != "" {
				out.Province = xdbRec.Province
				usedXDB = true
			}
			if out.City == "" && xdbRec.City != "" {
				out.City = xdbRec.City
				usedXDB = true
			}
			if xdbRec.ISP != "" {
				out.ISP = xdbRec.ISP
				usedXDB = true
			}
			if !usedCityMMDB && (xdbRec.CountryCode != "" || xdbRec.Country != "") {
				usedXDB = true
			}
		}
	}

	if !usedXDB && !usedCityMMDB && countryLoc != nil && countryLoc.CountryCode != "" {
		usedCountryMMDB = true
	}

	// 3. 统一中文国家名（优先 ISO 中文映射，回退库内原始国家名）
	if zh := CountryNameZh(out.CountryCode); zh != "" {
		out.Country = zh
	} else if xdbRec != nil && xdbRec.Country != "" {
		out.Country = xdbRec.Country
	} else if cityLoc != nil && cityLoc.Country != "" {
		out.Country = cityLoc.Country
	} else if countryLoc != nil && countryLoc.Country != "" {
		out.Country = countryLoc.Country
	}

	out.Label = formatGeoLabel(out.Country, out.Province, out.City)
	switch {
	case usedXDB && usedCityMMDB:
		out.Source = "hybrid"
	case usedXDB:
		out.Source = "ip2region"
	case usedCityMMDB:
		out.Source = "dbip"
	case usedCountryMMDB:
		out.Source = "country_mmdb"
	}
	return out
}

func isGreaterChina(code string) bool {
	return code == "CN" || code == "HK" || code == "MO" || code == "TW"
}

func ptrFloat64(v float64) *float64 {
	return &v
}

// formatGeoLabel 拼接紧凑易读的中文归属地标签，自动去重直辖市与港澳台重复词。
func formatGeoLabel(country, province, city string) string {
	var parts []string
	if country != "" {
		parts = append(parts, country)
	}
	if province != "" && !regionRedundant(country, province) {
		parts = append(parts, province)
	}
	if city != "" && !regionRedundant(country, city) && !regionRedundant(province, city) {
		parts = append(parts, city)
	}
	return strings.Join(parts, " ")
}

func regionRedundant(parent, child string) bool {
	if parent == "" || child == "" {
		return false
	}
	if strings.EqualFold(parent, child) {
		return true
	}
	pk := normalizeCNRegionKey(parent)
	ck := normalizeCNRegionKey(child)
	if ck != "" && (pk == ck || strings.HasSuffix(parent, ck)) {
		return true
	}
	return false
}
