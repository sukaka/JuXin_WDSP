package main

import (
	"fmt"
	"strconv"
	"strings"
)

type emixEntry struct {
	Path   string `json:"path"`
	Weight int    `json:"weight"`
}

type emixProfile struct {
	Name        string      `json:"name"`
	Entries     []emixEntry `json:"entries"`
	totalWeight int
}

// buildEMIXProfile 构建 NetSecOPEN / 企业 EMIX 对象尺寸权重分布。
func buildEMIXProfile(preset, customSpec string) (*emixProfile, error) {
	if strings.TrimSpace(customSpec) != "" {
		var entries []emixEntry
		total := 0
		for _, part := range strings.Split(customSpec, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			kv := strings.SplitN(part, ":", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid emix item %q (want path:weight)", part)
			}
			w, err := strconv.Atoi(strings.TrimSpace(kv[1]))
			if err != nil || w <= 0 {
				return nil, fmt.Errorf("invalid emix weight in %q", part)
			}
			p := strings.TrimSpace(kv[0])
			if !strings.HasPrefix(p, "/") {
				p = "/" + p
			}
			entries = append(entries, emixEntry{Path: p, Weight: w})
			total += w
		}
		if len(entries) == 0 || total == 0 {
			return nil, fmt.Errorf("empty custom emix spec")
		}
		return &emixProfile{Name: "custom", Entries: entries, totalWeight: total}, nil
	}

	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "", "netsecopen":
		// 对标 RFC 9411 / NetSecOPEN 多尺寸企业流量混合（加权平均响应体 ≈ 55.8 KiB）
		entries := []emixEntry{
			{Path: "/static/1k.bin", Weight: 20},
			{Path: "/static/4k.bin", Weight: 25},
			{Path: "/static/16k.bin", Weight: 25},
			{Path: "/static/64k.bin", Weight: 20},
			{Path: "/static/256k.bin", Weight: 8},
			{Path: "/static/1m.bin", Weight: 2},
		}
		return &emixProfile{Name: "netsecopen", Entries: entries, totalWeight: 100}, nil
	case "enterprise_web":
		// 偏中小对象的企业 Web 混合（加权平均 ≈ 19.8 KiB）
		entries := []emixEntry{
			{Path: "/static/256b.txt", Weight: 15},
			{Path: "/static/1k.bin", Weight: 20},
			{Path: "/static/4k.bin", Weight: 30},
			{Path: "/static/16k.bin", Weight: 20},
			{Path: "/static/64k.bin", Weight: 12},
			{Path: "/static/256k.bin", Weight: 3},
		}
		return &emixProfile{Name: "enterprise_web", Entries: entries, totalWeight: 100}, nil
	case "api_mixed":
		// Web 静态 + API 读路径混合
		entries := []emixEntry{
			{Path: "/v1/emix-api/1", Weight: 40},
			{Path: "/static/1k.bin", Weight: 20},
			{Path: "/static/4k.bin", Weight: 20},
			{Path: "/static/16k.bin", Weight: 15},
			{Path: "/static/64k.bin", Weight: 5},
		}
		return &emixProfile{Name: "api_mixed", Entries: entries, totalWeight: 100}, nil
	default:
		return nil, fmt.Errorf("unknown emix preset %q (want netsecopen, enterprise_web, api_mixed)", preset)
	}
}

// Pick 基于序列号确定性加权挑选对象路径，保证多轮压测完全可复现。
func (e *emixProfile) Pick(seq uint64) string {
	// 简单线性混合避免连续请求全落同一尺寸段，同时保持 100% 确定性
	slot := int(((seq * 37) + 13) % uint64(e.totalWeight))
	acc := 0
	for _, entry := range e.Entries {
		acc += entry.Weight
		if slot < acc {
			return entry.Path
		}
	}
	return e.Entries[len(e.Entries)-1].Path
}
