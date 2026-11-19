// Package k8smeta keeps a small, fail-open Kubernetes IP metadata snapshot.
package k8smeta

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	pageLimit         = "500"

	// DefaultRefreshInterval 元数据全量快照刷新周期。
	DefaultRefreshInterval = 30 * time.Second
	// DefaultEntryTTL 条目在未被成功快照再次确认后仍参与解析的最长时间。
	// 超时后不再把该 IP 归属到旧 Pod/工作负载——防止长时间 API 故障期间
	// Pod 删除或 IP 重用把流量串联到旧归属。
	DefaultEntryTTL = 10 * time.Minute
	// DefaultUnavailableAfter 刷新持续失败超过该时长后，快照状态由 STALE 升级为
	// UNAVAILABLE（采集继续，但元数据必须显式显示失效，不得显示为正常）。
	DefaultUnavailableAfter = 5 * time.Minute
)

// State 快照健康状态（P1-03 §6：OK / STALE / UNAVAILABLE）。
type State string

const (
	// StateOK 最近一次刷新成功。
	StateOK State = "OK"
	// StateStale 刷新失败，仍提供最后一次成功快照（附带距成功时长）。
	StateStale State = "STALE"
	// StateUnavailable 从未成功，或持续失败超过 UnavailableAfter。
	StateUnavailable State = "UNAVAILABLE"
)

// Metadata is attached to an event when either endpoint matches a running Pod.
// 线格式受 server/agent 冻结契约约束（server 端机器端点拒绝未知字段），
// 新增可见性只能走心跳 metrics，不能在此加字段。
type Metadata struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Workload  string `json:"workload,omitempty"`
	Service   string `json:"service,omitempty"`
	Side      string `json:"side"`
}

// entry 快照条目：confirmedAt 为最近一次成功同步仍确认该 IP 的时间；
// inferred 标记 Workload 为 ReplicaSet 截尾推断（未经 ReplicaSet→Deployment 权威解析）。
type entry struct {
	meta        Metadata
	inferred    bool
	confirmedAt time.Time
}

type snapshot struct{ byIP map[string]entry }

// Health 快照健康视图，供心跳指标与排障查询。
type Health struct {
	State          State
	Entries        int           // 未过期的条目数
	InferredOwners int           // 其中 Workload 为推断的条目数
	StaleFor       time.Duration // 距上次成功刷新时长（非 OK 时有意义）
	LastSuccess    time.Time
	SyncFailures   uint64 // 累计刷新失败次数
	LastError      string
}

// Resolver publishes complete snapshots atomically. A failed refresh never clears
// the old one; entries expire individually after EntryTTL so that stale ownership
// is not attributed to reused IPs indefinitely.
type Resolver struct {
	current atomic.Pointer[snapshot]

	mu           sync.Mutex
	lastSuccess  time.Time
	lastFailure  time.Time
	syncFailures uint64
	lastError    string

	now func() time.Time // 测试可替换

	// EntryTTL / UnavailableAfter 可在首次使用前覆盖（默认见 Default* 常量）。
	EntryTTL         time.Duration
	UnavailableAfter time.Duration
}

func NewResolver() *Resolver {
	return &Resolver{now: time.Now, EntryTTL: DefaultEntryTTL, UnavailableAfter: DefaultUnavailableAfter}
}

// Replace publishes an already-built IP map. It is exported for the client and focused tests.
func (r *Resolver) Replace(items map[string]Metadata) {
	entries := make(map[string]entry, len(items))
	for k, v := range items {
		entries[k] = entry{meta: v}
	}
	r.replaceAll(entries, r.now())
}

// replaceAll 原子发布新快照并标记一次成功刷新；所有条目以 t 作为确认时间。
func (r *Resolver) replaceAll(entries map[string]entry, t time.Time) {
	for k, e := range entries {
		e.confirmedAt = t
		entries[k] = e
	}
	r.current.Store(&snapshot{byIP: entries})
	r.mu.Lock()
	r.lastSuccess, r.lastError = t, ""
	r.mu.Unlock()
}

// noteFailure 记录一次刷新失败：保留旧快照，状态经 Health 体现为 STALE/UNAVAILABLE。
func (r *Resolver) noteFailure(err error, t time.Time) {
	r.mu.Lock()
	r.lastFailure = t
	r.lastError = err.Error()
	r.syncFailures++
	r.mu.Unlock()
}

// Health 当前快照健康状态与规模。
func (r *Resolver) Health() Health {
	now := r.now()
	r.mu.Lock()
	h := Health{LastSuccess: r.lastSuccess, SyncFailures: r.syncFailures, LastError: r.lastError}
	lastSuccess, lastFailure := r.lastSuccess, r.lastFailure
	r.mu.Unlock()
	switch {
	case lastSuccess.IsZero():
		// 从未成功（含首次同步尚未完成与持续失败）：无数据可声明为正常。
		h.State = StateUnavailable
	case lastFailure.After(lastSuccess):
		h.StaleFor = now.Sub(lastSuccess)
		if h.StaleFor >= r.UnavailableAfter {
			h.State = StateUnavailable
		} else {
			h.State = StateStale
		}
	default:
		h.State = StateOK
	}
	if s := r.current.Load(); s != nil {
		for _, e := range s.byIP {
			if r.expired(e, now) {
				continue
			}
			h.Entries++
			if e.inferred {
				h.InferredOwners++
			}
		}
	}
	return h
}

func (r *Resolver) expired(e entry, now time.Time) bool {
	return r.EntryTTL > 0 && now.Sub(e.confirmedAt) > r.EntryTTL
}

// Resolve prefers destination/server metadata when both endpoints are Pods.
// 超过 EntryTTL 未被成功快照再确认的条目不参与解析（防 IP 重用串联旧归属）。
func (r *Resolver) Resolve(srcIP, dstIP string) *Metadata {
	s := r.current.Load()
	if s == nil {
		return nil
	}
	now := r.now()
	lookup := func(ip string) *Metadata {
		e, ok := s.byIP[ip]
		if !ok || r.expired(e, now) {
			return nil
		}
		m := e.meta
		return &m
	}
	if m := lookup(dstIP); m != nil {
		m.Side = "dst"
		return m
	}
	if m := lookup(srcIP); m != nil {
		m.Side = "src"
		return m
	}
	return nil
}

// Client is a stdlib-only in-cluster Kubernetes API client.
// 实现只使用 list 动词（分页全量快照，无 watch）；endpoints 与 replicasets
// 按本节点 Pod 所在 namespace 分别查询，不做全集群分页。
type Client struct {
	baseURL, token, nodeName, cluster string
	tokenPath                         string // ServiceAccount token 文件（投射卷轮换后重读）
	http                              *http.Client
	log                               *slog.Logger
	refreshInterval                   time.Duration // 默认 DefaultRefreshInterval
}

// NewInCluster detects the service environment and service-account credentials.
func NewInCluster(nodeName, cluster string, log *slog.Logger) (*Client, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("Kubernetes service environment not found")
	}
	if strings.TrimSpace(nodeName) == "" {
		return nil, errors.New("NODE_NAME is required for Kubernetes metadata sync")
	}
	tokenPath := filepath.Join(serviceAccountDir, "token")
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service-account token: %w", err)
	}
	ca, err := os.ReadFile(filepath.Join(serviceAccountDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read service-account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid service-account CA")
	}
	return &Client{baseURL: "https://" + net.JoinHostPort(host, port), token: strings.TrimSpace(string(token)), tokenPath: tokenPath, nodeName: nodeName, cluster: cluster, http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, Timeout: 15 * time.Second}, log: log}, nil
}

// reloadToken re-reads the service-account token file. Projected volumes rotate
// bound tokens roughly every minute; without a re-read the rotated token would
// leave every sync failing with 401 forever. Fail-open: keeps the old token.
func (c *Client) reloadToken() {
	if c.tokenPath == "" {
		return
	}
	b, err := os.ReadFile(c.tokenPath)
	if err != nil {
		if c.log != nil {
			c.log.Warn("重读 service-account token 失败，沿用旧 token", "err", err)
		}
		return
	}
	c.token = strings.TrimSpace(string(b))
}

type listMeta struct {
	Continue string `json:"continue"`
}
type ownerRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}
type podList struct {
	Metadata listMeta `json:"metadata"`
	Items    []struct {
		Metadata struct {
			Name, Namespace string
			OwnerReferences []ownerRef `json:"ownerReferences"`
		} `json:"metadata"`
		Spec struct {
			HostNetwork bool `json:"hostNetwork"`
		} `json:"spec"`
		Status struct {
			PodIP string `json:"podIP"`
		} `json:"status"`
	} `json:"items"`
}
type replicaSetList struct {
	Metadata listMeta `json:"metadata"`
	Items    []struct {
		Metadata struct {
			Name            string
			OwnerReferences []ownerRef `json:"ownerReferences"`
		} `json:"metadata"`
	} `json:"items"`
}
type endpointList struct {
	Metadata listMeta `json:"metadata"`
	Items    []struct {
		Metadata struct{ Name, Namespace string } `json:"metadata"`
		Subsets  []struct {
			Addresses []struct {
				IP string `json:"ip"`
			} `json:"addresses"`
		} `json:"subsets"`
	} `json:"items"`
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	err := c.getOnce(ctx, path, out)
	if err != nil && errors.Is(err, errUnauthorized) && c.tokenPath != "" {
		// 401：投射卷可能已轮换 token，重读文件后重试一次
		c.reloadToken()
		return c.getOnce(ctx, path, out)
	}
	return err
}

// errUnauthorized 标记 kube API 401（供 get 触发 token 重读重试）。
var errUnauthorized = errors.New("kube API 401 Unauthorized")

func (c *Client) getOnce(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("kube API %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out)
}

// podItem 一次成功 Pod 列表的解析结果（owner 解析在 ReplicaSet 查询后完成）。
type podItem struct {
	ip    string
	meta  Metadata
	owner *ownerRef
}

// sync 拉取全量快照。endpoints 失败视为整体失败（保留旧快照并置 STALE）；
// ReplicaSet 列表失败只降级该 namespace 的 Deployment 归属为截尾推断（fail-open）。
func (c *Client) sync(ctx context.Context) (map[string]entry, error) {
	c.reloadToken() // 每轮 sync 重读 token（投射卷轮换）；失败沿用旧 token

	var pods []podItem
	namespaces := map[string]struct{}{}
	rsNeeded := map[string]bool{} // 存在 ReplicaSet owner 的 namespace
	{
		var page podList
		cont := ""
		for {
			q := url.Values{"limit": {pageLimit}, "fieldSelector": {"spec.nodeName=" + c.nodeName + ",status.phase=Running"}}
			if cont != "" {
				q.Set("continue", cont)
			}
			page = podList{}
			if err := c.get(ctx, "/api/v1/pods?"+q.Encode(), &page); err != nil {
				return nil, err
			}
			for _, p := range page.Items {
				// hostNetwork Pod 的 podIP 即节点 IP，归属到 Pod 会把节点级
				// 流量错误归到该工作负载——跳过。
				if p.Status.PodIP == "" || p.Spec.HostNetwork {
					continue
				}
				ns := p.Metadata.Namespace
				namespaces[ns] = struct{}{}
				item := podItem{ip: p.Status.PodIP, meta: Metadata{Cluster: c.cluster, Namespace: ns, Pod: p.Metadata.Name}}
				if len(p.Metadata.OwnerReferences) > 0 {
					o := p.Metadata.OwnerReferences[0]
					item.owner = &o
					if o.Kind == "ReplicaSet" {
						rsNeeded[ns] = true
					}
				}
				pods = append(pods, item)
			}
			cont = page.Metadata.Continue
			if cont == "" {
				break
			}
		}
	}

	// ReplicaSet → Deployment 权威解析：仅查询本节点 Pod 所在 namespace。
	// 值存在即"已权威解析"；空值表示独立 ReplicaSet（非 Deployment 管辖）。
	rsResolved := map[string]string{} // "ns/name" → Deployment 名（空 = 独立 RS）
	for ns := range namespaces {
		if !rsNeeded[ns] {
			continue
		}
		owners, err := c.listReplicaSetOwners(ctx, ns)
		if err != nil {
			// fail-open：RBAC 缺 apps/replicasets 或临时故障时，Deployment 归属
			// 降级为截尾推断并在 Health.InferredOwners 中显式计数。
			if c.log != nil {
				c.log.Warn("ReplicaSet 列表失败，Deployment 归属降级为截尾推断", "namespace", ns, "err", err)
			}
			continue
		}
		for k, v := range owners {
			rsResolved[k] = v
		}
	}

	out := make(map[string]entry, len(pods))
	for _, p := range pods {
		e := entry{meta: p.meta}
		switch {
		case p.owner == nil:
			e.meta.Workload = p.meta.Pod // 无 owner：工作负载即 Pod 本身（权威）
		case p.owner.Kind == "ReplicaSet":
			if dep, ok := rsResolved[p.meta.Namespace+"/"+p.owner.Name]; ok {
				if dep != "" {
					e.meta.Workload = dep
				} else {
					e.meta.Workload = p.owner.Name
				}
			} else {
				e.meta.Workload = truncateReplicaSetName(p.owner.Name)
				e.inferred = true
			}
		default:
			// StatefulSet/DaemonSet/Job 等直接 owner：名称权威。
			e.meta.Workload = p.owner.Name
		}
		out[p.ip] = e
	}

	// Endpoints 按本节点 Pod 所在 namespace 分别查询（替代全集群分页）。
	for ns := range namespaces {
		var page endpointList
		cont := ""
		for {
			q := url.Values{"limit": {pageLimit}}
			if cont != "" {
				q.Set("continue", cont)
			}
			page = endpointList{}
			if err := c.get(ctx, "/api/v1/namespaces/"+url.PathEscape(ns)+"/endpoints?"+q.Encode(), &page); err != nil {
				return nil, err
			}
			for _, ep := range page.Items {
				for _, ss := range ep.Subsets {
					for _, a := range ss.Addresses {
						if e, ok := out[a.IP]; ok && e.meta.Namespace == ep.Metadata.Namespace {
							e.meta.Service = ep.Metadata.Name
							out[a.IP] = e
						}
					}
				}
			}
			cont = page.Metadata.Continue
			if cont == "" {
				break
			}
		}
	}
	return out, nil
}

// listReplicaSetOwners 列出 namespace 内 ReplicaSet 的 Deployment 归属。
// 返回键 "ns/name"；值为 Deployment 名，空值表示该 RS 无 Deployment owner（独立 RS）。
func (c *Client) listReplicaSetOwners(ctx context.Context, ns string) (map[string]string, error) {
	out := map[string]string{}
	var page replicaSetList
	cont := ""
	for {
		q := url.Values{"limit": {pageLimit}}
		if cont != "" {
			q.Set("continue", cont)
		}
		page = replicaSetList{}
		if err := c.get(ctx, "/apis/apps/v1/namespaces/"+url.PathEscape(ns)+"/replicasets?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		for _, rs := range page.Items {
			owner := ""
			for _, o := range rs.Metadata.OwnerReferences {
				if o.Kind == "Deployment" {
					owner = o.Name
					break
				}
			}
			out[ns+"/"+rs.Metadata.Name] = owner
		}
		cont = page.Metadata.Continue
		if cont == "" {
			return out, nil
		}
	}
}

// truncateReplicaSetName 截尾推断 Deployment 名（仅作 ReplicaSet 权威解析
// 不可用时的降级路径；结果必须经 entry.inferred 显式标记为推断）。
func truncateReplicaSetName(name string) string {
	if i := strings.LastIndexByte(name, '-'); i > 0 {
		return name[:i]
	}
	return name
}

// Run refreshes immediately and then every DefaultRefreshInterval, retaining stale
// data on error (STALE → UNAVAILABLE 经 Resolver.Health 显式输出，采集不中断).
func (c *Client) Run(ctx context.Context, r *Resolver) {
	interval := c.refreshInterval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	syncOnce := func() {
		entries, err := c.sync(ctx)
		if err != nil {
			r.noteFailure(err, time.Now())
			if c.log != nil {
				c.log.Warn("Kubernetes 元数据同步失败，保留旧快照", "err", err, "state", string(r.Health().State))
			}
			return
		}
		r.replaceAll(entries, time.Now())
	}
	syncOnce()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce()
		}
	}
}
