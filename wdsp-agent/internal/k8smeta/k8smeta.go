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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const (
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	pageLimit         = "500"
)

// Metadata is attached to an event when either endpoint matches a running Pod.
type Metadata struct {
	Cluster   string `json:"cluster"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Workload  string `json:"workload,omitempty"`
	Service   string `json:"service,omitempty"`
	Side      string `json:"side"`
}

type snapshot struct{ byIP map[string]Metadata }

// Resolver publishes complete snapshots atomically. A failed refresh never clears the old one.
type Resolver struct{ current atomic.Pointer[snapshot] }

func NewResolver() *Resolver { return &Resolver{} }

// Replace publishes an already-built IP map. It is exported for the client and focused tests.
func (r *Resolver) Replace(items map[string]Metadata) {
	copyMap := make(map[string]Metadata, len(items))
	for k, v := range items {
		copyMap[k] = v
	}
	r.current.Store(&snapshot{byIP: copyMap})
}

// Resolve prefers destination/server metadata when both endpoints are Pods.
func (r *Resolver) Resolve(srcIP, dstIP string) *Metadata {
	s := r.current.Load()
	if s == nil {
		return nil
	}
	if m, ok := s.byIP[dstIP]; ok {
		m.Side = "dst"
		return &m
	}
	if m, ok := s.byIP[srcIP]; ok {
		m.Side = "src"
		return &m
	}
	return nil
}

// Client is a stdlib-only in-cluster Kubernetes API client.
type Client struct {
	baseURL, token, nodeName, cluster string
	tokenPath                         string // ServiceAccount token 文件（投射卷轮换后重读）
	http                              *http.Client
	log                               *slog.Logger
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
	return &Client{baseURL: "https://" + host + ":" + port, token: strings.TrimSpace(string(token)), tokenPath: tokenPath, nodeName: nodeName, cluster: cluster, http: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}, Timeout: 15 * time.Second}, log: log}, nil
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
		Status struct {
			PodIP string `json:"podIP"`
		} `json:"status"`
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

func (c *Client) sync(ctx context.Context) (map[string]Metadata, error) {
	c.reloadToken() // 每轮 sync 重读 token（投射卷轮换）；失败沿用旧 token
	pods := map[string]Metadata{}
	cont := ""
	for {
		q := url.Values{"limit": {pageLimit}, "fieldSelector": {"spec.nodeName=" + c.nodeName + ",status.phase=Running"}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page podList
		if err := c.get(ctx, "/api/v1/pods?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		for _, p := range page.Items {
			if p.Status.PodIP == "" {
				continue
			}
			workload := p.Metadata.Name
			if len(p.Metadata.OwnerReferences) > 0 {
				workload = workloadName(p.Metadata.OwnerReferences[0])
			}
			pods[p.Status.PodIP] = Metadata{Cluster: c.cluster, Namespace: p.Metadata.Namespace, Pod: p.Metadata.Name, Workload: workload}
		}
		cont = page.Metadata.Continue
		if cont == "" {
			break
		}
	}
	cont = ""
	for {
		q := url.Values{"limit": {pageLimit}}
		if cont != "" {
			q.Set("continue", cont)
		}
		var page endpointList
		if err := c.get(ctx, "/api/v1/endpoints?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		for _, ep := range page.Items {
			for _, ss := range ep.Subsets {
				for _, a := range ss.Addresses {
					if m, ok := pods[a.IP]; ok && m.Namespace == ep.Metadata.Namespace {
						m.Service = ep.Metadata.Name
						pods[a.IP] = m
					}
				}
			}
		}
		cont = page.Metadata.Continue
		if cont == "" {
			break
		}
	}
	return pods, nil
}

func workloadName(o ownerRef) string {
	if o.Kind != "ReplicaSet" {
		return o.Name
	}
	if i := strings.LastIndexByte(o.Name, '-'); i > 0 {
		return o.Name[:i]
	}
	return o.Name
}

// Run refreshes immediately and then every 30 seconds, retaining stale data on error.
func (c *Client) Run(ctx context.Context, r *Resolver) {
	syncOnce := func() {
		items, err := c.sync(ctx)
		if err != nil {
			if c.log != nil {
				c.log.Warn("Kubernetes 元数据同步失败，保留旧快照", "err", err)
			}
			return
		}
		r.Replace(items)
	}
	syncOnce()
	ticker := time.NewTicker(30 * time.Second)
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
