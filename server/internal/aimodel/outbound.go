package aimodel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/server/internal/outboundhttp"
)

// ErrInvalidProviderEndpoint marks a provider URL or target scope rejected by
// the outbound security policy.
var ErrInvalidProviderEndpoint = errors.New("invalid AI provider endpoint")

// CanonicalOrigin returns the persisted identity of a provider endpoint. Paths,
// queries and fragments are intentionally excluded from the binding.
func CanonicalOrigin(raw string) (string, error) {
	u, err := outboundhttp.ParseURL(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidProviderEndpoint, err)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

var sensitiveProviderHosts = map[string]bool{
	"localhost": true, "metadata.google.internal": true, "metadata": true,
	"caddy": true, "docker": true, "db": true, "database": true,
	"postgres": true, "postgresql": true, "mysql": true, "valkey": true,
	"redis": true, "server": true, "gateway": true,
}

var sensitiveProviderPorts = map[string]bool{
	"2019": true,               // Caddy admin
	"2375": true, "2376": true, // Docker API
	"3306": true, "5432": true, // MySQL/PostgreSQL
	"6379": true, // Redis/Valkey
}

func providerHostDenied(host string, port string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if sensitiveProviderHosts[host] || strings.HasSuffix(host, ".metadata.google.internal") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLinkLocalUnicast() || ip.Equal(net.ParseIP("fd00:ec2::254")) {
			return true
		}
	}
	return sensitiveProviderPorts[port]
}

// ValidateProviderEndpoint validates the configured endpoint and target scope.
// It performs DNS resolution now; requestClient repeats resolution while dialing.
func ValidateProviderEndpoint(ctx context.Context, p *Provider) error {
	if p == nil {
		return fmt.Errorf("%w: provider is nil", ErrInvalidProviderEndpoint)
	}
	u, err := outboundhttp.ParseURL(p.BaseURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProviderEndpoint, err)
	}
	if providerHostDenied(u.Hostname(), u.Port()) {
		return fmt.Errorf("%w: %w: sensitive target denied", ErrInvalidProviderEndpoint, outboundhttp.ErrDenied)
	}
	if len(p.AllowedTargets) > 32 {
		return fmt.Errorf("%w: too many allowed targets", ErrInvalidProviderEndpoint)
	}
	allow := make([]string, 0, len(p.AllowedTargets)+1)
	for _, target := range p.AllowedTargets {
		target = strings.TrimSpace(target)
		if target == "" || len(target) > 253 {
			return fmt.Errorf("%w: invalid allowed target", ErrInvalidProviderEndpoint)
		}
		allow = append(allow, target)
	}
	// The compose service name is an explicit, supported local Ollama target.
	// Other private/local targets still require an administrator scope entry.
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if (p.Type == ProviderOllama || p.Type == ProviderLocal) && host == "ollama" && u.Port() == "11434" {
		allow = append(allow, host)
	}
	policy, err := outboundhttp.NewPolicy(outboundhttp.Options{Allowlist: strings.Join(allow, ","), MaxRedirects: 0})
	if err != nil {
		return fmt.Errorf("%w: target scope: %w", ErrInvalidProviderEndpoint, err)
	}
	if _, err := policy.ValidateURL(ctx, p.BaseURL); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidProviderEndpoint, err)
	}
	return nil
}

func providerURL(p *Provider) (*url.URL, error) {
	u, err := outboundhttp.ParseURL(p.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidProviderEndpoint, err)
	}
	return u, nil
}

func providerPolicy(p *Provider) (*outboundhttp.Policy, error) {
	allow := strings.Join(p.AllowedTargets, ",")
	host := strings.ToLower(strings.TrimSuffix(mustURLHost(p.BaseURL), "."))
	u, err := providerURL(p)
	if err != nil {
		return nil, err
	}
	if (p.Type == ProviderOllama || p.Type == ProviderLocal) && host == "ollama" && u.Port() == "11434" {
		if allow != "" {
			allow += ","
		}
		allow += "ollama"
	}
	return outboundhttp.NewPolicy(outboundhttp.Options{Allowlist: allow, MaxRedirects: 0})
}

func mustURLHost(raw string) string {
	u, _ := outboundhttp.ParseURL(raw)
	if u == nil {
		return ""
	}
	return u.Hostname()
}

func validatePersistedOrigin(p *Provider) error {
	origin, err := CanonicalOrigin(p.BaseURL)
	if err != nil {
		return err
	}
	if p.CanonicalOrigin != "" && p.CanonicalOrigin != origin {
		return fmt.Errorf("%w: provider origin changed; re-enter API key", ErrInvalidProviderEndpoint)
	}
	p.CanonicalOrigin = origin
	return nil
}

func validPort(raw string) bool {
	n, err := strconv.Atoi(raw)
	return err == nil && n >= 1 && n <= 65535
}
