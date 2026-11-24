package main

import (
	"crypto/tls"
	"fmt"
	"strings"
)

var namedCipherSuites = map[string]uint16{
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":         tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":         tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256":       tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384":       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
}

func buildTLSConfig(version, cipherName, serverName string, insecure, resume bool) (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: insecure, //nolint:gosec // 压测自签证书环境显式可控
		ServerName:         serverName,
	}

	switch strings.ToLower(strings.TrimSpace(version)) {
	case "", "auto":
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS13
	case "1.2", "tls1.2", "tls12":
		cfg.MinVersion = tls.VersionTLS12
		cfg.MaxVersion = tls.VersionTLS12
	case "1.3", "tls1.3", "tls13":
		cfg.MinVersion = tls.VersionTLS13
		cfg.MaxVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("unsupported tls-version %q (want auto, 1.2, 1.3)", version)
	}

	if strings.TrimSpace(cipherName) != "" {
		if cfg.MinVersion == tls.VersionTLS13 {
			return nil, fmt.Errorf("tls-cipher cannot be locked in Go when tls-version=1.3 (TLS 1.3 ciphers are auto-negotiated)")
		}
		id, ok := namedCipherSuites[strings.ToUpper(strings.TrimSpace(cipherName))]
		if !ok {
			return nil, fmt.Errorf("unsupported tls-cipher %q", cipherName)
		}
		cfg.CipherSuites = []uint16{id}
	}

	if resume {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(65536)
	} else {
		cfg.ClientSessionCache = nil
	}
	return cfg, nil
}
