// hasyncd is the lightweight, zero-third-party-dependency HA node sync sidecar for
// JiuZhang WDSP. It exposes an HMAC-SHA256 authenticated HTTP(S) control API for
// cross-node Caddy reloads, sidecar sync, hostctl firewall rules, telemetry collection,
// and offline upgrade staging.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jiuzhang-waf/gateway/hasyncd"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "hasyncd error: %v\n", err)
		os.Exit(1)
	}
}

func envOr(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func envDefault(def string, keys ...string) string {
	if v := envOr(keys...); v != "" {
		return v
	}
	return def
}

func run() error {
	var (
		listenAddr         = flag.String("listen", envDefault(hasyncd.DefaultListenAddr, "HASYNC_LISTEN"), "HTTP(S) listen address (default 127.0.0.1:18443)")
		nodeName           = flag.String("node", envOr("GATEWAY_NODE_NAME", "NODE_NAME"), "Gateway node identifier (required; env GATEWAY_NODE_NAME)")
		secretFile         = flag.String("secret-file", envOr("HASYNC_SECRET_FILE"), "Path to HMAC shared secret file (>=32-byte hex; env HASYNC_SECRET_FILE)")
		tlsCert            = flag.String("tls-cert", envOr("HASYNC_TLS_CERT"), "Optional TLS server certificate PEM path")
		tlsKey             = flag.String("tls-key", envOr("HASYNC_TLS_KEY"), "Optional TLS server private key PEM path")
		caddySocket        = flag.String("caddy-socket", envDefault(hasyncd.DefaultCaddySocket, "HASYNC_CADDY_SOCKET", "CADDY_ADMIN_SOCKET"), "Local Caddy Admin Unix socket path")
		sidecarDir         = flag.String("sidecar-dir", envDefault(hasyncd.DefaultSidecarDir, "HASYNC_SIDECAR_DIR"), "Local sidecar configuration/status directory")
		hostctlDir         = flag.String("hostctl-dir", envDefault(hasyncd.DefaultHostctlDir, "HOSTCTL_DIR", "HASYNC_HOSTCTL_DIR"), "Local hostctl flag directory")
		upgradesDir        = flag.String("upgrades-dir", envDefault(hasyncd.DefaultUpgradesDir, "HASYNC_UPGRADES_DIR"), "Local upgrades root directory (packages/ and executor/)")
		upgradePackagesDir = flag.String("upgrade-packages-dir", envOr("UPGRADE_PACKAGES_DIR"), "Optional override for upgrade packages directory")
		upgradeExecutorDir = flag.String("upgrade-executor-dir", envOr("UPGRADE_EXECUTOR_DIR"), "Optional override for upgrade executor directory")
		nodeIfacesLog      = flag.String("node-ifaces-log", envDefault(hasyncd.DefaultNodeIfacesLog, "HASYNC_NODE_IFACES_LOG"), "Path to node-interfaces.jsonl snapshot file")
		version            = flag.String("version", envOr("APP_VERSION", "HASYNC_VERSION"), "Reported application version (env APP_VERSION)")
		versionFile        = flag.String("version-file", envOr("APP_VERSION_FILE", "HASYNC_VERSION_FILE"), "Optional version file path fallback")
		healthStamp        = flag.String("health-stamp", envDefault(hasyncd.DefaultHealthStampPath, "HASYNC_HEALTH_STAMP"), "Local health stamp file path for --healthcheck")
		healthcheck        = flag.Bool("healthcheck", false, "Check local health stamp readiness and exit 0/1 (no unauthenticated TCP endpoint)")
	)
	flag.Parse()

	if *healthcheck {
		return hasyncd.CheckHealthStamp(*healthStamp, time.Now().UTC(), hasyncd.DefaultHealthStampMaxAge)
	}

	srv, err := hasyncd.NewServer(hasyncd.Config{
		ListenAddr:         *listenAddr,
		NodeName:           *nodeName,
		SecretFile:         *secretFile,
		TLSCertFile:        *tlsCert,
		TLSKeyFile:         *tlsKey,
		CaddySocket:        *caddySocket,
		SidecarDir:         *sidecarDir,
		HostctlDir:         *hostctlDir,
		UpgradesDir:        *upgradesDir,
		UpgradePackagesDir: *upgradePackagesDir,
		UpgradeExecutorDir: *upgradeExecutorDir,
		NodeIfacesLog:      *nodeIfacesLog,
		Version:            *version,
		VersionFile:        *versionFile,
		HealthStampPath:    *healthStamp,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Printf("[hasyncd] starting node=%s listen=%s caddy_sock=%s sidecar_dir=%s hostctl_dir=%s upgrades_dir=%s",
		*nodeName, *listenAddr, *caddySocket, *sidecarDir, *hostctlDir, *upgradesDir)
	return srv.Run(ctx)
}
