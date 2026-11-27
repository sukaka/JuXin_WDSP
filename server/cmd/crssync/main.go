package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/wafrules"
)

type syncOptions struct {
	rulesDir   string
	crsVersion string
	db         config.DBConfig
}

func envOrDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func parseOptions(args []string, stderr io.Writer) (syncOptions, error) {
	fs := flag.NewFlagSet("crssync", flag.ContinueOnError)
	fs.SetOutput(stderr)

	rulesDir := fs.String("rules-dir", envOrDefault("WAF_CRS_DIR", "gateway/rules/crs/rules"), "OWASP CRS rules directory (env: WAF_CRS_DIR)")
	crsVersion := fs.String("crs-version", envOrDefault("WAF_CRS_VERSION", "4.28.0"), "OWASP CRS version label (env: WAF_CRS_VERSION)")
	if err := fs.Parse(args); err != nil {
		return syncOptions{}, err
	}

	dir := strings.TrimSpace(*rulesDir)
	if dir == "" {
		return syncOptions{}, fmt.Errorf("rules-dir is required")
	}
	ver := strings.TrimSpace(*crsVersion)
	if ver == "" {
		return syncOptions{}, fmt.Errorf("crs-version is required")
	}

	dbCfg, err := config.LoadDBConfig()
	if err != nil {
		return syncOptions{}, err
	}
	if dbCfg.MaxConns <= 0 || dbCfg.MaxConns > 4 {
		dbCfg.MaxConns = 2
	}
	if dbCfg.MinConns > dbCfg.MaxConns {
		dbCfg.MinConns = 1
	}

	return syncOptions{
		rulesDir:   dir,
		crsVersion: ver,
		db:         dbCfg,
	}, nil
}

func main() {
	opts, err := parseOptions(os.Args[1:], os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	info, err := os.Stat(opts.rulesDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "rules-dir %q is not an accessible directory\n", opts.rulesDir)
		os.Exit(1)
	}

	db, err := database.Connect(context.Background(), opts.db)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer db.Close()

	svc := wafrules.NewSyncService(db)
	report, err := svc.SyncFromDirectory(context.Background(), opts.rulesDir, opts.crsVersion)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sync:", err)
		os.Exit(1)
	}
	fmt.Printf("parsed=%d added=%d updated=%d unchanged=%d missing=%d parse_failed=%d conflicts=%d total_in_db=%d\n",
		report.TotalParsed, report.Added, report.Updated, report.Unchanged, report.Missing, report.ParseFailed, report.Conflicts, report.TotalInDB)
	if len(report.FailedRules) > 0 {
		fmt.Println("failed sample:", report.FailedRules[:min(3, len(report.FailedRules))])
	}
}
