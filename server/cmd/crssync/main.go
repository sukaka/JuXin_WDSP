package main

import (
	"context"
	"fmt"
	"os"

	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/wafrules"
)

func main() {
	cfg := config.DBConfig{
		Host: "127.0.0.1", Port: 5432, Database: "jiuzhang_waf",
		User: "jiuzhang", Password: os.Getenv("POSTGRES_PASSWORD"), SSLMode: "disable", MaxConns: 2,
	}
	db, err := database.Connect(context.Background(), cfg)
	if err != nil {
		fmt.Println("connect:", err)
		os.Exit(1)
	}
	defer db.Close()
	svc := wafrules.NewSyncService(db)
	report, err := svc.SyncFromDirectory(context.Background(), "/Users/zhanglei/Documents/JiuZhang_WAF/gateway/rules/crs/rules", "4.28.0")
	if err != nil {
		fmt.Println("sync:", err)
		os.Exit(1)
	}
	fmt.Printf("parsed=%d added=%d updated=%d unchanged=%d missing=%d parse_failed=%d conflicts=%d total_in_db=%d\n",
		report.TotalParsed, report.Added, report.Updated, report.Unchanged, report.Missing, report.ParseFailed, report.Conflicts, report.TotalInDB)
	if len(report.FailedRules) > 0 {
		fmt.Println("failed sample:", report.FailedRules[:min(3, len(report.FailedRules))])
	}
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
