package apiassets

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestDirectoryOf(t *testing.T) {
	cases := map[string]string{
		"/test/php/login": "/test/php",
		"/users/{id}":     "/users",
		"/a/b":            "/a",
		"/health":         "",
		"/":               "",
		"":                "",
	}
	for in, want := range cases {
		if got := DirectoryOf(in); got != want {
			t.Fatalf("DirectoryOf(%q)=%q want %q", in, got, want)
		}
	}
}

// 发现回填归属与目录；命中不覆盖归属（允许后续人工改属）。
func TestUpsertDiscoveryFillsSiteAndDirectory(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	appID := uuid.New()
	domID := uuid.New()
	e, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "POST", PathTemplate: "/test/php/login", Confidence: 0.9, IsAPI: true,
		ApplicationID: &appID, DomainID: &domID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.DirectoryPath != "/test/php" {
		t.Fatalf("directory=%q", e.DirectoryPath)
	}
	if e.ApplicationID == nil || *e.ApplicationID != appID || e.DomainID == nil || *e.DomainID != domID {
		t.Fatalf("site/domain not filled: %+v", e)
	}
	// 命中（同端点键）不覆盖归属
	if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{
		Method: "POST", PathTemplate: "/test/php/login", Confidence: 0.95, IsAPI: true,
	}); err != nil {
		t.Fatal(err)
	}
	again, err := store.GetByID(ctx, e.ID)
	if err != nil {
		t.Fatal(err)
	}
	if again.ApplicationID == nil || *again.ApplicationID != appID {
		t.Fatalf("site overwritten on hit: %+v", again)
	}
}

// 未归属过滤与目录前缀过滤、目录树聚合。
func TestListUnassignedAndDirectoryFilters(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	appID := uuid.New()
	mk := func(method, path string, app *uuid.UUID) {
		if _, err := store.UpsertDiscovery(ctx, DiscoveryInput{
			Method: method, PathTemplate: path, Confidence: 0.5, IsAPI: true, ApplicationID: app,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mk("GET", "/test/php/login", &appID)
	mk("GET", "/test/php/logout", &appID)
	mk("GET", "/test/index", &appID)
	mk("GET", "/other/a", nil)

	// 目录前缀：/test/php 仅命中自身
	list, total, err := store.List(ctx, ListFilter{DirectoryPrefix: "/test/php"})
	if err != nil || total != 2 || len(list) != 2 {
		t.Fatalf("prefix /test/php total=%d len=%d err=%v", total, len(list), err)
	}
	// 目录前缀：/test 命中自身与子目录（3 条）
	if _, total, _ = store.List(ctx, ListFilter{DirectoryPrefix: "/test"}); total != 3 {
		t.Fatalf("prefix /test total=%d", total)
	}
	// 未归属：仅 /other/a
	list, total, err = store.List(ctx, ListFilter{Unassigned: true})
	if err != nil || total != 1 || list[0].NormalizedPath != "/other/a" {
		t.Fatalf("unassigned total=%d list=%+v err=%v", total, list, err)
	}
	// 站点汇总（内存实现仅未归属桶）
	_, unassigned, err := store.SiteSummary(ctx)
	if err != nil || unassigned != 1 {
		t.Fatalf("site summary unassigned=%d err=%v", unassigned, err)
	}
	// 目录树聚合
	tree, err := store.DirectoryTree(ctx, &appID, false)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, dc := range tree {
		counts[dc.DirectoryPath] = dc.EndpointCount
	}
	if counts["/test/php"] != 2 || counts["/test"] != 1 {
		t.Fatalf("tree=%+v", tree)
	}
}
