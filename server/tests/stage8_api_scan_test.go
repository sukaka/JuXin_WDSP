// stage8_api_scan_test.go API 主动扫描（W6-D / P1-07）集成测试：
// 真实 PostgreSQL 验证迁移 000053/000054 建表 + apiscan.Store 全生命周期
// （目标/授权/任务/发现、claim 互斥、停止不被完成覆盖、发现一次性处置、撤销幂等）、
// 迁移 down/up 往返（直读 SQL 文件执行，不经 migrate 机制避免影响其他分片迁移）。
package tests

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiscan"
)

// createScanTestApp 创建测试应用（api_scan_targets.application_id 外键）。
func createScanTestApp(t *testing.T, env *testEnv) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := env.db.QueryRow(context.Background(),
		`INSERT INTO applications (code, name) VALUES ($1, $2) RETURNING id`,
		"scan-test-"+uuid.NewString()[:8], "主动扫描测试应用").Scan(&id)
	if err != nil {
		t.Fatalf("create application: %v", err)
	}
	return id
}

// scanAdminUserID 取 setupTestEnv 创建的管理员用户 ID（authorized_by 外键）。
func scanAdminUserID(t *testing.T, env *testEnv) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := env.db.QueryRow(context.Background(),
		`SELECT id FROM users WHERE username = 'test_sysadmin'`).Scan(&id)
	if err != nil {
		t.Fatalf("query admin user: %v", err)
	}
	return id
}

// TestAPIScanStoreIntegration 存储全生命周期（真实 PG）。
func TestAPIScanStoreIntegration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	appID := createScanTestApp(t, env)
	store := apiscan.NewStore(env.db)

	// ---- 目标 ----
	target := &apiscan.Target{
		ApplicationID: appID, Name: "测试目标", BaseURL: "http://127.0.0.1:8080",
		AllowedPaths: []string{"/v1/users", "/v1/orders/1"},
	}
	if err := store.CreateTarget(ctx, target); err != nil {
		t.Fatalf("create target: %v", err)
	}
	got, err := store.GetTarget(ctx, target.ID)
	if err != nil || got.Name != "测试目标" || got.Status != apiscan.TargetStatusEnabled {
		t.Fatalf("get target: %+v err=%v", got, err)
	}
	if len(got.AllowedPaths) != 2 || got.AllowedPaths[0] != "/v1/users" {
		t.Fatalf("allowed_paths roundtrip: %+v", got.AllowedPaths)
	}
	// 外键：不存在的应用 → 23503
	bad := &apiscan.Target{ApplicationID: uuid.New(), Name: "x", BaseURL: "http://a.com"}
	if err := store.CreateTarget(ctx, bad); err == nil {
		t.Fatal("target with unknown application should fail (FK)")
	}
	// 更新（停用）
	got.Status = apiscan.TargetStatusDisabled
	if err := store.UpdateTarget(ctx, got); err != nil {
		t.Fatalf("update target: %v", err)
	}
	list, total, err := store.ListTargets(ctx, &appID, apiscan.TargetStatusDisabled, 1, 20)
	if err != nil || total != 1 || list[0].ID != target.ID {
		t.Fatalf("list targets: total=%d err=%v", total, err)
	}
	got.Status = apiscan.TargetStatusEnabled
	if err := store.UpdateTarget(ctx, got); err != nil {
		t.Fatalf("re-enable target: %v", err)
	}

	// ---- 授权 ----
	start := time.Now().Add(-time.Hour)
	end := time.Now().Add(2 * time.Hour)
	authz := &apiscan.Authorization{
		TargetID: target.ID, AuthorizedBy: scanAdminUserID(t, env),
		Allowlist: []string{"127.0.0.1"}, TimeWindow: apiscan.TimeWindow{Start: &start, End: &end},
		MaxQPS: 10, MaxConcurrency: 2, TestProfile: "AUTH_REQUIRED,METHOD_ENUM",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := store.CreateAuthorization(ctx, authz); err != nil {
		t.Fatalf("create authorization: %v", err)
	}
	gotA, err := store.GetAuthorization(ctx, authz.ID)
	if err != nil {
		t.Fatalf("get authorization: %v", err)
	}
	if !gotA.Active(time.Now()) {
		t.Fatal("authorization should be active")
	}
	if len(gotA.Allowlist) != 1 || gotA.TimeWindow.Start == nil || gotA.TimeWindow.End == nil {
		t.Fatalf("authorization jsonb roundtrip: %+v", gotA)
	}
	alist, atotal, err := store.ListAuthorizations(ctx, target.ID, 1, 20)
	if err != nil || atotal != 1 || alist[0].ID != authz.ID {
		t.Fatalf("list authorizations: total=%d err=%v", atotal, err)
	}

	// ---- 任务生命周期：创建 → claim（互斥）→ 进度 → 完成 ----
	job := &apiscan.Job{TargetID: target.ID, AuthorizationID: authz.ID, ProbeSet: "AUTH_REQUIRED"}
	if err := store.CreateJob(ctx, job); err != nil {
		t.Fatalf("create job: %v", err)
	}
	if job.Status != apiscan.JobStatusPending {
		t.Fatalf("job default status=%s", job.Status)
	}
	job2 := &apiscan.Job{TargetID: target.ID, AuthorizationID: authz.ID}
	if err := store.CreateJob(ctx, job2); err != nil {
		t.Fatalf("create job2: %v", err)
	}
	claimed, err := store.ClaimPendingJob(ctx, time.Now())
	if err != nil || claimed == nil || claimed.ID != job.ID {
		t.Fatalf("claim: %+v err=%v", claimed, err)
	}
	if claimed.Status != apiscan.JobStatusRunning || claimed.StartedAt == nil {
		t.Fatalf("claimed job: %+v", claimed)
	}
	// 同目标互斥：job2 不可取
	again, err := store.ClaimPendingJob(ctx, time.Now())
	if err != nil || again != nil {
		t.Fatalf("same-target exclusion: %+v err=%v", again, err)
	}
	// 进度保存（仅 RUNNING）
	p := apiscan.Progress{Total: 2, Done: 1, Requests: 3}
	if _, err := store.SaveJobProgress(ctx, job.ID, p); err != nil {
		t.Fatalf("save progress: %v", err)
	}
	p.Done, p.Requests, p.Findings = 2, 6, 1
	finished, err := store.FinishJob(ctx, job.ID, apiscan.JobStatusCompleted, p, time.Now())
	if err != nil {
		t.Fatalf("finish job: %v", err)
	}
	if finished.Status != apiscan.JobStatusCompleted || finished.FinishedAt == nil ||
		finished.Progress.Findings != 1 || finished.Progress.Requests != 6 {
		t.Fatalf("finished job: %+v", finished)
	}
	// job2 现在可取
	claimed2, err := store.ClaimPendingJob(ctx, time.Now())
	if err != nil || claimed2 == nil || claimed2.ID != job2.ID {
		t.Fatalf("second claim: %+v err=%v", claimed2, err)
	}

	// ---- 停止不被完成覆盖（停止优先）----
	if _, err := store.StopJob(ctx, job2.ID, time.Now()); err != nil {
		t.Fatalf("stop job2: %v", err)
	}
	after, err := store.FinishJob(ctx, job2.ID, apiscan.JobStatusCompleted, apiscan.Progress{}, time.Now())
	if err != nil {
		t.Fatalf("finish after stop: %v", err)
	}
	if after.Status != apiscan.JobStatusStopped {
		t.Fatalf("stopped job overridden by finish: %s", after.Status)
	}
	// 终态再停止 → ErrInvalidTransition
	if _, err := store.StopJob(ctx, job2.ID, time.Now()); err != apiscan.ErrInvalidTransition {
		t.Fatalf("stop terminal: %v", err)
	}

	// ---- 撤销幂等 + 按授权停止 ----
	job3 := &apiscan.Job{TargetID: target.ID, AuthorizationID: authz.ID}
	if err := store.CreateJob(ctx, job3); err != nil {
		t.Fatalf("create job3: %v", err)
	}
	revoked, err := store.RevokeAuthorization(ctx, authz.ID, time.Now())
	if err != nil || revoked.RevokedAt == nil {
		t.Fatalf("revoke: %+v err=%v", revoked, err)
	}
	stopped, err := store.StopJobsByAuthorization(ctx, authz.ID, time.Now())
	if err != nil || stopped != 1 {
		t.Fatalf("stop by authorization: %d err=%v", stopped, err)
	}
	firstRevokedAt := *revoked.RevokedAt
	again2, err := store.RevokeAuthorization(ctx, authz.ID, time.Now().Add(time.Minute))
	if err != nil || !again2.RevokedAt.Equal(firstRevokedAt) {
		t.Fatalf("revoke not idempotent: %+v", again2)
	}

	// ---- 发现 ----
	finding := &apiscan.Finding{
		JobID: job.ID, Template: apiscan.ProbeAuthRequired, EndpointKey: "GET /v1/users",
		Category: apiscan.CategoryAuthn, Severity: apiscan.SeverityHigh, Confidence: 0.9,
		Evidence:      map[string]any{"rule": "unauthenticated_request_returned_2xx", "status_code": 200},
		RequestSample: "GET /v1/users HTTP/1.1\r\nAuthorization: [redacted]\r\n",
	}
	if err := store.CreateFinding(ctx, finding); err != nil {
		t.Fatalf("create finding: %v", err)
	}
	if finding.Status != apiscan.FindingStatusNew || finding.Engine != "builtin" {
		t.Fatalf("finding defaults: %+v", finding)
	}
	gotF, err := store.GetFinding(ctx, finding.ID)
	if err != nil {
		t.Fatalf("get finding: %v", err)
	}
	ev, _ := gotF.Evidence.(map[string]any)
	if ev["rule"] != "unauthenticated_request_returned_2xx" {
		t.Fatalf("evidence roundtrip: %+v", gotF.Evidence)
	}
	flist, ftotal, err := store.ListFindings(ctx, apiscan.FindingFilter{JobID: &job.ID, Severity: apiscan.SeverityHigh})
	if err != nil || ftotal != 1 || flist[0].ID != finding.ID {
		t.Fatalf("list findings: total=%d err=%v", ftotal, err)
	}
	// 一次性处置：NEW→CONFIRMED 后不可再处置（weakness_id 须为真实弱点——FK 生效）
	var weaknessID uuid.UUID
	if err := env.db.QueryRow(ctx,
		`INSERT INTO api_weaknesses (weakness_code, weakness_name) VALUES ('UNAUTHENTICATED_SENSITIVE_API', '测试弱点') RETURNING id`).Scan(&weaknessID); err != nil {
		t.Fatalf("create weakness: %v", err)
	}
	cf, err := store.SetFindingStatus(ctx, finding.ID, apiscan.FindingStatusConfirmed, &weaknessID)
	if err != nil || cf.Status != apiscan.FindingStatusConfirmed || cf.WeaknessID == nil {
		t.Fatalf("confirm finding: %+v err=%v", cf, err)
	}
	if _, err := store.SetFindingStatus(ctx, finding.ID, apiscan.FindingStatusFalsePositive, nil); err != apiscan.ErrInvalidTransition {
		t.Fatalf("re-dispose: %v", err)
	}
	// 状态 CHECK：词表外状态被数据库拒绝
	if _, err := env.db.Exec(ctx,
		`INSERT INTO api_scan_findings (job_id, template, status) VALUES ($1, 'AUTH_REQUIRED', 'OPEN')`, job.ID); err == nil {
		t.Fatal("invalid finding status should be rejected by CHECK")
	}
	// 任务状态 CHECK
	if _, err := env.db.Exec(ctx,
		`INSERT INTO api_scan_jobs (target_id, authorization_id, status) VALUES ($1, $2, 'BOGUS')`, target.ID, authz.ID); err == nil {
		t.Fatal("invalid job status should be rejected by CHECK")
	}
}

// TestAPIScanMigrationDownUp 迁移 000053/000054 down/up 往返（直接执行 SQL 文件）。
func TestAPIScanMigrationDownUp(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	tableExists := func(name string) bool {
		var exists bool
		if err := env.db.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`, name).Scan(&exists); err != nil {
			t.Fatalf("check table %s: %v", name, err)
		}
		return exists
	}
	for _, tbl := range []string{"api_scan_targets", "api_scan_authorizations", "api_scan_jobs", "api_scan_findings"} {
		if !tableExists(tbl) {
			t.Fatalf("table %s missing after migrate up", tbl)
		}
	}
	execFile := func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if _, err := env.db.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("exec %s: %v", path, err)
		}
	}
	// down（依赖逆序：findings → core）
	execFile("../migrations/000054_api_scan_findings.down.sql")
	execFile("../migrations/000053_api_scan_core.down.sql")
	for _, tbl := range []string{"api_scan_targets", "api_scan_authorizations", "api_scan_jobs", "api_scan_findings"} {
		if tableExists(tbl) {
			t.Fatalf("table %s still exists after down", tbl)
		}
	}
	// up 恢复
	execFile("../migrations/000053_api_scan_core.up.sql")
	execFile("../migrations/000054_api_scan_findings.up.sql")
	for _, tbl := range []string{"api_scan_targets", "api_scan_authorizations", "api_scan_jobs", "api_scan_findings"} {
		if !tableExists(tbl) {
			t.Fatalf("table %s missing after re-up", tbl)
		}
	}
}
