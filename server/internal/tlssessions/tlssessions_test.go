package tlssessions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

func TestParseLineAllProtocolsAndEdgeCases(t *testing.T) {
	appID := uuid.New().String()
	protocols := []struct {
		raw      string
		want     string
		action   string
		cipher   string
		wantGM   bool
		isLegacy bool
	}{
		{"SSLv2", ProtoSSLv2, ActionBlockedLegacySSL, "", false, true},
		{"SSLv2/v3", ProtoSSLv2v3, ActionBlockedLegacySSL, "", false, true},
		{"SSLv2_v3", ProtoSSLv2v3, ActionBlockedLegacySSL, "", false, true},
		{"SSLv3", ProtoSSLv3, ActionBlockedLegacySSL, "", false, true},
		{"TLS1.0", ProtoTLS10, ActionBlockedProtocolPolicy, "", false, false},
		{"TLS1.1", ProtoTLS11, ActionAllowed, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", false, false},
		{"TLS1.2", ProtoTLS12, ActionAllowed, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", false, false},
		{"TLS1.3", ProtoTLS13, ActionAllowed, "TLS_AES_128_GCM_SHA256", false, false},
		{"TLCP1.1", ProtoTLCP11, ActionAllowed, "TLCP_ECC_SM4_GCM_SM3", true, false},
		{"UNKNOWN", ProtoUnknown, ActionHandshakeFailed, "", false, false},
	}

	for _, tc := range protocols {
		t.Run("protocol_"+tc.raw, func(t *testing.T) {
			line := fmt.Sprintf(
				`{"occurred_at":"2026-11-25T08:00:00Z","gateway_node_id":"gw-01","application_id":%q,`+
					`"sni":"APP.Example.COM","client_ip":"203.0.113.10","client_port":54321,"server_port":443,`+
					`"detected_protocol":%q,"negotiated_protocol":%q,"cipher_suite":%q,"is_gm":%v,`+
					`"ja3_hash":"ABCDEF0123456789ABCDEF0123456789","alpn":"h2","action":%q,"error_reason":""}`,
				appID, tc.raw, tc.want, tc.cipher, tc.wantGM, tc.action,
			)
			e, err := ParseLine([]byte(line))
			if err != nil {
				t.Fatalf("ParseLine(%s) unexpected error: %v", tc.raw, err)
			}
			if e.DetectedProtocol != tc.want {
				t.Errorf("DetectedProtocol = %q, want %q", e.DetectedProtocol, tc.want)
			}
			if e.IsGM != tc.wantGM {
				t.Errorf("IsGM = %v, want %v", e.IsGM, tc.wantGM)
			}
			if IsLegacyProtocol(e.DetectedProtocol) != tc.isLegacy {
				t.Errorf("IsLegacyProtocol(%q) = %v, want %v", e.DetectedProtocol, !tc.isLegacy, tc.isLegacy)
			}
			if e.SNI != "app.example.com" {
				t.Errorf("SNI = %q, want lowercase app.example.com", e.SNI)
			}
			if e.JA3Hash != "abcdef0123456789abcdef0123456789" {
				t.Errorf("JA3Hash = %q, want lowercase", e.JA3Hash)
			}
			if e.Action != tc.action {
				t.Errorf("Action = %q, want %q", e.Action, tc.action)
			}
		})
	}

	t.Run("rejects malformed and invalid lines", func(t *testing.T) {
		badLines := []string{
			"   \n",
			"{broken json",
			`{"sni":"a.com"}`,
			`{"occurred_at":"2026-11-25T08:00:00Z","action":"INVALID_ACTION"}`,
			`{"occurred_at":"2026-11-25T08:00:00Z","error_reason":"` + strings.Repeat("x", maxLineLen+10) + `"}`,
		}
		for _, bad := range badLines {
			if _, err := ParseLine([]byte(bad)); err == nil {
				t.Errorf("expected error for line len=%d", len(bad))
			}
		}
	})

	t.Run("sanitizes truncation, NUL, invalid ports, invalid uuid, and infers GM", func(t *testing.T) {
		line := fmt.Sprintf(
			`{"occurred_at":"2026-11-25T08:00:00Z","gateway_node_id":%q,"application_id":"not-a-uuid",`+
				`"sni":%q,"client_ip":"2001:0db8::1","client_port":99999,"server_port":-1,`+
				`"detected_protocol":"TLCP1.1","cipher_suite":"TLCP_ECC_SM4_GCM_SM3","is_gm":false,`+
				`"error_reason":"err\u0000`+strings.Repeat("e", 600)+`"}`,
			strings.Repeat("n", 100),
			strings.Repeat("a", 300),
		)
		e, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(e.GatewayNodeID) != maxGatewayNodeLen {
			t.Errorf("GatewayNodeID len = %d, want %d", len(e.GatewayNodeID), maxGatewayNodeLen)
		}
		if len(e.SNI) != maxSNILen {
			t.Errorf("SNI len = %d, want %d", len(e.SNI), maxSNILen)
		}
		if e.ClientIP != "2001:db8::1" {
			t.Errorf("ClientIP = %q, want canonical 2001:db8::1", e.ClientIP)
		}
		if e.ClientPort != 0 || e.ServerPort != 0 {
			t.Errorf("invalid ports should clamp to 0, got %d/%d", e.ClientPort, e.ServerPort)
		}
		if e.ApplicationID != "" {
			t.Errorf("invalid uuid should clear ApplicationID, got %q", e.ApplicationID)
		}
		if !e.IsGM {
			t.Error("TLCP1.1 must infer IsGM=true")
		}
		if e.Action != ActionAllowed {
			t.Errorf("empty action should default to ALLOWED, got %q", e.Action)
		}
		if strings.Contains(e.ErrorReason, "\x00") || len(e.ErrorReason) != maxErrorReasonLen {
			t.Errorf("ErrorReason not sanitized/truncated: len=%d", len(e.ErrorReason))
		}
	})
}

func TestCollectorTailPartialRotationAndMalformedLines(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "tls-handshake-events.jsonl")
	repo := NewMemStore()
	c := NewCollectorWithRepository(repo, DefaultCollectorID, logPath)

	// 1. Missing file: silent no-op
	if n, err := c.CollectOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("missing file: n=%d err=%v, want 0 nil", n, err)
	}

	// 2. Initial write with valid lines + malformed line + trailing partial line (no newline)
	appID := uuid.New().String()
	line1 := fmt.Sprintf(`{"occurred_at":"2026-11-25T08:00:01Z","gateway_node_id":"gw-1","application_id":%q,"sni":"gm.example.com","client_ip":"192.0.2.10","client_port":11111,"server_port":443,"detected_protocol":"TLCP1.1","negotiated_protocol":"TLCP1.1","cipher_suite":"TLCP_ECC_SM4_GCM_SM3","is_gm":true,"ja3_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","alpn":"http/1.1","action":"ALLOWED"}`, appID)
	line2 := `{"occurred_at":"2026-11-25T08:00:02Z","gateway_node_id":"gw-1","sni":"old.example.com","client_ip":"192.0.2.11","client_port":11112,"server_port":443,"detected_protocol":"SSLv3","is_gm":false,"action":"BLOCKED_LEGACY_SSL","error_reason":"legacy protocol SSLv3 rejected"}`
	line3Prefix := `{"occurred_at":"2026-11-25T08:00:03Z","gateway_node_id":"gw-1","sni":"intl.example.com",`
	line3Suffix := `"client_ip":"192.0.2.12","client_port":11113,"server_port":443,"detected_protocol":"TLS1.3","negotiated_protocol":"TLS1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","is_gm":false,"action":"ALLOWED"}`

	initialContent := line1 + "\n{bad json line\n" + line2 + "\n" + line3Prefix
	if err := os.WriteFile(logPath, []byte(initialContent), 0o600); err != nil {
		t.Fatal(err)
	}

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("first CollectOnce: %v", err)
	}
	if n != 3 || c.processedCount != 2 || c.failedCount != 1 {
		t.Fatalf("after initial read: n=%d processed=%d failed=%d, want 3/2/1", n, c.processedCount, c.failedCount)
	}

	// 3. Complete partial line 3 and verify checkpoint avoids re-reading lines 1 & 2
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(line3Suffix + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	n, err = c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("second CollectOnce: %v", err)
	}
	if n != 1 || c.processedCount != 3 {
		t.Fatalf("after completing partial line: n=%d processed=%d, want 1/3", n, c.processedCount)
	}

	// 4. Poll with no new bytes -> 0 processed
	if n, err := c.CollectOnce(context.Background()); err != nil || n != 0 {
		t.Fatalf("idle poll: n=%d err=%v, want 0 nil", n, err)
	}

	// 5. Log rotation via rename + recreate (inode change)
	rotatedPath := filepath.Join(dir, "tls-handshake-events.jsonl.1")
	if err := os.Rename(logPath, rotatedPath); err != nil {
		t.Fatal(err)
	}
	line4 := `{"occurred_at":"2026-11-25T08:01:00Z","gateway_node_id":"gw-1","sni":"rot.example.com","client_ip":"192.0.2.20","detected_protocol":"SSLv2","action":"BLOCKED_LEGACY_SSL"}`
	if err := os.WriteFile(logPath, []byte(line4+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err = c.CollectOnce(context.Background())
	if err != nil || n != 1 || c.processedCount != 4 {
		t.Fatalf("after inode rotation: n=%d err=%v processed=%d, want 1 nil 4", n, err, c.processedCount)
	}

	// 6. Truncation (same inode, smaller size)
	line5 := `{"occurred_at":"2026-11-25T08:02:00Z","sni":"tr.example.com","detected_protocol":"TLS1.2","action":"ALLOWED"}`
	if err := os.WriteFile(logPath, []byte(line5+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err = c.CollectOnce(context.Background())
	if err != nil || n != 1 || c.processedCount != 5 {
		t.Fatalf("after truncation: n=%d err=%v processed=%d, want 1 nil 5", n, err, c.processedCount)
	}

	items, total, err := repo.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if err != nil || total != 5 || len(items) != 5 {
		t.Fatalf("repo total=%d len=%d err=%v, want 5/5/nil", total, len(items), err)
	}
}

// --- Batch transaction collector test (mirrors accesslogs/collector_batchtx_test.go) ---

type fakeBatchTx struct {
	pgx.Tx
	ops        []string
	commitErr  error
	failSubstr string
	failFired  bool
	committed  bool
	rolled     bool
}

func (f *fakeBatchTx) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.ops = append(f.ops, sql)
	if f.failSubstr != "" && !f.failFired && strings.Contains(sql, f.failSubstr) {
		f.failFired = true
		return pgconn.CommandTag{}, errors.New("injected insert failure")
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (f *fakeBatchTx) Commit(context.Context) error {
	f.ops = append(f.ops, "__commit__")
	if f.commitErr != nil {
		return f.commitErr
	}
	f.committed = true
	return nil
}

func (f *fakeBatchTx) Rollback(context.Context) error {
	f.ops = append(f.ops, "__rollback__")
	f.rolled = true
	return nil
}

func (f *fakeBatchTx) countOps(substr string) int {
	n := 0
	for _, o := range f.ops {
		if strings.Contains(o, substr) {
			n++
		}
	}
	return n
}

func (f *fakeBatchTx) indexOf(substr string) int {
	for i, o := range f.ops {
		if strings.Contains(o, substr) {
			return i
		}
	}
	return -1
}

func deadPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestCollectorBatchTxCommitsAndIsolatesRowFailures(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "tls-handshake-events.jsonl")
	lines := []string{
		`{"occurred_at":"2026-11-25T08:00:01Z","sni":"a.example.com","detected_protocol":"TLS1.3","action":"ALLOWED"}`,
		`{malformed`,
		`{"occurred_at":"2026-11-25T08:00:02Z","sni":"b.example.com","detected_protocol":"TLCP1.1","is_gm":true,"action":"ALLOWED"}`,
	}
	if err := os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var txs []*fakeBatchTx
	c := NewCollector(deadPool(t), DefaultCollectorID, logPath)
	c.SetFlushPolicy(100, time.Hour)
	c.SetBatchTxFactory(func(context.Context) (pgx.Tx, error) {
		tx := &fakeBatchTx{failSubstr: "INSERT INTO tls_handshake_events"}
		txs = append(txs, tx)
		return tx, nil
	})

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 3 || c.processedCount != 1 || c.failedCount != 2 {
		t.Fatalf("n=%d processed=%d failed=%d, want 3/1/2", n, c.processedCount, c.failedCount)
	}
	if len(txs) != 1 || !txs[0].committed || txs[0].rolled {
		t.Fatalf("expected 1 committed tx, got %+v", txs)
	}
	tx := txs[0]
	if tx.countOps("ROLLBACK TO SAVEPOINT "+lineSavepoint) < 1 {
		t.Fatalf("expected row savepoint rollback, ops=%v", tx.ops)
	}
	if tx.countOps("INSERT INTO event_parse_failures") != 2 {
		t.Fatalf("expected 2 failures queued (1 insert fail + 1 parse fail), ops=%v", tx.ops)
	}
	cpIdx := tx.indexOf("INSERT INTO event_collector_checkpoints")
	if cpIdx < 0 || cpIdx > tx.indexOf("__commit__") {
		t.Fatalf("checkpoint upsert must precede commit: ops=%v", tx.ops)
	}
}

// --- Store SQL builder & Retention unit tests ---

type captureDB struct {
	sqls        []string
	args        [][]any
	rowsPerCall []int64
	callIdx     int
}

func (c *captureDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	c.sqls = append(c.sqls, sql)
	c.args = append(c.args, args)
	var affected int64 = 1
	if c.callIdx < len(c.rowsPerCall) {
		affected = c.rowsPerCall[c.callIdx]
	}
	c.callIdx++
	return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", affected)), nil
}

func (c *captureDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("not implemented")
}

func (c *captureDB) QueryRow(context.Context, string, ...any) pgx.Row { return nil }

func TestStoreInsertAndBuildWhere(t *testing.T) {
	db := &captureDB{}
	store := NewStore(nil).WithDB(db)
	appID := uuid.New()

	entry := &HandshakeEntry{
		OccurredAt:         time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC),
		GatewayNodeID:      "gw-01",
		ApplicationID:      appID.String(),
		SNI:                "gm.example.com",
		ClientIP:           "203.0.113.10",
		ClientPort:         51234,
		ServerPort:         443,
		DetectedProtocol:   ProtoTLCP11,
		NegotiatedProtocol: ProtoTLCP11,
		CipherSuite:        "TLCP_ECC_SM4_GCM_SM3",
		IsGM:               true,
		JA3Hash:            "0123456789abcdef0123456789abcdef",
		ALPN:               "http/1.1",
		Action:             ActionAllowed,
		ErrorReason:        "",
	}
	if err := store.Insert(context.Background(), entry); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if len(db.sqls) != 1 || !strings.Contains(db.sqls[0], "INSERT INTO tls_handshake_events") {
		t.Fatalf("unexpected SQL: %v", db.sqls)
	}
	if len(db.args[0]) != 15 {
		t.Fatalf("arg count = %d, want 15", len(db.args[0]))
	}

	start := time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	isGM := true
	where, args := buildListWhere(ListFilter{
		StartTime:        &start,
		EndTime:          &end,
		SNI:              "'; DROP TABLE tls_handshake_events;--",
		ClientIP:         "203.0.113.",
		DetectedProtocol: ProtoTLCP11,
		Action:           ActionAllowed,
		IsGM:             &isGM,
		ApplicationID:    &appID,
	})
	for _, want := range []string{
		"occurred_at >= $1",
		"occurred_at <= $2",
		"sni ILIKE $3",
		"client_ip ILIKE $4",
		"detected_protocol = $5",
		"action = $6",
		"is_gm = $7",
		"application_id = $8",
	} {
		if !strings.Contains(where, want) {
			t.Errorf("where missing %q: %s", want, where)
		}
	}
	if strings.Contains(where, "DROP TABLE") {
		t.Fatalf("user input concatenated into SQL: %s", where)
	}
	if len(args) != 8 || args[3] != "203.0.113.%" {
		t.Fatalf("unexpected args: %#v", args)
	}

	// Exact valid IP uses equality match (not prefix LIKE)
	whereExact, argsExact := buildListWhere(ListFilter{ClientIP: "203.0.113.1"})
	if !strings.Contains(whereExact, "client_ip = $1") || argsExact[0] != "203.0.113.1" {
		t.Fatalf("exact IP should use =, got where=%q args=%v", whereExact, argsExact)
	}
}

type stubRetentionSettings struct{ days int }

func (s stubRetentionSettings) GetInt(context.Context, string, string, int) int { return s.days }

func TestRetentionCleanerCleanOnce(t *testing.T) {
	db := &captureDB{rowsPerCall: []int64{42}}
	rc := &RetentionCleaner{db: db, settings: stubRetentionSettings{days: 14}}
	n, err := rc.CleanOnce(context.Background())
	if err != nil {
		t.Fatalf("CleanOnce: %v", err)
	}
	if n != 42 {
		t.Fatalf("deleted = %d, want 42", n)
	}
	if len(db.sqls) != 1 || !strings.Contains(db.sqls[0], "DELETE FROM tls_handshake_events") {
		t.Fatalf("unexpected delete SQL: %v", db.sqls)
	}
}

type stubRelkindRow struct {
	relkind string
	err     error
}

func (r stubRelkindRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*(dest[0].(*string)) = r.relkind
	return nil
}

type relkindCaptureDB struct {
	captureDB
	relkind string
}

func (c *relkindCaptureDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return stubRelkindRow{relkind: c.relkind}
}

func TestRetentionCleanerSkipsPartitionedTable(t *testing.T) {
	db := &relkindCaptureDB{
		captureDB: captureDB{rowsPerCall: []int64{10}},
		relkind:   "p",
	}
	rc := &RetentionCleaner{db: db, settings: stubRetentionSettings{days: 7}}
	n, err := rc.CleanOnce(context.Background())
	if err != nil {
		t.Fatalf("CleanOnce: %v", err)
	}
	if n != 0 {
		t.Fatalf("deleted = %d, want 0 when relkind='p'", n)
	}
	if len(db.sqls) != 0 {
		t.Fatalf("expected 0 DELETE executions when relkind='p', got %v", db.sqls)
	}

	dbReg := &relkindCaptureDB{
		captureDB: captureDB{rowsPerCall: []int64{9}},
		relkind:   "r",
	}
	rcReg := &RetentionCleaner{db: dbReg, settings: stubRetentionSettings{days: 7}}
	nReg, err := rcReg.CleanOnce(context.Background())
	if err != nil || nReg != 9 || len(dbReg.sqls) != 1 {
		t.Fatalf("expected fallback DELETE on relkind='r', got n=%d err=%v sqls=%v", nReg, err, dbReg.sqls)
	}
}

func TestMemStoreInsertGeneratesUUIDv7(t *testing.T) {
	ms := NewMemStore()
	if err := ms.Insert(context.Background(), &HandshakeEntry{
		OccurredAt:       time.Now().UTC(),
		DetectedProtocol: ProtoTLS13,
		Action:           ActionAllowed,
	}); err != nil {
		t.Fatalf("MemStore.Insert: %v", err)
	}
	items, total, err := ms.List(context.Background(), ListFilter{})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("List = (%d, %d, %v)", len(items), total, err)
	}
	if items[0].ID.Version() != 7 || items[0].ID.Variant() != uuid.RFC4122 {
		t.Fatalf("expected UUIDv7 RFC4122, got version=%d variant=%v (%s)", items[0].ID.Version(), items[0].ID.Variant(), items[0].ID)
	}
}

// --- HTTP Handler, Filter, Summary & RBAC tests ---

func newTestMux(repo Repository) http.Handler {
	h := NewHandler(repo)
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/tls-sessions", middleware.RequirePermission("events.read")(http.HandlerFunc(h.List)))
	mux.Handle("GET /api/v1/tls-sessions/summary", middleware.RequirePermission("events.read")(http.HandlerFunc(h.Summary)))
	return mux
}

func withPerms(req *http.Request, perms ...string) *http.Request {
	set := make(map[string]bool, len(perms))
	for _, p := range perms {
		set[p] = true
	}
	return req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.New(),
		Username: "operadmin",
		PermsSet: set,
	}))
}

func seedTestSessions(t *testing.T, repo *MemStore) (uuid.UUID, uuid.UUID) {
	t.Helper()
	appA := uuid.New()
	appB := uuid.New()
	base := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

	entries := []*HandshakeEntry{
		{
			OccurredAt: base.Add(1 * time.Minute), GatewayNodeID: "gw-1", ApplicationID: appA.String(),
			SNI: "gm.example.com", ClientIP: "203.0.113.1", ClientPort: 40001, ServerPort: 443,
			DetectedProtocol: ProtoTLCP11, NegotiatedProtocol: ProtoTLCP11, CipherSuite: "TLCP_ECC_SM4_GCM_SM3",
			IsGM: true, JA3Hash: "11111111111111111111111111111111", ALPN: "http/1.1", Action: ActionAllowed,
		},
		{
			OccurredAt: base.Add(2 * time.Minute), GatewayNodeID: "gw-1", ApplicationID: appA.String(),
			SNI: "gm.example.com", ClientIP: "203.0.113.10", ClientPort: 40002, ServerPort: 443,
			DetectedProtocol: ProtoTLCP11, NegotiatedProtocol: ProtoTLCP11, CipherSuite: "TLCP_ECC_SM4_GCM_SM3",
			IsGM: true, JA3Hash: "11111111111111111111111111111111", ALPN: "http/1.1", Action: ActionAllowed,
		},
		{
			OccurredAt: base.Add(3 * time.Minute), GatewayNodeID: "gw-1", ApplicationID: appA.String(),
			SNI: "web.example.com", ClientIP: "203.0.113.20", ClientPort: 40003, ServerPort: 443,
			DetectedProtocol: ProtoTLS13, NegotiatedProtocol: ProtoTLS13, CipherSuite: "TLS_AES_128_GCM_SHA256",
			IsGM: false, JA3Hash: "22222222222222222222222222222222", ALPN: "h2", Action: ActionAllowed,
		},
		{
			OccurredAt: base.Add(4 * time.Minute), GatewayNodeID: "gw-1", ApplicationID: appA.String(),
			SNI: "legacy.example.com", ClientIP: "198.51.100.5", ClientPort: 40004, ServerPort: 443,
			DetectedProtocol: ProtoSSLv2v3, IsGM: false, JA3Hash: "33333333333333333333333333333333",
			Action: ActionBlockedLegacySSL, ErrorReason: "legacy protocol SSLv2/v3 rejected",
		},
		{
			OccurredAt: base.Add(5 * time.Minute), GatewayNodeID: "gw-1", ApplicationID: appB.String(),
			SNI: "legacy.example.com", ClientIP: "198.51.100.6", ClientPort: 40005, ServerPort: 443,
			DetectedProtocol: ProtoTLS10, IsGM: false, Action: ActionBlockedProtocolPolicy,
			ErrorReason: "TLS1.0 disabled by policy",
		},
		{
			OccurredAt: base.Add(6 * time.Minute), GatewayNodeID: "gw-2", ApplicationID: appB.String(),
			SNI: "broken.example.com", ClientIP: "198.51.100.7", ClientPort: 40006, ServerPort: 443,
			DetectedProtocol: ProtoUnknown, IsGM: false, Action: ActionHandshakeFailed,
			ErrorReason: "unrecognized TLS/TLCP ClientHello record",
		},
	}
	for _, e := range entries {
		if err := repo.Insert(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	return appA, appB
}

func TestHandlerListFiltersPaginationAndOrder(t *testing.T) {
	repo := NewMemStore()
	appA, _ := seedTestSessions(t, repo)
	mux := newTestMux(repo)

	getJSON := func(path string) (int, struct {
		Code string `json:"code"`
		Data struct {
			Items    []SessionEvent `json:"items"`
			Page     int            `json:"page"`
			PageSize int            `json:"page_size"`
			Total    int64          `json:"total"`
		} `json:"data"`
	}) {
		t.Helper()
		req := withPerms(httptest.NewRequest(http.MethodGet, path, nil), "events.read")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var resp struct {
			Code string `json:"code"`
			Data struct {
				Items    []SessionEvent `json:"items"`
				Page     int            `json:"page"`
				PageSize int            `json:"page_size"`
				Total    int64          `json:"total"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal %s: %v (body=%s)", path, err, rec.Body.String())
		}
		return rec.Code, resp
	}

	// Default pagination & newest-first order
	code, resp := getJSON("/api/v1/tls-sessions?page=1&page_size=2")
	if code != http.StatusOK || resp.Data.Total != 6 || len(resp.Data.Items) != 2 || resp.Data.PageSize != 2 {
		t.Fatalf("page 1: code=%d total=%d len=%d", code, resp.Data.Total, len(resp.Data.Items))
	}
	if resp.Data.Items[0].DetectedProtocol != ProtoUnknown || resp.Data.Items[1].DetectedProtocol != ProtoTLS10 {
		t.Fatalf("expected newest-first order, got %s then %s",
			resp.Data.Items[0].DetectedProtocol, resp.Data.Items[1].DetectedProtocol)
	}

	// page_size > 100 clamped to 100
	code, resp = getJSON("/api/v1/tls-sessions?page_size=500")
	if code != http.StatusOK || resp.Data.PageSize != 100 {
		t.Fatalf("page_size clamp failed: code=%d page_size=%d", code, resp.Data.PageSize)
	}

	// Filter by exact IP: 203.0.113.1 must NOT match 203.0.113.10
	code, resp = getJSON("/api/v1/tls-sessions?client_ip=203.0.113.1")
	if code != http.StatusOK || resp.Data.Total != 1 || resp.Data.Items[0].ClientIP != "203.0.113.1" {
		t.Fatalf("exact ip filter failed: code=%d total=%d items=%+v", code, resp.Data.Total, resp.Data.Items)
	}

	// Filter by IP prefix: 203.0.113. matches 3 records
	code, resp = getJSON("/api/v1/tls-sessions?client_ip=203.0.113.")
	if code != http.StatusOK || resp.Data.Total != 3 {
		t.Fatalf("prefix ip filter failed: code=%d total=%d", code, resp.Data.Total)
	}

	// Filter by SNI ILIKE + is_gm=true + application_id
	code, resp = getJSON("/api/v1/tls-sessions?sni=GM.EXAMPLE&is_gm=true&application_id=" + appA.String())
	if code != http.StatusOK || resp.Data.Total != 2 {
		t.Fatalf("sni+gm+app filter failed: code=%d total=%d", code, resp.Data.Total)
	}

	// Filter by detected_protocol=SSLv2/v3 & action=BLOCKED_LEGACY_SSL
	code, resp = getJSON("/api/v1/tls-sessions?detected_protocol=SSLv2/v3&action=BLOCKED_LEGACY_SSL")
	if code != http.StatusOK || resp.Data.Total != 1 || resp.Data.Items[0].Action != ActionBlockedLegacySSL {
		t.Fatalf("protocol+action filter failed: code=%d total=%d", code, resp.Data.Total)
	}

	// Filter by start_time & end_time window (minutes 2..4 -> 3 items)
	code, resp = getJSON("/api/v1/tls-sessions?start_time=2026-11-25T10:02:00Z&end_time=2026-11-25T10:04:00Z")
	if code != http.StatusOK || resp.Data.Total != 3 {
		t.Fatalf("time window filter failed: code=%d total=%d", code, resp.Data.Total)
	}
}

func TestHandlerSummaryAggregation(t *testing.T) {
	repo := NewMemStore()
	appA, _ := seedTestSessions(t, repo)
	mux := newTestMux(repo)

	getSummary := func(path string) (int, Summary, string) {
		t.Helper()
		req := withPerms(httptest.NewRequest(http.MethodGet, path, nil), "events.read")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var resp struct {
			Code string  `json:"code"`
			Data Summary `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal %s: %v (body=%s)", path, err, rec.Body.String())
		}
		return rec.Code, resp.Data, rec.Body.String()
	}

	// Global summary across all 6 events
	code, s, _ := getSummary("/api/v1/tls-sessions/summary")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if s.TotalHandshakes != 6 || s.AllowedCount != 3 || s.GMCount != 2 || s.IntlCount != 4 ||
		s.LegacySSLBlockedCount != 1 || s.PolicyBlockedCount != 1 || s.HandshakeFailedCount != 1 {
		t.Fatalf("unexpected global summary counts: %+v", s)
	}
	if len(s.ByProtocol) != 5 {
		t.Fatalf("by_protocol len = %d, want 5 (%+v)", len(s.ByProtocol), s.ByProtocol)
	}
	if s.ByProtocol[0].Protocol != ProtoTLCP11 || s.ByProtocol[0].Count != 2 || !s.ByProtocol[0].IsGM || s.ByProtocol[0].IsLegacy {
		t.Fatalf("top protocol mismatch: %+v", s.ByProtocol[0])
	}
	foundLegacyProto := false
	for _, ps := range s.ByProtocol {
		if ps.Protocol == ProtoSSLv2v3 && ps.IsLegacy && !ps.IsGM && ps.Count == 1 {
			foundLegacyProto = true
		}
	}
	if !foundLegacyProto {
		t.Fatalf("expected SSLv2/v3 with is_legacy=true in by_protocol: %+v", s.ByProtocol)
	}
	// Empty cipher suites must be excluded from by_cipher_suite
	if len(s.ByCipherSuite) != 2 {
		t.Fatalf("by_cipher_suite len = %d, want 2 (%+v)", len(s.ByCipherSuite), s.ByCipherSuite)
	}
	if s.ByCipherSuite[0].CipherSuite != "TLCP_ECC_SM4_GCM_SM3" || s.ByCipherSuite[0].Count != 2 || !s.ByCipherSuite[0].IsGM {
		t.Fatalf("top cipher suite mismatch: %+v", s.ByCipherSuite[0])
	}

	// Scoped summary by application_id=appA (4 events)
	code, sApp, _ := getSummary("/api/v1/tls-sessions/summary?application_id=" + appA.String())
	if code != http.StatusOK || sApp.TotalHandshakes != 4 || sApp.GMCount != 2 || sApp.IntlCount != 2 || sApp.LegacySSLBlockedCount != 1 || sApp.PolicyBlockedCount != 0 {
		t.Fatalf("appA summary mismatch: code=%d summary=%+v", code, sApp)
	}

	// Empty store returns empty JSON arrays [] (never null)
	emptyMux := newTestMux(NewMemStore())
	req := withPerms(httptest.NewRequest(http.MethodGet, "/api/v1/tls-sessions/summary", nil), "events.read")
	rec := httptest.NewRecorder()
	emptyMux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("empty summary status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, `"by_protocol":null`) || strings.Contains(body, `"by_cipher_suite":null`) {
		t.Fatalf("summary slices must not serialize as null: %s", body)
	}
}

func TestHandlerValidationAndPermissions(t *testing.T) {
	mux := newTestMux(NewMemStore())

	// 1. Unauthenticated -> 401
	for _, path := range []string{"/api/v1/tls-sessions", "/api/v1/tls-sessions/summary"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated %s = %d, want 401", path, rec.Code)
		}
	}

	// 2. Missing events.read permission -> 403
	for _, path := range []string{"/api/v1/tls-sessions", "/api/v1/tls-sessions/summary"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, withPerms(httptest.NewRequest(http.MethodGet, path, nil), "users.read", "security_events.read"))
		if rec.Code != http.StatusForbidden {
			t.Errorf("without events.read %s = %d, want 403", path, rec.Code)
		}
	}

	// 3. Invalid query params -> 400 INVALID_ARGUMENT
	badQueries := []string{
		"/api/v1/tls-sessions?application_id=not-a-uuid",
		"/api/v1/tls-sessions?start_time=not-a-time",
		"/api/v1/tls-sessions?end_time=2026-13-99",
		"/api/v1/tls-sessions?start_time=2026-11-25T10:00:00Z&end_time=2026-11-25T09:00:00Z",
		"/api/v1/tls-sessions?is_gm=yes",
		"/api/v1/tls-sessions?action=INVALID",
		"/api/v1/tls-sessions?detected_protocol=TLS9.9",
		"/api/v1/tls-sessions?page=0",
		"/api/v1/tls-sessions?page=abc",
		"/api/v1/tls-sessions?page_size=-1",
		"/api/v1/tls-sessions/summary?application_id=bad-uuid",
		"/api/v1/tls-sessions/summary?start_time=bad",
		"/api/v1/tls-sessions/summary?start_time=2026-11-25T12:00:00Z&end_time=2026-11-25T11:00:00Z",
	}
	for _, path := range badQueries {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, withPerms(httptest.NewRequest(http.MethodGet, path, nil), "events.read"))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("GET %s = %d, want 400 (body=%s)", path, rec.Code, rec.Body.String())
			}
			var body response.Body
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != response.CodeInvalidArgument {
				t.Fatalf("unexpected error body for %s: %s", path, rec.Body.String())
			}
		})
	}
}

func TestMigration000241StaticContract(t *testing.T) {
	upBytes, err := os.ReadFile(filepath.Join("..", "..", "migrations", "000241_tls_session_analysis.up.sql"))
	if err != nil {
		t.Fatalf("read up migration: %v", err)
	}
	up := string(upBytes)
	for _, frag := range []string{
		"ALTER TABLE access_logs",
		"ADD COLUMN IF NOT EXISTS tls_protocol",
		"ADD COLUMN IF NOT EXISTS tls_cipher_suite",
		"ADD COLUMN IF NOT EXISTS tls_is_gm",
		"ADD COLUMN IF NOT EXISTS tls_ja3",
		"ADD COLUMN IF NOT EXISTS client_hello_version",
		"CREATE TABLE IF NOT EXISTS tls_handshake_events",
		"idx_tls_handshake_events_occurred_at",
		"idx_tls_handshake_events_protocol_occurred",
		"idx_tls_handshake_events_action_occurred",
		"idx_tls_handshake_events_sni_occurred",
		"idx_tls_handshake_events_app_occurred",
		"'events.read'",
		"SECURITY_ADMIN",
	} {
		if !strings.Contains(up, frag) {
			t.Errorf("000241 up migration missing %q", frag)
		}
	}

	downBytes, err := os.ReadFile(filepath.Join("..", "..", "migrations", "000241_tls_session_analysis.down.sql"))
	if err != nil {
		t.Fatalf("read down migration: %v", err)
	}
	down := string(downBytes)
	for _, frag := range []string{
		"DROP TABLE IF EXISTS tls_handshake_events",
		"DROP COLUMN IF EXISTS tls_protocol",
		"DROP COLUMN IF EXISTS tls_cipher_suite",
		"DROP COLUMN IF EXISTS tls_is_gm",
		"DROP COLUMN IF EXISTS tls_ja3",
		"DROP COLUMN IF EXISTS client_hello_version",
		"'events.read'",
	} {
		if !strings.Contains(down, frag) {
			t.Errorf("000241 down migration missing %q", frag)
		}
	}
}
