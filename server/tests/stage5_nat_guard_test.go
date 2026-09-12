package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
)

// seedIdentityIPHistory 为 ip 写入 n 个不同身份的近 24h 关联记录
// （client_identity + identity_ip_history，迁移 000097 口径）。
func seedIdentityIPHistory(t *testing.T, env *testEnv, ip string, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		var identityID string
		err := env.db.QueryRow(ctx, `
INSERT INTO client_identity (identity_key, identity_type, first_seen_at, last_seen_at, primary_ip)
VALUES ($1, 'HUMAN', now(), now(), $2) RETURNING id`,
			fmt.Sprintf("nat-guard-test-%s-%d", ip, i), ip).Scan(&identityID)
		if err != nil {
			t.Fatalf("insert client_identity: %v", err)
		}
		if _, err := env.db.Exec(ctx, `
INSERT INTO identity_ip_history (identity_id, ip, first_seen_at, last_seen_at, request_count)
VALUES ($1, $2, now(), now(), 10)`, identityID, ip); err != nil {
			t.Fatalf("insert identity_ip_history: %v", err)
		}
	}
}

// valkeyBlockExpires 读取 Valkey 封禁 field 的 expires_at（网关轮询同步的实际生效值）。
func valkeyBlockExpires(t *testing.T, env *testEnv, ip string) time.Time {
	t.Helper()
	raw, err := env.cache.Redis().HGet(context.Background(), temporaryblocks.HashKey,
		temporaryblocks.BlockFieldKey(ip, "")).Result()
	if err != nil {
		t.Fatalf("read tempblock hash field: %v", err)
	}
	var v struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("decode tempblock value: %v", err)
	}
	return v.ExpiresAt
}

// TestStage5NATGuardDowngrade 阶段5 §十五：CC 自动封禁命中共享出口（NAT）风险时
// 降档缩短封禁时长——DB、Valkey（网关实际执行面）与审计事件三处同口径缩短留痕。
func TestStage5NATGuardDowngrade(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	ip := "203.0.113.240"

	// 迁移 000153 种子就位（默认：开关开 / 阈值 2 / 降档 15 分钟）
	settingsSvc := settings.NewService(env.db)
	if !settingsSvc.GetBool(ctx, temporaryblocks.NATSettingsGroup, "nat_guard_enabled", false) {
		t.Fatal("nat_guard_enabled seed missing or false")
	}

	// 同 IP 近 24h 关联 3 个不同身份 → 疑似共享出口
	seedIdentityIPHistory(t, env, ip, 3)

	// 模拟网关已先行写入 Valkey 的全时长（1h）封禁
	fullExpiry := time.Now().Add(time.Hour).UTC()
	if err := env.cache.Redis().HSet(ctx, temporaryblocks.HashKey, temporaryblocks.BlockFieldKey(ip, ""),
		fmt.Sprintf(`{"id":"gw","client_ip":%q,"application_id":"","expires_at":%q,"reason":"cc_threshold_exceeded","auto":true}`,
			ip, fullExpiry.Format(time.RFC3339Nano))).Err(); err != nil {
		t.Fatalf("seed gateway tempblock field: %v", err)
	}

	// 与 main.go 装配同口径：设置读取器 + 降档审计事件回调
	store := temporaryblocks.NewStore(env.db, env.cache)
	store.SetNATGuardSettings(settingsSvc)
	acStore := accesscontrolevents.NewStore(env.db)
	store.SetNATDowngradeEmitter(func(ctx context.Context, b *temporaryblocks.Block, d temporaryblocks.NATDowngrade) {
		expiresAt := b.BlockExpiresAt
		if _, err := acStore.Insert(ctx, []accesscontrolevents.Event{{
			OccurredAt:     time.Now().UTC(),
			ClientIP:       b.ClientIP,
			EventType:      accesscontrolevents.EventTypeCCTempBlockDowngraded,
			Action:         accesscontrolevents.ActionTempBlock,
			AccessRuleID:   b.ID.String(),
			BlockExpiresAt: &expiresAt,
			Message:        "自动封禁命中共享出口（NAT）风险，降档缩短封禁时长",
			GatewayNodeID:  "management-api",
			Details:        map[string]interface{}{"nat_guard": d},
		}}); err != nil {
			t.Errorf("insert downgrade event: %v", err)
		}
	})

	// 采集器落点：CC_TEMP_BLOCK_CREATED → UpsertFromEvent（原始时长 1h）
	before := time.Now()
	blk := &temporaryblocks.Block{ClientIP: ip, BlockExpiresAt: fullExpiry}
	if err := store.UpsertFromEvent(ctx, blk); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	after := time.Now()

	// DB 到期时间已夹紧到 ~15 分钟
	var dbExpiry time.Time
	if err := env.db.QueryRow(ctx,
		`SELECT block_expires_at FROM temporary_blocks WHERE client_ip=$1 AND status='ACTIVE'`, ip).Scan(&dbExpiry); err != nil {
		t.Fatalf("read block: %v", err)
	}
	lo := before.Add(14 * time.Minute)
	hi := after.Add(16 * time.Minute)
	if dbExpiry.Before(lo) || dbExpiry.After(hi) {
		t.Errorf("db expiry = %v, want within [%v, %v]（降档 15 分钟）", dbExpiry, lo, hi)
	}

	// Valkey 执行面已回写缩短后的到期时间（且 reason 保留网关原值）
	vExpiry := valkeyBlockExpires(t, env, ip)
	if vExpiry.Before(lo) || vExpiry.After(hi) {
		t.Errorf("valkey expiry = %v, want within [%v, %v]", vExpiry, lo, hi)
	}
	raw, _ := env.cache.Redis().HGet(ctx, temporaryblocks.HashKey, temporaryblocks.BlockFieldKey(ip, "")).Result()
	var vv struct {
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal([]byte(raw), &vv)
	if vv.Reason != "cc_threshold_exceeded" {
		t.Errorf("valkey reason = %q, want preserved gateway reason", vv.Reason)
	}

	// 审计事件已落库（details.nat_guard 可溯源）
	var evtCount int
	var details []byte
	err := env.db.QueryRow(ctx, `
SELECT count(*), (SELECT details FROM access_control_events
  WHERE event_type='CC_TEMP_BLOCK_DOWNGRADED' AND client_ip=$1 ORDER BY occurred_at DESC LIMIT 1)
FROM access_control_events WHERE event_type='CC_TEMP_BLOCK_DOWNGRADED' AND client_ip=$1`, ip).
		Scan(&evtCount, &details)
	if err != nil || evtCount != 1 {
		t.Fatalf("downgrade audit event count = %d, err = %v, want 1", evtCount, err)
	}
	var dm map[string]struct {
		IdentityCount int64  `json:"identity_count"`
		Reason        string `json:"reason"`
		ValkeySynced  bool   `json:"valkey_synced"`
	}
	if err := json.Unmarshal(details, &dm); err != nil {
		t.Fatalf("decode event details: %v", err)
	}
	ng, ok := dm["nat_guard"]
	if !ok || ng.IdentityCount != 3 || ng.Reason != "shared_egress_suspected" || !ng.ValkeySynced {
		t.Errorf("unexpected nat_guard details: %s", details)
	}

	// 幂等更新路径：同 IP 再次触发（网关仍按全时长上报），存量 ACTIVE 不得抵消降档
	if err := store.UpsertFromEvent(ctx, &temporaryblocks.Block{ClientIP: ip, BlockExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if err := env.db.QueryRow(ctx,
		`SELECT block_expires_at FROM temporary_blocks WHERE client_ip=$1 AND status='ACTIVE'`, ip).Scan(&dbExpiry); err != nil {
		t.Fatalf("read block after second upsert: %v", err)
	}
	if dbExpiry.After(time.Now().Add(16 * time.Minute)) {
		t.Errorf("db expiry after re-trigger = %v, want still capped ≤ ~15min", dbExpiry)
	}
}

// TestStage5NATGuardNoDowngrade 单身份 IP（无共享出口迹象）不降档：
// DB 保留原时长，且管理面不触碰 Valkey（网关写入的原值原样保留）。
func TestStage5NATGuardNoDowngrade(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	ip := "203.0.113.241"

	seedIdentityIPHistory(t, env, ip, 1)

	fullExpiry := time.Now().Add(time.Hour).UTC()
	gwValue := fmt.Sprintf(`{"id":"gw","client_ip":%q,"application_id":"","expires_at":%q,"auto":true}`,
		ip, fullExpiry.Format(time.RFC3339Nano))
	if err := env.cache.Redis().HSet(ctx, temporaryblocks.HashKey, temporaryblocks.BlockFieldKey(ip, ""), gwValue).Err(); err != nil {
		t.Fatalf("seed gateway tempblock field: %v", err)
	}

	store := temporaryblocks.NewStore(env.db, env.cache)
	store.SetNATGuardSettings(settings.NewService(env.db))
	emitCount := 0
	store.SetNATDowngradeEmitter(func(context.Context, *temporaryblocks.Block, temporaryblocks.NATDowngrade) { emitCount++ })

	if err := store.UpsertFromEvent(ctx, &temporaryblocks.Block{ClientIP: ip, BlockExpiresAt: fullExpiry}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if emitCount != 0 {
		t.Errorf("downgrade emitter fired %d times for single-identity ip, want 0", emitCount)
	}

	var dbExpiry time.Time
	if err := env.db.QueryRow(ctx,
		`SELECT block_expires_at FROM temporary_blocks WHERE client_ip=$1 AND status='ACTIVE'`, ip).Scan(&dbExpiry); err != nil {
		t.Fatalf("read block: %v", err)
	}
	if dbExpiry.Before(time.Now().Add(59 * time.Minute)) {
		t.Errorf("db expiry = %v, want ~1h（未降档）", dbExpiry)
	}
	raw, err := env.cache.Redis().HGet(ctx, temporaryblocks.HashKey, temporaryblocks.BlockFieldKey(ip, "")).Result()
	if err != nil {
		t.Fatalf("read tempblock hash field: %v", err)
	}
	if raw != gwValue {
		t.Errorf("valkey field rewritten by server on non-downgrade path: %s", raw)
	}
}

// TestStage5NATGuardDisabledBySetting 设置开关关闭时不降档（管理面可关闭检查）。
func TestStage5NATGuardDisabledBySetting(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	ip := "203.0.113.242"

	if _, err := env.db.Exec(ctx,
		`UPDATE system_settings SET setting_value='false' WHERE setting_group='cc_auto_block' AND setting_key='nat_guard_enabled'`); err != nil {
		t.Fatalf("disable nat guard: %v", err)
	}
	seedIdentityIPHistory(t, env, ip, 5)

	store := temporaryblocks.NewStore(env.db, env.cache)
	store.SetNATGuardSettings(settings.NewService(env.db))
	store.SetNATDowngradeEmitter(func(context.Context, *temporaryblocks.Block, temporaryblocks.NATDowngrade) {
		t.Error("downgrade emitter fired while guard disabled")
	})

	fullExpiry := time.Now().Add(time.Hour)
	if err := store.UpsertFromEvent(ctx, &temporaryblocks.Block{ClientIP: ip, BlockExpiresAt: fullExpiry}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	var dbExpiry time.Time
	if err := env.db.QueryRow(ctx,
		`SELECT block_expires_at FROM temporary_blocks WHERE client_ip=$1 AND status='ACTIVE'`, ip).Scan(&dbExpiry); err != nil {
		t.Fatalf("read block: %v", err)
	}
	if dbExpiry.Before(time.Now().Add(59 * time.Minute)) {
		t.Errorf("db expiry = %v, want ~1h（开关关闭不降档）", dbExpiry)
	}
}
