package nodesync

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/hagroups"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
)

type spyTelemetrySink struct {
	mu      sync.Mutex
	records []TelemetryRecord
}

func (s *spyTelemetrySink) SaveTelemetry(_ context.Context, rec TelemetryRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, rec)
	return nil
}

func TestTelemetrySweeperPollsReconcilesAndRecordsTransitions(t *testing.T) {
	var (
		mu       sync.Mutex
		vipState = "BACKUP"
		lpState  = "BOTH_UP"
	)
	baseTime := time.Date(2026, 11, 25, 1, 0, 0, 0, time.UTC)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/status" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		mu.Lock()
		vs := vipState
		ls := lpState
		mu.Unlock()

		hv, _ := json.Marshal(map[string]any{
			"group":              "ha-main",
			"node":               "gw-b",
			"state":              vs,
			"keepalived_running": true,
			"vips_present":       []string{},
		})
		ns, _ := json.Marshal(map[string]any{
			"ok":      true,
			"message": "applied",
			"link_pairs": []map[string]any{
				{"bridge": "br0", "state": ls, "down_port": "eth2", "propagated_port": "eth3"},
			},
		})
		mtime := baseTime
		resp := StatusResponse{
			Node:               "gw-b",
			Version:            "1.12.0",
			PolicyVersion:      "v100",
			ConfigHash:         "abcd",
			CaddyReachable:     true,
			HaVipStatus:        hv,
			HaVipStatusMtime:   &mtime,
			NetworkStatus:      ns,
			NetworkStatusMtime: &mtime,
			Interfaces: []InterfaceSnapshot{
				{
					NodeName:    "gw-b",
					IfName:      "eth0",
					MAC:         "00:11:22:33:44:55",
					IPAddresses: []string{"10.0.0.2/24"},
					MediaType:   "TP",
					LinkSpeed:   1000,
					OperState:   "up",
					CollectedAt: baseTime,
				},
			},
			CollectedAt: baseTime,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	nodeB := uuid.New()
	groupID := uuid.NewString()
	store := newMemNodeStore(
		NodeCredential{
			NodeID:               nodeB,
			NodeName:             "gw-b",
			SyncAgentAddr:        srv.URL,
			SyncSecretCiphertext: "enc:" + testSharedSecretHex,
			SyncEnabled:          true,
		},
		// Unreachable node should not block polling gw-b
		NodeCredential{
			NodeID:               uuid.New(),
			NodeName:             "gw-down",
			SyncAgentAddr:        "https://127.0.0.1:1",
			SyncSecretCiphertext: "enc:" + testSharedSecretHex,
			SyncEnabled:          true,
		},
	)
	mgr := NewManager(store, fakeDecryptor{}, ManagerConfig{
		LocalNodeName: "gw-a",
		TLSCAPEM:      caPEM,
		Timeout:       2 * time.Second,
	})
	sink := &spyTelemetrySink{}
	ifaceStore := nodeinterfaces.NewMemStore()
	haEvents := hagroups.NewMemStore()

	sweeper := NewTelemetrySweeper(mgr, sink).
		SetInterfaceApplier(ifaceStore).
		SetHAEventRecorder(haEvents).
		SetGroupIDResolver(func(_ context.Context, groupName string) string {
			if groupName == "ha-main" {
				return groupID
			}
			return ""
		}).
		SetClock(func() time.Time { return baseTime })

	ctx := context.Background()

	// Sweep 1: initial seed -> saves telemetry & interfaces, no fake transition events
	if err := sweeper.SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce 1: %v", err)
	}
	if len(sink.records) != 1 || sink.records[0].ReportedVersion != "1.12.0" || sink.records[0].PolicyVersion != "v100" {
		t.Fatalf("telemetry records after sweep 1 = %+v", sink.records)
	}
	grouped, err := ifaceStore.ListGrouped(ctx, "gw-b")
	if err != nil || len(grouped) != 1 || len(grouped[0].Interfaces) != 1 || grouped[0].Interfaces[0].Ifname != "eth0" {
		t.Fatalf("reconciled interfaces = %+v err=%v", grouped, err)
	}
	evs, total, err := haEvents.ListEvents(ctx, hagroups.EventFilter{})
	if err != nil || total != 0 || len(evs) != 0 {
		t.Fatalf("initial sweep must not emit fake transitions: total=%d evs=%+v", total, evs)
	}

	// Sweep 2: unchanged state -> still 0 transition events
	if err := sweeper.SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce 2: %v", err)
	}
	_, total, _ = haEvents.ListEvents(ctx, hagroups.EventFilter{})
	if total != 0 {
		t.Fatalf("unchanged sweep emitted %d events, want 0", total)
	}

	// Sweep 3: VIP transitions BACKUP -> MASTER and br0 transitions BOTH_UP -> PROPAGATED_DOWN
	mu.Lock()
	vipState = "MASTER"
	lpState = "PROPAGATED_DOWN"
	mu.Unlock()
	if err := sweeper.SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce 3: %v", err)
	}
	evs, total, err = haEvents.ListEvents(ctx, hagroups.EventFilter{})
	if err != nil || total != 2 {
		t.Fatalf("expected 2 transition events, got total=%d evs=%+v err=%v", total, evs, err)
	}
	var sawVIP, sawLP bool
	for _, ev := range evs {
		switch ev.EventType {
		case hagroups.EventTypeVIPTransition:
			sawVIP = true
			if ev.GroupID != groupID || ev.GroupName != "ha-main" || ev.NodeName != "gw-b" ||
				ev.Detail["from_state"] != "BACKUP" || ev.Detail["to_state"] != "MASTER" {
				t.Fatalf("unexpected VIP_TRANSITION event: %+v", ev)
			}
		case hagroups.EventTypeLinkPairChange:
			sawLP = true
			if ev.NodeName != "gw-b" || ev.Detail["bridge"] != "br0" ||
				ev.Detail["from_state"] != "BOTH_UP" || ev.Detail["to_state"] != "PROPAGATED_DOWN" {
				t.Fatalf("unexpected LINK_PAIR_CHANGE event: %+v", ev)
			}
		}
	}
	if !sawVIP || !sawLP {
		t.Fatalf("missing expected event types: sawVIP=%v sawLP=%v evs=%+v", sawVIP, sawLP, evs)
	}

	// Sweep 4: still MASTER + PROPAGATED_DOWN -> idempotent, no duplicate events
	if err := sweeper.SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce 4: %v", err)
	}
	_, total, _ = haEvents.ListEvents(ctx, hagroups.EventFilter{})
	if total != 2 {
		t.Fatalf("duplicate events emitted on steady state: total=%d", total)
	}
}
