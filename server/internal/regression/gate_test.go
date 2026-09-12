// gate_test.go 发布门禁 OFF/OBSERVE/ENFORCE 行为测试
// （缺失/过期/撤销/不完整/验证失败/依赖不可用/恢复通道）。
package regression

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fakeGateStore struct {
	policy    *Policy
	policyErr error
	run       *Run
	runErr    error
	objects   []ImportObjectRef
	objErr    error
	decisions []GateDecision
	decErr    error
}

func (f *fakeGateStore) GetPolicy(context.Context) (*Policy, error) { return f.policy, f.policyErr }
func (f *fakeGateStore) LatestVerifiedRunForFingerprint(context.Context, string) (*Run, error) {
	return f.run, f.runErr
}
func (f *fakeGateStore) RunObjects(context.Context, uuid.UUID) ([]ImportObjectRef, error) {
	return f.objects, f.objErr
}
func (f *fakeGateStore) InsertGateDecision(_ context.Context, d GateDecision) error {
	if f.decErr != nil {
		return f.decErr
	}
	f.decisions = append(f.decisions, d)
	return nil
}

type fakeObjectChecker struct{ intact map[uuid.UUID]bool }

func (f fakeObjectChecker) ObjectIntact(_ context.Context, id uuid.UUID) (bool, error) {
	return f.intact[id], nil
}

func gateTestKeys(t *testing.T, keyID string) (SettingsReader, string) {
	t.Helper()
	pub, _, err := ed25519Generate()
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(pub)
	val, _ := json.Marshal([]TrustedKey{{KeyID: keyID, Algorithm: SignatureAlgorithmEd25519, PublicKey: b64, Status: KeyStatusActive}})
	return func(context.Context, string, string, string) string { return string(val) }, b64
}

func gateTestRun(keyID string, created time.Time) *Run {
	return &Run{
		ID:                 uuid.New(),
		RunID:              "20260908T010000-abcdef",
		Level:              LevelFull,
		DeclaredStatus:     StatusPass,
		VerificationStatus: VerifyPassed,
		SignatureKeyID:     keyID,
		ConfigFingerprint:  testFP,
		CorpusID:           "p1-corpus",
		Counts:             ManifestCounts{Planned: 2, Executed: 2, Passed: 2, MandatoryTotal: 1},
		CreatedAt:          created,
	}
}

func enforcePolicy() *Policy {
	return &Policy{Mode: ModeEnforce, RequiredLevel: LevelFull, EvidenceMaxAgeSeconds: DefaultEvidenceMaxAge, Version: 3}
}

func TestGateOffNoCheckNoRecord(t *testing.T) {
	fs := &fakeGateStore{policy: &Policy{Mode: ModeOff}, runErr: ErrNotFound}
	g := NewGate(fs, nil, nil)
	res, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP})
	if err != nil || res.Decision != DecisionAllow {
		t.Fatalf("OFF: res=%+v err=%v", res, err)
	}
	if len(fs.decisions) != 0 {
		t.Fatal("OFF recorded a decision")
	}
}

func TestGateEnforceMissingEvidenceBlocks(t *testing.T) {
	fs := &fakeGateStore{policy: enforcePolicy(), runErr: ErrNotFound}
	g := NewGate(fs, gateTestKeysReader(t, "k1"), fakeObjectChecker{})
	_, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP})
	if !errors.Is(err, ErrGateRejected) {
		t.Fatalf("missing evidence not blocked: %v", err)
	}
	if len(fs.decisions) != 1 || fs.decisions[0].Decision != DecisionBlock {
		t.Fatalf("decision not recorded: %+v", fs.decisions)
	}
}

func TestGateEnforceValidEvidenceAllows(t *testing.T) {
	objID := uuid.New()
	fs := &fakeGateStore{
		policy:  enforcePolicy(),
		run:     gateTestRun("k1", time.Now().Add(-time.Hour)),
		objects: []ImportObjectRef{{ObjectID: objID, Role: KindManifest, SHA256: testHash}},
	}
	g := NewGate(fs, gateTestKeysReader(t, "k1"), fakeObjectChecker{intact: map[uuid.UUID]bool{objID: true}})
	res, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP})
	if err != nil || res.Decision != DecisionAllow {
		t.Fatalf("valid evidence blocked: res=%+v err=%v", res, err)
	}
}

func TestGateObserveRecordsButNeverBlocks(t *testing.T) {
	fs := &fakeGateStore{
		policy: &Policy{Mode: ModeObserve, RequiredLevel: LevelFull, EvidenceMaxAgeSeconds: DefaultEvidenceMaxAge, Version: 1},
		runErr: ErrNotFound,
	}
	g := NewGate(fs, gateTestKeysReader(t, "k1"), fakeObjectChecker{})
	res, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP})
	if err != nil {
		t.Fatalf("OBSERVE blocked: %v", err)
	}
	if res.Decision != DecisionRecord || len(fs.decisions) != 1 {
		t.Fatalf("OBSERVE not recorded: res=%+v decisions=%v", res, fs.decisions)
	}
}

func TestGateEnforceMatrix(t *testing.T) {
	objID := uuid.New()
	base := func() *fakeGateStore {
		return &fakeGateStore{
			policy:  enforcePolicy(),
			run:     gateTestRun("k1", time.Now().Add(-time.Hour)),
			objects: []ImportObjectRef{{ObjectID: objID, Role: KindManifest, SHA256: testHash}},
		}
	}
	intact := fakeObjectChecker{intact: map[uuid.UUID]bool{objID: true}}

	t.Run("expired", func(t *testing.T) {
		fs := base()
		fs.run.CreatedAt = time.Now().Add(-8 * 24 * time.Hour)
		g := NewGate(fs, gateTestKeysReader(t, "k1"), intact)
		if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateRejected) {
			t.Fatalf("expired not blocked: %v", err)
		}
	})
	t.Run("expired restore channel allowed with note", func(t *testing.T) {
		fs := base()
		fs.run.CreatedAt = time.Now().Add(-8 * 24 * time.Hour)
		g := NewGate(fs, gateTestKeysReader(t, "k1"), intact)
		res, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP, RestoreChannel: true})
		if err != nil || res.Decision != DecisionAllow {
			t.Fatalf("restore channel blocked by expiry: res=%+v err=%v", res, err)
		}
		if !strings.Contains(strings.Join(res.Reasons, ";"), "恢复通道") {
			t.Fatalf("restore note missing: %v", res.Reasons)
		}
	})
	t.Run("revoked key blocks even restore channel", func(t *testing.T) {
		fs := base()
		fs.run.CreatedAt = time.Now().Add(-8 * 24 * time.Hour)
		// 登记中 k1 已撤销
		revoked, _ := json.Marshal([]TrustedKey{{KeyID: "k1", Algorithm: SignatureAlgorithmEd25519,
			PublicKey: mustPubB64(t), Status: KeyStatusRevoked}})
		g := NewGate(fs, func(context.Context, string, string, string) string { return string(revoked) }, intact)
		if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP, RestoreChannel: true}); !errors.Is(err, ErrGateRejected) {
			t.Fatalf("revoked key not blocked: %v", err)
		}
	})
	t.Run("level too low", func(t *testing.T) {
		fs := base()
		fs.run.Level = LevelSmoke
		g := NewGate(fs, gateTestKeysReader(t, "k1"), intact)
		if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateRejected) {
			t.Fatalf("smoke evidence accepted for FULL gate: %v", err)
		}
	})
	t.Run("declared not pass", func(t *testing.T) {
		fs := base()
		fs.run.DeclaredStatus = StatusFail
		g := NewGate(fs, gateTestKeysReader(t, "k1"), intact)
		if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateRejected) {
			t.Fatalf("declared FAIL accepted: %v", err)
		}
	})
	t.Run("zero executed", func(t *testing.T) {
		fs := base()
		fs.run.Counts.Executed = 0
		g := NewGate(fs, gateTestKeysReader(t, "k1"), intact)
		if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateRejected) {
			t.Fatalf("zero executed accepted: %v", err)
		}
	})
	t.Run("mandatory incomplete", func(t *testing.T) {
		fs := base()
		fs.run.Counts.MandatoryFailed = 1
		g := NewGate(fs, gateTestKeysReader(t, "k1"), intact)
		if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateRejected) {
			t.Fatalf("mandatory failure accepted: %v", err)
		}
	})
	t.Run("evidence object cleaned", func(t *testing.T) {
		fs := base()
		g := NewGate(fs, gateTestKeysReader(t, "k1"), fakeObjectChecker{intact: map[uuid.UUID]bool{objID: false}})
		if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateRejected) {
			t.Fatalf("incomplete evidence accepted: %v", err)
		}
	})
	t.Run("corpus mismatch", func(t *testing.T) {
		fs := base()
		fs.policy.RequiredCorpusID = "other-corpus"
		g := NewGate(fs, gateTestKeysReader(t, "k1"), intact)
		if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateRejected) {
			t.Fatalf("corpus mismatch accepted: %v", err)
		}
	})
}

func TestGateDependencyUnavailableExplicitFailure(t *testing.T) {
	// 策略读取失败：无法判定模式，明确失败（OBSERVE 可能性也不放行）
	fs := &fakeGateStore{policyErr: errors.New("db down")}
	g := NewGate(fs, nil, nil)
	if _, err := g.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateUnavailable) {
		t.Fatalf("policy read failure not unavailable: %v", err)
	}
	// 密钥登记损坏
	fs2 := &fakeGateStore{policy: enforcePolicy(), run: gateTestRun("k1", time.Now())}
	bad := func(context.Context, string, string, string) string { return `[{corrupt` }
	g2 := NewGate(fs2, bad, fakeObjectChecker{})
	if _, err := g2.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateUnavailable) {
		t.Fatalf("corrupt key registry not unavailable: %v", err)
	}
	// 证据查询失败
	fs3 := &fakeGateStore{policy: enforcePolicy(), runErr: errors.New("query boom")}
	g3 := NewGate(fs3, gateTestKeysReader(t, "k1"), fakeObjectChecker{})
	if _, err := g3.Evaluate(context.Background(), GateInput{Fingerprint: testFP}); !errors.Is(err, ErrGateUnavailable) {
		t.Fatalf("evidence query failure not unavailable: %v", err)
	}
}

func gateTestKeysReader(t *testing.T, keyID string) SettingsReader {
	t.Helper()
	r, _ := gateTestKeys(t, keyID)
	return r
}

func mustPubB64(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519Generate()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}
