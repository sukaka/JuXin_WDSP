package requestpcap

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
)

type serviceStoreStub struct {
	mu       sync.Mutex
	artifact Artifact
	link     RequestLink
	grants   map[uuid.UUID]DownloadGrant
	consumed int
}

func (s *serviceStoreStub) ListRequestLinks(_ context.Context, requestID string) ([]RequestLink, error) {
	if requestID != s.link.RequestID {
		return []RequestLink{}, nil
	}
	return []RequestLink{s.link}, nil
}

func (s *serviceStoreStub) GetRequestLink(_ context.Context, requestID string, artifactID uuid.UUID) (RequestLink, error) {
	if requestID != s.link.RequestID || artifactID != s.link.ArtifactID {
		return RequestLink{}, ErrArtifactNotFound
	}
	return s.link, nil
}

func (s *serviceStoreStub) GetArtifact(_ context.Context, id uuid.UUID) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != s.artifact.ID {
		return Artifact{}, ErrArtifactNotFound
	}
	return s.artifact, nil
}

func (s *serviceStoreStub) SetVerification(_ context.Context, id uuid.UUID, status, code string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != s.artifact.ID {
		return ErrArtifactNotFound
	}
	s.artifact.IntegrityStatus = status
	s.artifact.VerificationErrorCode = code
	s.artifact.LastVerifiedAt = &at
	return nil
}

func (s *serviceStoreStub) CreateDownloadGrant(_ context.Context, grant DownloadGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if grant.Reason == "" || !grant.ExpiresAt.After(time.Now()) {
		return errors.New("invalid grant")
	}
	s.grants[grant.ID] = grant
	return nil
}

func (s *serviceStoreStub) ConsumeDownloadGrant(_ context.Context, id, userID uuid.UUID, sessionID string, now time.Time) (DownloadGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, ok := s.grants[id]
	if !ok || grant.UserID != userID || grant.SessionID != sessionID || grant.ConsumedAt != nil || !grant.ExpiresAt.After(now) {
		return DownloadGrant{}, ErrGrantNotAvailable
	}
	grant.ConsumedAt = &now
	s.grants[id] = grant
	s.consumed++
	return grant, nil
}

type serviceKeyStub struct {
	privateKey []byte
}

func (s serviceKeyStub) Unwrap(keyID string, envelope []byte) ([]byte, error) {
	return evidencekey.UnwrapDEK(s.privateKey, keyID, envelope)
}

func TestServiceRealVerificationAndDerivedDownload(t *testing.T) {
	store, service, plain := newServiceFixture(t)
	ctx := context.Background()
	status, err := service.Query(ctx, store.link.RequestID)
	if err != nil || len(status.Items) != 1 || status.Items[0].DownloadEligible {
		t.Fatalf("unverified evidence should not be downloadable: %+v err=%v", status, err)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"wrapped_dek", "private_key", ".wpcap", "hot", "manifest"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("query leaked internal evidence metadata %q: %s", forbidden, encoded)
		}
	}
	verified, err := service.Verify(ctx, store.link.RequestID, store.artifact.ID, uuid.New())
	if err != nil || verified.IntegrityStatus != "PASS" || !verified.DownloadEligible {
		t.Fatalf("real verification failed: %+v err=%v", verified, err)
	}
	userID := uuid.New()
	grant, err := service.CreateGrant(ctx, store.link.RequestID, store.artifact.ID, userID, "session-a", "调查真实攻击", "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(grant.ExpiresAt) > time.Minute {
		t.Fatal("grant exceeds the one-minute lifetime")
	}
	if _, err := service.PrepareDownload(ctx, store.link.RequestID, store.artifact.ID, grant.ID, uuid.New(), "session-a"); !errors.Is(err, ErrGrantNotAvailable) {
		t.Fatalf("cross-user download error=%v", err)
	}
	prepared, err := service.PrepareDownload(ctx, store.link.RequestID, store.artifact.ID, grant.ID, userID, "session-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(ctx, store.link.RequestID, store.artifact.ID, userID); !errors.Is(err, ErrOperationBusy) {
		t.Fatalf("same-user concurrent operation error=%v", err)
	}
	var output bytes.Buffer
	packets, err := prepared.WriteTo(&output)
	prepared.Close()
	if err != nil || packets != 1 {
		t.Fatalf("real derived download packets=%d err=%v", packets, err)
	}
	var expected bytes.Buffer
	if _, err := pcapevidence.ExportPCAPRange(bytes.NewReader(plain), &expected, 2, 2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), expected.Bytes()) {
		t.Fatal("derived PCAP does not match the selected real packet")
	}
	if _, err := service.PrepareDownload(ctx, store.link.RequestID, store.artifact.ID, grant.ID, userID, "session-a"); !errors.Is(err, ErrGrantNotAvailable) {
		t.Fatalf("grant was replayed: %v", err)
	}
	entries, err := os.ReadDir(service.hotRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.HasSuffix(entries[0].Name(), ".wpcap") {
		t.Fatalf("plaintext or temporary file was left in storage: %+v", entries)
	}
}

func TestServiceVerificationFailureBlocksGrant(t *testing.T) {
	store, service, _ := newServiceFixture(t)
	userID := uuid.New()
	path := filepath.Join(service.hotRoot, store.artifact.ID.String()+".wpcap")
	file, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, 40); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), store.link.RequestID, store.artifact.ID, userID); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("tampered evidence verification error=%v", err)
	}
	artifact, _ := store.GetArtifact(context.Background(), store.artifact.ID)
	if artifact.IntegrityStatus != "FAILED" || artifact.VerificationErrorCode != "INTEGRITY_FAILED" {
		t.Fatalf("tamper result not persisted: %+v", artifact)
	}
	if _, err := service.CreateGrant(context.Background(), store.link.RequestID, store.artifact.ID, userID, "session-a", "取证", ""); !errors.Is(err, ErrEvidenceUnavailable) {
		t.Fatalf("tampered evidence grant error=%v", err)
	}
}

func newServiceFixture(t *testing.T) (*serviceStoreStub, *Service, []byte) {
	t.Helper()
	plain := testPCAP(t)
	hotRoot, warmRoot := t.TempDir(), t.TempDir()
	artifactID, err := pcapevidence.NewArtifactID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hotRoot, artifactID.String()+".wpcap")
	key := bytes.Repeat([]byte{23}, 32)
	writer, err := pcapevidence.NewSegmentWriter(path, pcapevidence.Segment{ArtifactID: artifactID, NodeID: "gw-service",
		CapturePoint: "GATEWAY_EGRESS", StartedAt: time.Now().UTC().Add(-time.Minute), PacketCount: 3}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	manifest, err := writer.Commit()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Segment.PacketCount = 3
	manifest.Segment.DroppedCount = 0
	encodedManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, keyID, err := evidencekey.WrapDEK(pair.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := ArtifactFromManifest(encodedManifest, wrapped, keyID, time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	artifact.IntegrityStatus = "UNVERIFIED"
	first, last := int64(2), int64(2)
	link := RequestLink{ID: uuid.New(), ArtifactID: uuid.MustParse(artifactID.String()), RequestID: "req-service",
		MatchStatus: "MATCHED", MatchBasis: "HTTP1_REQUEST_ID", Coverage: "CONNECTION", CandidateCount: 1,
		FirstPacketNo: &first, LastPacketNo: &last, ExpiresAt: artifact.ExpiresAt}
	store := &serviceStoreStub{artifact: artifact, link: link, grants: make(map[uuid.UUID]DownloadGrant)}
	service, err := NewService(store, serviceKeyStub{privateKey: pair.PrivateKey}, hotRoot, warmRoot)
	if err != nil {
		t.Fatal(err)
	}
	return store, service, plain
}

func testPCAP(t *testing.T) []byte {
	t.Helper()
	var output bytes.Buffer
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 65535)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	output.Write(header)
	for i := byte(1); i <= 3; i++ {
		packet := bytes.Repeat([]byte{i}, 64)
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record[0:4], uint32(i))
		binary.LittleEndian.PutUint32(record[8:12], uint32(len(packet)))
		binary.LittleEndian.PutUint32(record[12:16], uint32(len(packet)))
		output.Write(record)
		output.Write(packet)
	}
	return output.Bytes()
}
