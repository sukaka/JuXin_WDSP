package requestpcap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
)

var (
	ErrEvidenceNotFound    = errors.New("request PCAP evidence not found")
	ErrEvidenceUnavailable = errors.New("request PCAP evidence is not available for download")
	ErrOperationBusy       = errors.New("another PCAP verification or download is active for this user")
	validEvidenceRequestID = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

type evidenceStore interface {
	ListRequestLinks(context.Context, string) ([]RequestLink, error)
	GetRequestLink(context.Context, string, uuid.UUID) (RequestLink, error)
	GetArtifact(context.Context, uuid.UUID) (Artifact, error)
	SetVerification(context.Context, uuid.UUID, string, string, time.Time) error
	CreateDownloadGrant(context.Context, DownloadGrant) error
	ConsumeDownloadGrant(context.Context, uuid.UUID, uuid.UUID, string, time.Time) (DownloadGrant, error)
}

type evidenceUnwrapper interface {
	Unwrap(keyID string, envelope []byte) ([]byte, error)
}

type EvidenceItem struct {
	ArtifactID            uuid.UUID  `json:"artifact_id"`
	NodeID                string     `json:"gateway_node_id"`
	CapturePoint          string     `json:"capture_point"`
	State                 string     `json:"state"`
	StorageTier           string     `json:"storage_tier"`
	CaptureStartedAt      time.Time  `json:"capture_started_at"`
	CaptureEndedAt        time.Time  `json:"capture_ended_at"`
	PacketCount           int64      `json:"packet_count"`
	DroppedCount          int64      `json:"dropped_count"`
	Truncated             bool       `json:"truncated"`
	PlaintextSizeBytes    int64      `json:"plaintext_size_bytes"`
	CiphertextSizeBytes   int64      `json:"ciphertext_size_bytes"`
	PlaintextSHA256       string     `json:"plaintext_sha256"`
	CiphertextSHA256      string     `json:"ciphertext_sha256"`
	ExpiresAt             time.Time  `json:"expires_at"`
	IntegrityStatus       string     `json:"integrity_status"`
	LastVerifiedAt        *time.Time `json:"last_verified_at,omitempty"`
	VerificationErrorCode string     `json:"verification_error_code,omitempty"`
	MatchStatus           string     `json:"match_status"`
	MatchBasis            string     `json:"match_basis"`
	Coverage              string     `json:"coverage"`
	CandidateCount        int        `json:"candidate_count"`
	FirstPacketNo         *int64     `json:"first_packet_no,omitempty"`
	LastPacketNo          *int64     `json:"last_packet_no,omitempty"`
	DownloadEligible      bool       `json:"download_eligible"`
	DownloadBlockedReason string     `json:"download_blocked_reason,omitempty"`
}

type EvidenceStatus struct {
	RequestID string         `json:"request_id"`
	Items     []EvidenceItem `json:"items"`
	Truncated bool           `json:"truncated"`
}

type Service struct {
	store    evidenceStore
	keys     evidenceUnwrapper
	hotRoot  string
	warmRoot string
	now      func() time.Time
	slots    chan struct{}
	mu       sync.Mutex
	users    map[uuid.UUID]struct{}
}

func NewService(store evidenceStore, keys evidenceUnwrapper, hotRoot, warmRoot string) (*Service, error) {
	if store == nil || keys == nil || !filepath.IsAbs(hotRoot) || !filepath.IsAbs(warmRoot) || filepath.Clean(hotRoot) == filepath.Clean(warmRoot) {
		return nil, fmt.Errorf("evidence store, keyring and distinct absolute storage roots are required")
	}
	for _, root := range []string{hotRoot, warmRoot} {
		stat, err := os.Stat(root)
		if err != nil || !stat.IsDir() {
			return nil, fmt.Errorf("evidence storage root is unavailable")
		}
	}
	return &Service{store: store, keys: keys, hotRoot: filepath.Clean(hotRoot), warmRoot: filepath.Clean(warmRoot),
		now: func() time.Time { return time.Now().UTC() }, slots: make(chan struct{}, 2), users: make(map[uuid.UUID]struct{})}, nil
}

func (s *Service) Query(ctx context.Context, requestID string) (EvidenceStatus, error) {
	if s == nil || !validEvidenceRequestID.MatchString(requestID) {
		return EvidenceStatus{}, ErrEvidenceNotFound
	}
	links, err := s.store.ListRequestLinks(ctx, requestID)
	if err != nil {
		return EvidenceStatus{}, err
	}
	result := EvidenceStatus{RequestID: requestID, Truncated: len(links) > 100, Items: make([]EvidenceItem, 0, len(links))}
	if result.Truncated {
		links = links[:100]
	}
	for _, link := range links {
		artifact, err := s.store.GetArtifact(ctx, link.ArtifactID)
		if errors.Is(err, ErrArtifactNotFound) {
			return EvidenceStatus{}, fmt.Errorf("request evidence %s has no artifact", link.ArtifactID)
		}
		if err != nil {
			return EvidenceStatus{}, err
		}
		result.Items = append(result.Items, publicEvidence(artifact, link, s.now()))
	}
	return result, nil
}

func publicEvidence(artifact Artifact, link RequestLink, now time.Time) EvidenceItem {
	item := EvidenceItem{ArtifactID: artifact.ID, NodeID: artifact.NodeID, CapturePoint: artifact.CapturePoint,
		State: artifact.State, StorageTier: artifact.StorageTier, CaptureStartedAt: artifact.CaptureStartedAt,
		CaptureEndedAt: artifact.CaptureEndedAt, PacketCount: artifact.PacketCount, DroppedCount: artifact.DroppedCount,
		Truncated: artifact.Truncated, PlaintextSizeBytes: artifact.PlaintextSizeBytes,
		CiphertextSizeBytes: artifact.CiphertextSizeBytes, PlaintextSHA256: artifact.PlaintextSHA256,
		CiphertextSHA256: artifact.CiphertextSHA256, ExpiresAt: artifact.ExpiresAt,
		IntegrityStatus: artifact.IntegrityStatus, LastVerifiedAt: artifact.LastVerifiedAt,
		VerificationErrorCode: artifact.VerificationErrorCode, MatchStatus: link.MatchStatus,
		MatchBasis: link.MatchBasis, Coverage: link.Coverage, CandidateCount: link.CandidateCount,
		FirstPacketNo: link.FirstPacketNo, LastPacketNo: link.LastPacketNo}
	item.DownloadEligible, item.DownloadBlockedReason = downloadable(artifact, link, now)
	return item
}

func downloadable(artifact Artifact, link RequestLink, now time.Time) (bool, string) {
	switch {
	case artifact.State != "HOT" && artifact.State != "WARM" && artifact.State != "MIGRATING":
		return false, "STORAGE_UNAVAILABLE"
	case artifact.Truncated || artifact.DroppedCount != 0:
		return false, "EVIDENCE_INCOMPLETE"
	case !now.Before(artifact.ExpiresAt) || !now.Before(link.ExpiresAt):
		return false, "EVIDENCE_EXPIRED"
	case link.MatchStatus != "MATCHED" || link.CandidateCount != 1:
		return false, "UNIQUE_CORRELATION_REQUIRED"
	case link.Coverage != "REQUEST" && link.Coverage != "CONNECTION":
		return false, "PACKET_RANGE_REQUIRED"
	case link.FirstPacketNo == nil || link.LastPacketNo == nil || *link.FirstPacketNo <= 0 || *link.LastPacketNo < *link.FirstPacketNo || *link.LastPacketNo > artifact.PacketCount:
		return false, "PACKET_RANGE_REQUIRED"
	case artifact.IntegrityStatus != "PASS":
		return false, "VERIFICATION_REQUIRED"
	default:
		return true, ""
	}
}

func (s *Service) linkedArtifact(ctx context.Context, requestID string, artifactID uuid.UUID) (Artifact, RequestLink, error) {
	if !validEvidenceRequestID.MatchString(requestID) || artifactID == uuid.Nil {
		return Artifact{}, RequestLink{}, ErrEvidenceNotFound
	}
	link, err := s.store.GetRequestLink(ctx, requestID, artifactID)
	if errors.Is(err, ErrArtifactNotFound) {
		return Artifact{}, RequestLink{}, ErrEvidenceNotFound
	}
	if err != nil {
		return Artifact{}, RequestLink{}, err
	}
	artifact, err := s.store.GetArtifact(ctx, artifactID)
	if errors.Is(err, ErrArtifactNotFound) {
		return Artifact{}, RequestLink{}, ErrEvidenceNotFound
	}
	return artifact, link, err
}

func (s *Service) acquire(ctx context.Context, userID uuid.UUID) (func(), error) {
	if userID == uuid.Nil {
		return nil, ErrEvidenceUnavailable
	}
	s.mu.Lock()
	if _, exists := s.users[userID]; exists {
		s.mu.Unlock()
		return nil, ErrOperationBusy
	}
	s.users[userID] = struct{}{}
	s.mu.Unlock()
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.users, userID)
		s.mu.Unlock()
		return nil, ctx.Err()
	}
	return func() {
		<-s.slots
		s.mu.Lock()
		delete(s.users, userID)
		s.mu.Unlock()
	}, nil
}

func (s *Service) Verify(ctx context.Context, requestID string, artifactID, userID uuid.UUID) (EvidenceItem, error) {
	release, err := s.acquire(ctx, userID)
	if err != nil {
		return EvidenceItem{}, err
	}
	defer release()
	artifact, link, err := s.linkedArtifact(ctx, requestID, artifactID)
	if err != nil {
		return EvidenceItem{}, err
	}
	if artifact.State != "HOT" && artifact.State != "WARM" && artifact.State != "MIGRATING" {
		return EvidenceItem{}, ErrEvidenceUnavailable
	}
	file, err := s.openArtifact(artifact)
	if err != nil {
		return EvidenceItem{}, s.recordVerification(ctx, artifact, "FAILED", "STORAGE_UNAVAILABLE")
	}
	defer file.Close()
	manifest, err := artifactManifest(artifact)
	if err != nil {
		return EvidenceItem{}, s.recordVerification(ctx, artifact, "FAILED", "MANIFEST_INVALID")
	}
	key, err := s.keys.Unwrap(artifact.KeyID, artifact.WrappedDEK)
	if err != nil {
		return EvidenceItem{}, s.recordVerification(ctx, artifact, "KEY_UNAVAILABLE", "KEY_UNAVAILABLE")
	}
	err = pcapevidence.VerifyAndDecryptFile(file, manifest, key, io.Discard)
	clear(key)
	if err != nil {
		return EvidenceItem{}, s.recordVerification(ctx, artifact, "FAILED", "INTEGRITY_FAILED")
	}
	if err := s.recordVerification(ctx, artifact, "PASS", ""); err != nil {
		return EvidenceItem{}, err
	}
	artifact.IntegrityStatus = "PASS"
	verifiedAt := s.now()
	artifact.LastVerifiedAt = &verifiedAt
	artifact.VerificationErrorCode = ""
	return publicEvidence(artifact, link, verifiedAt), nil
}

func (s *Service) recordVerification(ctx context.Context, artifact Artifact, status, code string) error {
	if err := s.store.SetVerification(ctx, artifact.ID, status, code, s.now()); err != nil {
		return fmt.Errorf("record PCAP verification: %w", err)
	}
	if status == "PASS" {
		return nil
	}
	return ErrEvidenceUnavailable
}

func (s *Service) CreateGrant(ctx context.Context, requestID string, artifactID, userID uuid.UUID, sessionID, reason, sourceIP string) (DownloadGrant, error) {
	artifact, link, err := s.linkedArtifact(ctx, requestID, artifactID)
	if err != nil {
		return DownloadGrant{}, err
	}
	if eligible, _ := downloadable(artifact, link, s.now()); !eligible {
		return DownloadGrant{}, ErrEvidenceUnavailable
	}
	grant := DownloadGrant{ID: uuid.New(), ArtifactID: artifactID, RequestID: requestID, UserID: userID,
		SessionID: sessionID, Reason: strings.TrimSpace(reason), SourceIP: sourceIP, ExpiresAt: s.now().Add(time.Minute)}
	if err := s.store.CreateDownloadGrant(ctx, grant); err != nil {
		return DownloadGrant{}, err
	}
	return grant, nil
}

type PreparedDownload struct {
	file        *os.File
	key         []byte
	manifest    pcapevidence.Manifest
	first       uint64
	last        uint64
	Filename    string
	PacketCount uint64
	release     func()
}

func (s *Service) PrepareDownload(ctx context.Context, requestID string, artifactID, grantID, userID uuid.UUID, sessionID string) (*PreparedDownload, error) {
	release, err := s.acquire(ctx, userID)
	if err != nil {
		return nil, err
	}
	artifact, link, err := s.linkedArtifact(ctx, requestID, artifactID)
	if err != nil {
		release()
		return nil, err
	}
	if eligible, _ := downloadable(artifact, link, s.now()); !eligible {
		release()
		return nil, ErrEvidenceUnavailable
	}
	grant, err := s.store.ConsumeDownloadGrant(ctx, grantID, userID, sessionID, s.now())
	if err != nil {
		release()
		return nil, err
	}
	if grant.RequestID != requestID || grant.ArtifactID != artifactID {
		release()
		return nil, ErrGrantNotAvailable
	}
	prepared, err := s.prepareFile(artifact, link)
	if err != nil {
		release()
		return nil, err
	}
	prepared.release = release
	return prepared, nil
}

func (s *Service) prepareFile(artifact Artifact, link RequestLink) (*PreparedDownload, error) {
	file, err := s.openArtifact(artifact)
	if err != nil {
		return nil, ErrEvidenceUnavailable
	}
	manifest, err := artifactManifest(artifact)
	if err != nil {
		_ = file.Close()
		return nil, ErrEvidenceUnavailable
	}
	key, err := s.keys.Unwrap(artifact.KeyID, artifact.WrappedDEK)
	if err != nil {
		_ = file.Close()
		return nil, ErrEvidenceUnavailable
	}
	return &PreparedDownload{file: file, key: key, manifest: manifest, first: uint64(*link.FirstPacketNo), last: uint64(*link.LastPacketNo),
		Filename: "request-" + artifact.ID.String() + ".pcap", PacketCount: uint64(*link.LastPacketNo - *link.FirstPacketNo + 1)}, nil
}

func (s *Service) openArtifact(artifact Artifact) (*os.File, error) {
	root := s.warmRoot
	if artifact.StorageTier == "HOT" {
		root = s.hotRoot
	}
	return openRegularFile(filepath.Join(root, artifact.ID.String()+".wpcap"))
}

func artifactManifest(artifact Artifact) (pcapevidence.Manifest, error) {
	initial := artifact
	initial.State, initial.StorageTier = "HOT", "HOT"
	if err := ValidateArtifact(initial); err != nil {
		return pcapevidence.Manifest{}, err
	}
	var manifest pcapevidence.Manifest
	if err := json.Unmarshal(artifact.Manifest, &manifest); err != nil {
		return pcapevidence.Manifest{}, err
	}
	if err := manifest.Validate(); err != nil {
		return pcapevidence.Manifest{}, err
	}
	return manifest, nil
}

func (d *PreparedDownload) WriteTo(output io.Writer) (int64, error) {
	if d == nil || d.file == nil || output == nil {
		return 0, ErrEvidenceUnavailable
	}
	reader, writer := io.Pipe()
	result := make(chan error, 1)
	go func() {
		err := pcapevidence.VerifyAndDecryptFile(d.file, d.manifest, d.key, writer)
		_ = writer.CloseWithError(err)
		result <- err
	}()
	selected, err := pcapevidence.ExportPCAPRange(reader, output, d.first, d.last)
	if err != nil {
		_ = reader.CloseWithError(err)
	}
	if decryptErr := <-result; err == nil {
		err = decryptErr
	}
	if err == nil && selected != d.PacketCount {
		err = ErrEvidenceUnavailable
	}
	return int64(selected), err
}

func (d *PreparedDownload) Close() {
	if d == nil {
		return
	}
	if d.file != nil {
		_ = d.file.Close()
		d.file = nil
	}
	clear(d.key)
	d.key = nil
	if d.release != nil {
		d.release()
		d.release = nil
	}
}
