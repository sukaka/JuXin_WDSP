package evidencekey

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
)

const PublicKeyGrantFormat = "wdsp-request-pcap-public-key"

var grantNodePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type PublicKeyGrant struct {
	Format    string    `json:"format"`
	Version   int       `json:"version"`
	NodeID    string    `json:"node_id"`
	KeyID     string    `json:"key_id"`
	PublicKey []byte    `json:"public_key"`
	NotBefore time.Time `json:"not_before"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature []byte    `json:"signature"`
}

func signedGrantBytes(grant PublicKeyGrant) ([]byte, error) {
	grant.Signature = nil
	return json.Marshal(grant)
}

func SignPublicKeyGrant(publicKey []byte, privateKey ed25519.PrivateKey, nodeID string, notBefore, expiresAt time.Time) ([]byte, error) {
	keyID, err := PublicKeyID(publicKey)
	if err != nil {
		return nil, err
	}
	if len(privateKey) != ed25519.PrivateKeySize || !grantNodePattern.MatchString(nodeID) || notBefore.IsZero() || !expiresAt.After(notBefore) {
		return nil, fmt.Errorf("invalid evidence public key grant")
	}
	grant := PublicKeyGrant{Format: PublicKeyGrantFormat, Version: 1, NodeID: nodeID, KeyID: keyID,
		PublicKey: append([]byte(nil), publicKey...), NotBefore: notBefore.UTC(), ExpiresAt: expiresAt.UTC()}
	payload, err := signedGrantBytes(grant)
	if err != nil {
		return nil, err
	}
	grant.Signature = ed25519.Sign(privateKey, payload)
	return json.Marshal(grant)
}

func VerifyPublicKeyGrant(encoded, trustedPublicKey []byte, nodeID string, now time.Time) ([]byte, string, error) {
	if len(trustedPublicKey) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("invalid evidence release trust key")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var grant PublicKeyGrant
	if err := decoder.Decode(&grant); err != nil {
		return nil, "", fmt.Errorf("invalid evidence public key grant encoding")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, "", fmt.Errorf("evidence public key grant has trailing content")
	}
	if grant.Format != PublicKeyGrantFormat || grant.Version != 1 || grant.NodeID != nodeID || len(grant.Signature) != ed25519.SignatureSize {
		return nil, "", fmt.Errorf("evidence public key grant format or node mismatch")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Add(30*time.Second).Before(grant.NotBefore) || !now.Before(grant.ExpiresAt) {
		return nil, "", fmt.Errorf("evidence public key grant is not currently valid")
	}
	keyID, err := PublicKeyID(grant.PublicKey)
	if err != nil || keyID != grant.KeyID {
		return nil, "", fmt.Errorf("evidence public key identity mismatch")
	}
	payload, err := signedGrantBytes(grant)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(trustedPublicKey), payload, grant.Signature) {
		return nil, "", fmt.Errorf("evidence public key grant signature verification failed")
	}
	return append([]byte(nil), grant.PublicKey...), keyID, nil
}
