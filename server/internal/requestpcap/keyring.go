package requestpcap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
)

type keyEncryption interface {
	Encrypt(string) (string, error)
	Decrypt(string) (string, error)
}

// Keyring 在内存中保存证据私钥；私钥文件只保存主密钥加密后的密文。
type Keyring struct {
	mu                sync.RWMutex
	path              string
	encryption        keyEncryption
	privateKey        []byte
	publicKey         []byte
	keyID             string
	history           map[string][]byte
	releasePrivate    ed25519.PrivateKey
	releasePublic     ed25519.PublicKey
	releaseCiphertext string
}

type keyFileEntry struct {
	KeyID                string `json:"key_id"`
	PrivateKeyCiphertext string `json:"private_key_ciphertext"`
}

type keyFile struct {
	Format                   string         `json:"format"`
	Version                  int            `json:"version"`
	KeyID                    string         `json:"key_id"`
	PrivateKeyCiphertext     string         `json:"private_key_ciphertext"`
	ReleasePublicKey         []byte         `json:"release_public_key"`
	ReleasePrivateCiphertext string         `json:"release_private_key_ciphertext"`
	History                  []keyFileEntry `json:"history,omitempty"`
}

func LoadOrCreateKeyring(path string, encryption keyEncryption) (*Keyring, error) {
	if !filepath.IsAbs(path) || encryption == nil {
		return nil, fmt.Errorf("evidence key path and encryption service are required")
	}
	if stat, err := os.Stat(filepath.Dir(path)); err != nil || !stat.IsDir() {
		return nil, fmt.Errorf("evidence key parent directory is unavailable")
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return createKeyring(path, encryption)
	}
	return loadKeyring(path, encryption)
}

func createKeyring(path string, encryption keyEncryption) (*Keyring, error) {
	pair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	releasePublic, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ciphertext, err := encryption.Encrypt(string(pair.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("encrypt evidence private key: %w", err)
	}
	releaseCiphertext, err := encryption.Encrypt(string(releasePrivate))
	if err != nil {
		return nil, fmt.Errorf("encrypt evidence release private key: %w", err)
	}
	keyID, err := evidencekey.PublicKeyID(pair.PublicKey)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(keyFile{Format: "wdsp-request-pcap-key", Version: 2, KeyID: keyID,
		PrivateKeyCiphertext: ciphertext, ReleasePublicKey: releasePublic, ReleasePrivateCiphertext: releaseCiphertext})
	if err != nil {
		return nil, err
	}
	if err := writeKeyFile(path, payload, false); err != nil {
		return nil, err
	}
	return &Keyring{path: path, encryption: encryption, privateKey: pair.PrivateKey, publicKey: pair.PublicKey, keyID: keyID,
		history: map[string][]byte{keyID: pair.PrivateKey}, releasePrivate: releasePrivate, releasePublic: releasePublic, releaseCiphertext: releaseCiphertext}, nil
}

func loadKeyring(path string, encryption keyEncryption) (*Keyring, error) {
	file, err := openRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("evidence private key file must not be accessible by group or others")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(payload) > 64<<10 {
		return nil, fmt.Errorf("evidence key file is too large or unreadable")
	}
	var stored keyFile
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return nil, fmt.Errorf("invalid evidence key file: %w", err)
	}
	if stored.Format != "wdsp-request-pcap-key" || stored.Version != 2 || stored.PrivateKeyCiphertext == "" || stored.ReleasePrivateCiphertext == "" || len(stored.History) >= 256 {
		return nil, fmt.Errorf("unsupported evidence key file")
	}
	current, publicKey, err := decryptKeyEntry(stored.KeyID, stored.PrivateKeyCiphertext, encryption)
	if err != nil {
		return nil, err
	}
	history := map[string][]byte{stored.KeyID: current}
	for _, entry := range stored.History {
		if _, exists := history[entry.KeyID]; exists {
			return nil, fmt.Errorf("duplicate evidence private key id")
		}
		privateKey, _, err := decryptKeyEntry(entry.KeyID, entry.PrivateKeyCiphertext, encryption)
		if err != nil {
			return nil, err
		}
		history[entry.KeyID] = privateKey
	}
	releaseText, err := encryption.Decrypt(stored.ReleasePrivateCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt evidence release private key: %w", err)
	}
	releasePrivate := ed25519.PrivateKey(releaseText)
	if len(releasePrivate) != ed25519.PrivateKeySize || !bytes.Equal(releasePrivate.Public().(ed25519.PublicKey), stored.ReleasePublicKey) {
		return nil, fmt.Errorf("evidence release key identity mismatch")
	}
	return &Keyring{path: path, encryption: encryption, privateKey: current, publicKey: publicKey, keyID: stored.KeyID, history: history,
		releasePrivate: releasePrivate, releasePublic: append(ed25519.PublicKey(nil), stored.ReleasePublicKey...), releaseCiphertext: stored.ReleasePrivateCiphertext}, nil
}

func decryptKeyEntry(keyID, ciphertext string, encryption keyEncryption) ([]byte, []byte, error) {
	privateText, err := encryption.Decrypt(ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decrypt evidence private key: %w", err)
	}
	privateKey := []byte(privateText)
	publicKey, err := evidencekey.PublicKeyFromPrivate(privateKey)
	if err != nil {
		clear(privateKey)
		return nil, nil, err
	}
	actualID, err := evidencekey.PublicKeyID(publicKey)
	if err != nil || actualID != keyID {
		clear(privateKey)
		return nil, nil, fmt.Errorf("evidence key id does not match decrypted private key")
	}
	return privateKey, publicKey, nil
}

func (k *Keyring) PublicKey() []byte {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return append([]byte(nil), k.publicKey...)
}

func (k *Keyring) KeyID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keyID
}

func (k *Keyring) Unwrap(keyID string, envelope []byte) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("evidence key is unavailable")
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	privateKey := k.history[keyID]
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("evidence key is unavailable for requested key id")
	}
	return evidencekey.UnwrapDEK(privateKey, keyID, envelope)
}

func (k *Keyring) Rotate() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.encryption == nil || len(k.privateKey) == 0 || len(k.history) >= 256 {
		return fmt.Errorf("evidence keyring is closed or history limit reached")
	}
	pair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		return err
	}
	keyID, err := evidencekey.PublicKeyID(pair.PublicKey)
	if err != nil {
		return err
	}
	ciphertext, err := k.encryption.Encrypt(string(pair.PrivateKey))
	if err != nil {
		return fmt.Errorf("encrypt rotated evidence private key: %w", err)
	}
	entries := make([]keyFileEntry, 0, len(k.history)-1)
	for historicalID, privateKey := range k.history {
		if historicalID == k.keyID {
			continue
		}
		historicalCiphertext, err := k.encryption.Encrypt(string(privateKey))
		if err != nil {
			return err
		}
		entries = append(entries, keyFileEntry{KeyID: historicalID, PrivateKeyCiphertext: historicalCiphertext})
	}
	oldCiphertext, err := k.encryption.Encrypt(string(k.privateKey))
	if err != nil {
		return err
	}
	entries = append(entries, keyFileEntry{KeyID: k.keyID, PrivateKeyCiphertext: oldCiphertext})
	payload, err := json.Marshal(keyFile{Format: "wdsp-request-pcap-key", Version: 2, KeyID: keyID,
		PrivateKeyCiphertext: ciphertext, ReleasePublicKey: k.releasePublic, ReleasePrivateCiphertext: k.releaseCiphertext, History: entries})
	if err != nil {
		return err
	}
	if err := writeKeyFile(k.path, payload, true); err != nil {
		return err
	}
	k.privateKey = pair.PrivateKey
	k.publicKey = pair.PublicKey
	k.keyID = keyID
	k.history[keyID] = pair.PrivateKey
	return nil
}

func (k *Keyring) WritePublicGrant(grantPath, trustPath, nodeID string, now time.Time, lifetime time.Duration) error {
	if k == nil || !filepath.IsAbs(grantPath) || !filepath.IsAbs(trustPath) || lifetime < time.Minute || lifetime > 7*24*time.Hour {
		return fmt.Errorf("invalid evidence public key grant configuration")
	}
	k.mu.RLock()
	if len(k.releasePrivate) == 0 {
		k.mu.RUnlock()
		return fmt.Errorf("evidence release key is unavailable")
	}
	encoded, err := evidencekey.SignPublicKeyGrant(k.publicKey, k.releasePrivate, nodeID, now.Add(-time.Second), now.Add(lifetime))
	releasePublic := append(ed25519.PublicKey(nil), k.releasePublic...)
	k.mu.RUnlock()
	if err != nil {
		return err
	}
	if existing, err := os.ReadFile(trustPath); err == nil {
		if !bytes.Equal(existing, releasePublic) {
			return fmt.Errorf("evidence release trust key does not match the installed keyring")
		}
	} else if os.IsNotExist(err) {
		if err := writePublicFile(trustPath, releasePublic); err != nil {
			return err
		}
	} else {
		return err
	}
	return writePublicFile(grantPath, encoded)
}

func writeKeyFile(path string, payload []byte, overwrite bool) error {
	temporary := path + ".tmp"
	if err := removeRegularIfExists(temporary); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if err := writeKeyBytes(file, payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if overwrite {
		err = os.Rename(temporary, path)
	} else {
		err = os.Link(temporary, path)
		if err == nil {
			err = os.Remove(temporary)
		}
	}
	if err != nil {
		return fmt.Errorf("publish evidence key: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func writePublicFile(path string, payload []byte) error {
	if stat, err := os.Stat(filepath.Dir(path)); err != nil || !stat.IsDir() {
		return fmt.Errorf("evidence public key parent directory is unavailable")
	}
	temporary := path + ".tmp"
	if err := removeRegularIfExists(temporary); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	if err := writeKeyBytes(file, payload); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func (k *Keyring) Close() {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, privateKey := range k.history {
		clear(privateKey)
	}
	clear(k.privateKey)
	clear(k.releasePrivate)
	k.privateKey = nil
	k.releasePrivate = nil
	k.history = nil
	k.encryption = nil
}

func writeKeyBytes(file *os.File, data []byte) error {
	for len(data) > 0 {
		n, err := file.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
