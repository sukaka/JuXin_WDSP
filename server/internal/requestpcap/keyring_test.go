package requestpcap

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

func TestKeyringEncryptedInstallReloadAndUnwrap(t *testing.T) {
	master, err := encryption.NewWithKey(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "evidence-private.key")
	keyring, err := LoadOrCreateKeyring(path, master)
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()
	plainDEK := bytes.Repeat([]byte{7}, 32)
	wrapped, keyID, err := evidencekey.WrapDEK(keyring.PublicKey(), plainDEK)
	if err != nil {
		t.Fatal(err)
	}
	unwrapped, err := keyring.Unwrap(keyID, wrapped)
	if err != nil || !bytes.Equal(unwrapped, plainDEK) {
		t.Fatalf("keyring did not unwrap DEK: %v", err)
	}
	clear(unwrapped)

	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, keyring.privateKey) || bytes.Contains(disk, []byte("private_key\"")) {
		t.Fatal("private key file contains plaintext key material")
	}
	stat, err := os.Stat(path)
	if err != nil || stat.Mode().Perm() != 0o600 {
		t.Fatalf("private key file mode=%v err=%v", stat.Mode(), err)
	}
	reloaded, err := LoadOrCreateKeyring(path, master)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	if reloaded.KeyID() != keyring.KeyID() || !bytes.Equal(reloaded.PublicKey(), keyring.PublicKey()) {
		t.Fatal("reload changed the evidence key identity")
	}
	unwrapped, err = reloaded.Unwrap(keyID, wrapped)
	if err != nil || !bytes.Equal(unwrapped, plainDEK) {
		t.Fatalf("reload cannot unwrap historical evidence: %v", err)
	}
	clear(unwrapped)
}

func TestKeyringRejectsCorruptionAndUnsafePath(t *testing.T) {
	master, err := encryption.NewWithKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKeyring("relative-key", master); err == nil {
		t.Fatal("relative private key path was accepted")
	}
	path := filepath.Join(t.TempDir(), "evidence-private.key")
	if err := os.WriteFile(path, []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKeyring(path, master); err == nil {
		t.Fatal("corrupt private key file was accepted")
	}
}

func TestKeyringIssuesSignedNodeGrant(t *testing.T) {
	master, err := encryption.NewWithKey(bytes.Repeat([]byte{11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	keyring, err := LoadOrCreateKeyring(filepath.Join(directory, "private.key"), master)
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()
	grantPath := filepath.Join(directory, "pcap-public.json")
	trustPath := filepath.Join(directory, "pcap-release.pub")
	if err := keyring.WritePublicGrant(grantPath, trustPath, "gw-signed", time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	grant, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, keyID, err := evidencekey.VerifyPublicKeyGrant(grant, trust, "gw-signed", time.Now())
	if err != nil || keyID != keyring.KeyID() || !bytes.Equal(publicKey, keyring.PublicKey()) {
		t.Fatalf("installed grant is not valid: %v", err)
	}
	if err := keyring.WritePublicGrant(grantPath, trustPath, "gw-signed", time.Now(), time.Hour); err != nil {
		t.Fatalf("signed grant renewal failed: %v", err)
	}
}

func TestKeyringRotationRetainsHistoricalEvidenceKey(t *testing.T) {
	master, err := encryption.NewWithKey(bytes.Repeat([]byte{19}, 32))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "private.key")
	keyring, err := LoadOrCreateKeyring(path, master)
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()
	oldPublic := keyring.PublicKey()
	oldKeyID := keyring.KeyID()
	oldDEK := bytes.Repeat([]byte{21}, 32)
	wrapped, _, err := evidencekey.WrapDEK(oldPublic, oldDEK)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyring.Rotate(); err != nil {
		t.Fatal(err)
	}
	if keyring.KeyID() == oldKeyID || bytes.Equal(keyring.PublicKey(), oldPublic) {
		t.Fatal("rotation did not change the evidence public key")
	}
	unwrapped, err := keyring.Unwrap(oldKeyID, wrapped)
	if err != nil || !bytes.Equal(unwrapped, oldDEK) {
		t.Fatalf("historical evidence key was lost: %v", err)
	}
	clear(unwrapped)
	reloaded, err := LoadOrCreateKeyring(path, master)
	if err != nil {
		t.Fatal(err)
	}
	defer reloaded.Close()
	unwrapped, err = reloaded.Unwrap(oldKeyID, wrapped)
	if err != nil || !bytes.Equal(unwrapped, oldDEK) {
		t.Fatalf("historical evidence key did not survive reload: %v", err)
	}
	clear(unwrapped)
	grantPath := filepath.Join(filepath.Dir(path), "public.json")
	trustPath := filepath.Join(filepath.Dir(path), "release.pub")
	if err := reloaded.WritePublicGrant(grantPath, trustPath, "gw-rotate", time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	grant, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	_, grantedID, err := evidencekey.VerifyPublicKeyGrant(grant, trust, "gw-rotate", time.Now())
	if err != nil || grantedID != reloaded.KeyID() {
		t.Fatalf("rotated grant is invalid: %v", err)
	}
	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, oldDEK) || bytes.Contains(disk, []byte("private_key\":")) {
		t.Fatal("plaintext key material appeared after rotation")
	}
}

func TestKeyringConcurrentRotateAndWritePublicGrant(t *testing.T) {
	master, err := encryption.NewWithKey(bytes.Repeat([]byte{23}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyring, err := LoadOrCreateKeyring(filepath.Join(dir, "private.key"), master)
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Close()

	grantPath := filepath.Join(dir, "pcap-public.json")
	trustPath := filepath.Join(dir, "pcap-release.pub")
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 6; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := keyring.Rotate(); err != nil {
				errs <- err
			}
		}()
		go func() {
			defer wg.Done()
			if err := keyring.WritePublicGrant(grantPath, trustPath, "gw-race", time.Now(), time.Hour); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent rotate/grant failed: %v", err)
	}
	if err := keyring.WritePublicGrant(grantPath, trustPath, "gw-race", time.Now(), time.Hour); err != nil {
		t.Fatal(err)
	}
	grant, err := os.ReadFile(grantPath)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := os.ReadFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	_, keyID, err := evidencekey.VerifyPublicKeyGrant(grant, trust, "gw-race", time.Now())
	if err != nil || keyID != keyring.KeyID() {
		t.Fatalf("final grant invalid or stale: keyID=%s want=%s err=%v", keyID, keyring.KeyID(), err)
	}
}
