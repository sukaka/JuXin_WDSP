package pcapevidence

import (
	"bytes"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

func TestEncryptedPCAPSegmentRoundTrip(t *testing.T) {
	plain := testPCAP(t, 32)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "evidence.wpcap")
	writer, err := newSegmentWriter(path, Segment{
		ArtifactID: testArtifactID(t), NodeID: "gw-1", CapturePoint: "GATEWAY_INGRESS",
		StartedAt: time.Now().UTC().Add(-time.Second), PacketCount: 32,
	}, key, 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Abort()
	if _, err := writer.Write(plain); err != nil {
		t.Fatal(err)
	}
	manifest, err := writer.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SizePlain != int64(len(plain)) || manifest.SizeEncrypted <= manifest.SizePlain || manifest.Encryption.ChunkCount < 2 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("sensitive-test-marker")) || bytes.Contains(ciphertext, plain[:24]) {
		t.Fatal("encrypted segment contains plaintext PCAP data")
	}
	var decrypted bytes.Buffer
	if err := VerifyAndDecrypt(path, manifest, key, &decrypted); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted.Bytes(), plain) {
		t.Fatal("decrypted PCAP differs from original")
	}
	reader, err := pcapgo.NewReader(bytes.NewReader(decrypted.Bytes()))
	if err != nil {
		t.Fatalf("decrypted output is not a valid classic PCAP: %v", err)
	}
	packet, _, err := reader.ReadPacketData()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(packet, []byte("sensitive-test-marker")) {
		t.Fatal("PCAP packet payload was not preserved")
	}
}

func TestEncryptedPCAPSegmentRejectsTamperingAndWrongKey(t *testing.T) {
	plain := testPCAP(t, 2)
	key := bytes.Repeat([]byte{1}, 32)
	path := filepath.Join(t.TempDir(), "evidence.wpcap")
	writer, err := NewSegmentWriter(path, Segment{ArtifactID: testArtifactID(t), StartedAt: time.Now().UTC(), PacketCount: 2}, key)
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

	t.Run("wrong key", func(t *testing.T) {
		var output bytes.Buffer
		if err := VerifyAndDecrypt(path, manifest, bytes.Repeat([]byte{2}, 32), &output); err == nil {
			t.Fatal("wrong key unexpectedly decrypted evidence")
		}
	})
	t.Run("ciphertext changed", func(t *testing.T) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[len(data)-1] ^= 1
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := VerifyAndDecrypt(path, manifest, key, &output); err == nil {
			t.Fatal("tampered evidence unexpectedly passed verification")
		}
		if output.Len() != 0 {
			t.Fatal("unverified plaintext was written before ciphertext verification")
		}
	})
	t.Run("truncated", func(t *testing.T) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data[:len(data)-3], 0o600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyAndDecrypt(path, manifest, key, &bytes.Buffer{}); err == nil {
			t.Fatal("truncated evidence unexpectedly passed verification")
		}
	})
}

func TestSegmentWriterRejectsInvalidKeyAndAbortCleansTemporaryFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.wpcap")
	if _, err := NewSegmentWriter(path, Segment{ArtifactID: testArtifactID(t), StartedAt: time.Now().UTC()}, []byte{1}); err == nil {
		t.Fatal("short key unexpectedly accepted")
	}
	writer, err := NewSegmentWriter(path, Segment{ArtifactID: testArtifactID(t), StartedAt: time.Now().UTC()}, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("partial")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("abort left a final evidence file: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("abort left a temporary evidence file: %v", err)
	}
}

func testPCAP(t *testing.T, packets int) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := pcapgo.NewWriter(&buffer)
	if err := writer.WriteFileHeader(65535, 1); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < packets; i++ {
		data := bytes.Repeat([]byte("sensitive-test-marker-"), 4)
		info := gopacket.CaptureInfo{
			Timestamp:     time.Unix(1_700_000_000, int64(i)).UTC(),
			CaptureLength: len(data), Length: len(data),
		}
		if err := writer.WritePacket(info, data); err != nil {
			t.Fatal(err)
		}
	}
	return buffer.Bytes()
}

func testArtifactID(t *testing.T) ArtifactID {
	t.Helper()
	id, err := NewArtifactID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
