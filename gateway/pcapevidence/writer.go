package pcapevidence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"time"
)

// SegmentWriter 以固定内存上限流式加密PCAP；Commit前只有同目录临时文件。
type SegmentWriter struct {
	file         *os.File
	tmpPath      string
	finalPath    string
	segment      Segment
	aead         cipher.AEAD
	chunkSize    int
	buffer       []byte
	bufferUsed   int
	plainHash    hash.Hash
	cipherHash   hash.Hash
	cipherOutput io.Writer
	plainBytes   int64
	cipherBytes  int64
	chunkCount   uint64
	closed       bool
	committed    bool
	manifest     Manifest
}

func NewSegmentWriter(path string, segment Segment, key []byte) (*SegmentWriter, error) {
	return newSegmentWriter(path, segment, key, DefaultChunkSize)
}

func newSegmentWriter(path string, segment Segment, key []byte, chunkSize int) (*SegmentWriter, error) {
	if chunkSize <= 0 || chunkSize > MaxChunkSize {
		return nil, fmt.Errorf("invalid evidence chunk size")
	}
	if path == "" || segment.ArtifactID.IsZero() || segment.StartedAt.IsZero() {
		return nil, fmt.Errorf("evidence path, artifact id and start time are required")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("evidence DEK must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create evidence temporary file: %w", err)
	}
	writer := &SegmentWriter{
		file: file, tmpPath: path + ".tmp", finalPath: path, segment: segment,
		aead: aead, chunkSize: chunkSize, buffer: make([]byte, chunkSize),
		plainHash: sha256.New(), cipherHash: sha256.New(),
	}
	writer.cipherOutput = io.MultiWriter(file, writer.cipherHash)
	header := evidenceHeader(segment.ArtifactID, writer.chunkSize)
	if err := writer.writeCipher(header); err != nil {
		_ = writer.Abort()
		return nil, err
	}
	return writer, nil
}

func (w *SegmentWriter) Write(data []byte) (int, error) {
	if w.closed || w.committed {
		return 0, fmt.Errorf("evidence writer is closed")
	}
	if len(data) == 0 {
		return 0, nil
	}
	_, _ = w.plainHash.Write(data)
	w.plainBytes += int64(len(data))
	consumed := 0
	for consumed < len(data) {
		available := w.chunkSize - w.bufferUsed
		if remaining := len(data) - consumed; available > remaining {
			available = remaining
		}
		n := copy(w.buffer[w.bufferUsed:w.chunkSize], data[consumed:consumed+available])
		w.bufferUsed += n
		consumed += n
		if w.bufferUsed == w.chunkSize {
			if err := w.flushChunk(); err != nil {
				return consumed, err
			}
		}
	}
	return consumed, nil
}

func (w *SegmentWriter) flushChunk() error {
	if w.bufferUsed == 0 {
		return nil
	}
	plainLen := w.bufferUsed
	nonce := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate evidence nonce: %w", err)
	}
	frame := make([]byte, frameHeaderSize)
	binary.BigEndian.PutUint64(frame[0:8], w.chunkCount)
	binary.BigEndian.PutUint32(frame[8:12], uint32(plainLen))
	copy(frame[12:24], nonce)
	binary.BigEndian.PutUint32(frame[24:28], uint32(plainLen+w.aead.Overhead()))
	aad := evidenceAAD(w.segment.ArtifactID, w.chunkSize, w.chunkCount, plainLen)
	ciphertext := w.aead.Seal(nil, nonce, w.buffer[:plainLen], aad)
	if err := w.writeCipher(frame); err != nil {
		return err
	}
	if err := w.writeCipher(ciphertext); err != nil {
		return err
	}
	w.chunkCount++
	w.bufferUsed = 0
	return nil
}

func (w *SegmentWriter) writeCipher(data []byte) error {
	written, err := w.cipherOutput.Write(data)
	w.cipherBytes += int64(written)
	if err == nil && written != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("write encrypted evidence: %w", err)
	}
	return nil
}

func (w *SegmentWriter) Commit() (Manifest, error) {
	if w.committed {
		return w.manifest, nil
	}
	if w.closed {
		return Manifest{}, fmt.Errorf("evidence writer is closed")
	}
	if err := w.flushChunk(); err != nil {
		return Manifest{}, err
	}
	if err := w.file.Sync(); err != nil {
		return Manifest{}, fmt.Errorf("sync evidence: %w", err)
	}
	if err := w.file.Close(); err != nil {
		return Manifest{}, fmt.Errorf("close evidence: %w", err)
	}
	w.file = nil
	w.closed = true
	if err := os.Link(w.tmpPath, w.finalPath); err != nil {
		return Manifest{}, fmt.Errorf("seal evidence without replacing existing data: %w", err)
	}
	w.committed = true
	if err := os.Remove(w.tmpPath); err != nil {
		return Manifest{}, fmt.Errorf("remove sealed temporary link: %w", err)
	}
	w.manifest = Manifest{
		Format: FormatName, FormatVersion: FormatVersion, Segment: w.segment, EndedAt: time.Now().UTC(),
		SizePlain: w.plainBytes, SizeEncrypted: w.cipherBytes,
		SHA256Plain:     hex.EncodeToString(w.plainHash.Sum(nil)),
		SHA256Encrypted: hex.EncodeToString(w.cipherHash.Sum(nil)),
		Encryption:      EncryptionMeta{Algorithm: EncryptionAlgorithm, ChunkSize: w.chunkSize, ChunkCount: w.chunkCount},
	}
	if err := w.manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return w.manifest, nil
}

// Abort 清理未封口临时文件；已封口证据不会被删除。
func (w *SegmentWriter) Abort() error {
	if w.committed {
		return nil
	}
	w.closed = true
	var errs []error
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			errs = append(errs, err)
		}
		w.file = nil
	}
	if err := os.Remove(w.tmpPath); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func evidenceHeader(id [16]byte, chunkSize int) []byte {
	header := make([]byte, fileHeaderSize)
	copy(header[0:8], fileMagic)
	copy(header[8:24], id[:])
	binary.BigEndian.PutUint32(header[24:28], uint32(chunkSize))
	return header
}

func evidenceAAD(id [16]byte, chunkSize int, index uint64, plainLen int) []byte {
	aad := make([]byte, 40)
	copy(aad[:28], evidenceHeader(id, chunkSize))
	binary.BigEndian.PutUint64(aad[28:36], index)
	binary.BigEndian.PutUint32(aad[36:40], uint32(plainLen))
	return aad
}
