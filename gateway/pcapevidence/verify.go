package pcapevidence

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// VerifyAndDecrypt 先在同一打开文件上验证密文哈希，再流式解密并核验明文哈希。
// 服务端调用方必须进一步限制根目录、文件类型和授权，不得接受用户提供的任意路径。
func VerifyAndDecrypt(path string, manifest Manifest, key []byte, output io.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open evidence: %w", err)
	}
	defer file.Close()
	return VerifyAndDecryptFile(file, manifest, key, output)
}

// VerifyAndDecryptFile 允许调用方在受控根目录安全打开文件后复用同一文件描述符。
func VerifyAndDecryptFile(file *os.File, manifest Manifest, key []byte, output io.Writer) error {
	if output == nil || file == nil {
		return fmt.Errorf("evidence input and output are required")
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	if len(key) != 32 {
		return fmt.Errorf("evidence DEK must be 32 bytes")
	}
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != manifest.SizeEncrypted {
		return fmt.Errorf("evidence file type or size does not match manifest")
	}
	cipherHash := sha256.New()
	if _, err := io.Copy(cipherHash, file); err != nil {
		return fmt.Errorf("hash encrypted evidence: %w", err)
	}
	if hexString(cipherHash.Sum(nil)) != manifest.SHA256Encrypted {
		return fmt.Errorf("encrypted evidence integrity check failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	header := make([]byte, fileHeaderSize)
	if _, err := io.ReadFull(file, header); err != nil {
		return fmt.Errorf("read evidence header: %w", err)
	}
	if string(header[:8]) != fileMagic || !bytesEqual(header[8:24], manifest.Segment.ArtifactID[:]) {
		return fmt.Errorf("evidence identity does not match manifest")
	}
	chunkSize := int(binary.BigEndian.Uint32(header[24:28]))
	if chunkSize != manifest.Encryption.ChunkSize || chunkSize <= 0 || chunkSize > MaxChunkSize {
		return fmt.Errorf("evidence chunk size does not match manifest")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	var aead cipher.AEAD
	aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}
	plainHash := sha256.New()
	var plainBytes int64
	var chunkIndex uint64
	for {
		frame := make([]byte, frameHeaderSize)
		_, readErr := io.ReadFull(file, frame)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read encrypted evidence frame: %w", readErr)
		}
		index := binary.BigEndian.Uint64(frame[0:8])
		plainLen := int(binary.BigEndian.Uint32(frame[8:12]))
		cipherLen := int(binary.BigEndian.Uint32(frame[24:28]))
		if index != chunkIndex || plainLen <= 0 || plainLen > chunkSize || cipherLen != plainLen+aead.Overhead() || chunkIndex >= manifest.Encryption.ChunkCount {
			return fmt.Errorf("invalid evidence frame order or size")
		}
		ciphertext := make([]byte, cipherLen)
		if _, err := io.ReadFull(file, ciphertext); err != nil {
			return fmt.Errorf("read encrypted evidence payload: %w", err)
		}
		aad := evidenceAAD(manifest.Segment.ArtifactID, chunkSize, index, plainLen)
		plain, err := aead.Open(nil, frame[12:24], ciphertext, aad)
		if err != nil {
			return fmt.Errorf("decrypt evidence chunk: %w", err)
		}
		_, _ = plainHash.Write(plain)
		plainBytes += int64(len(plain))
		if err := writeAll(output, plain); err != nil {
			return fmt.Errorf("write decrypted evidence: %w", err)
		}
		chunkIndex++
	}
	if chunkIndex != manifest.Encryption.ChunkCount || plainBytes != manifest.SizePlain || hexString(plainHash.Sum(nil)) != manifest.SHA256Plain {
		return fmt.Errorf("decrypted evidence integrity check failed")
	}
	return nil
}

func writeAll(output io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := output.Write(data)
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

func hexString(data []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(data)*2)
	for i, value := range data {
		out[i*2] = digits[value>>4]
		out[i*2+1] = digits[value&15]
	}
	return string(out)
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for i := range left {
		different |= left[i] ^ right[i]
	}
	return different == 0
}
