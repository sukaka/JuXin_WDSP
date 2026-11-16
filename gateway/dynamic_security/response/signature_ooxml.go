package response

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

const (
	maxOOXMLSignatureBytes      = 32 << 20
	maxOOXMLSignatureTokenBytes = 512
	maxZipCommentBytes          = 1<<16 - 1
	ooxmlSignatureHeaderBytes   = 13
)

// 注释封装为 magic + 原注释长度 + token 长度 + Base64(原注释) + token。
// 仅修改 EOCD 注释长度和注释，不重写 ZIP 条目；普通 EOCD 之外的 ZIP64 布局不支持。
var ooxmlSignatureCommentMagic = []byte("JZSIGZ1")

func applyOOXMLFileSignature(body []byte, token string) ([]byte, string, bool, error) {
	_, existingToken, signed, err := RecoverOOXMLSignedContent(body)
	if err != nil {
		return body, "", false, err
	}
	if signed {
		return body, existingToken, false, nil
	}
	if len(token) == 0 || len(token) > maxOOXMLSignatureTokenBytes || !strings.HasPrefix(token, FileSignatureTokenPrefix+".") {
		return body, "", false, fmt.Errorf("invalid ooxml signature token")
	}
	offset, err := inspectOOXMLSignaturePackage(body)
	if err != nil {
		return body, "", false, err
	}
	originalComment := body[offset+22:]
	encodedComment := base64.StdEncoding.EncodeToString(originalComment)
	if len(encodedComment)+ooxmlSignatureHeaderBytes+len(token) > maxZipCommentBytes {
		return body, "", false, fmt.Errorf("ooxml zip comment exceeds %d bytes", maxZipCommentBytes)
	}
	comment := make([]byte, 0, ooxmlSignatureHeaderBytes+len(encodedComment)+len(token))
	comment = append(comment, ooxmlSignatureCommentMagic...)
	var size [4]byte
	binary.LittleEndian.PutUint32(size[:], uint32(len(originalComment)))
	comment = append(comment, size[:]...)
	binary.LittleEndian.PutUint16(size[:2], uint16(len(token)))
	comment = append(comment, size[:2]...)
	comment = append(comment, encodedComment...)
	comment = append(comment, token...)
	out := make([]byte, 0, len(body)+ooxmlSignatureHeaderBytes+len(encodedComment)+len(token)-len(originalComment))
	out = append(out, body[:offset+22]...)
	binary.LittleEndian.PutUint16(out[offset+20:offset+22], uint16(len(comment)))
	out = append(out, comment...)
	return out, token, true, nil
}

// RecoverOOXMLSignedContent restores the exact bytes covered by an OOXML ZIP
// comment signature. It does not validate the token's HMAC or expiration.
func RecoverOOXMLSignedContent(body []byte) ([]byte, string, bool, error) {
	offset, err := inspectOOXMLSignaturePackage(body)
	if err != nil {
		return body, "", false, err
	}
	comment := body[offset+22:]
	if !bytes.HasPrefix(comment, ooxmlSignatureCommentMagic) {
		return body, "", false, nil
	}
	if len(comment) < ooxmlSignatureHeaderBytes {
		return body, "", false, fmt.Errorf("invalid ooxml signature comment header")
	}
	originalCommentLen := int(binary.LittleEndian.Uint32(comment[7:11]))
	tokenLen := int(binary.LittleEndian.Uint16(comment[11:13]))
	if originalCommentLen > maxZipCommentBytes || tokenLen == 0 || tokenLen > maxOOXMLSignatureTokenBytes || tokenLen > len(comment)-ooxmlSignatureHeaderBytes {
		return body, "", false, fmt.Errorf("invalid ooxml signature comment lengths")
	}
	encodedLen := len(comment) - ooxmlSignatureHeaderBytes - tokenLen
	originalComment, err := base64.StdEncoding.DecodeString(string(comment[ooxmlSignatureHeaderBytes : ooxmlSignatureHeaderBytes+encodedLen]))
	if err != nil || len(originalComment) != originalCommentLen {
		return body, "", false, fmt.Errorf("invalid ooxml signature original comment encoding")
	}
	original := make([]byte, offset+22+originalCommentLen)
	copy(original, body[:offset+22])
	binary.LittleEndian.PutUint16(original[offset+20:offset+22], uint16(originalCommentLen))
	copy(original[offset+22:], originalComment)
	if _, err := zip.NewReader(bytes.NewReader(original), int64(len(original))); err != nil {
		return body, "", false, fmt.Errorf("recover original ooxml package: %w", err)
	}
	token := string(comment[ooxmlSignatureHeaderBytes+encodedLen:])
	return original, token, true, nil
}

func inspectOOXMLSignaturePackage(body []byte) (int, error) {
	if len(body) == 0 || len(body) > maxOOXMLSignatureBytes {
		return 0, fmt.Errorf("ooxml package size exceeds %d bytes", maxOOXMLSignatureBytes)
	}
	reader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return 0, fmt.Errorf("read ooxml zip package: %w", err)
	}
	hasContentTypes, hasRels := false, false
	for _, entry := range reader.File {
		if entry.Name == ooxmlEncryptedPackagePart || entry.Flags&0x1 != 0 {
			return 0, fmt.Errorf("ooxml package is encrypted")
		}
		switch entry.Name {
		case ooxmlContentTypesPart:
			hasContentTypes = true
		case ooxmlRelsPart:
			hasRels = true
		}
	}
	if !hasContentTypes || !hasRels {
		return 0, fmt.Errorf("ooxml package missing required registration parts")
	}
	return findOOXMLSignatureEOCD(body)
}

func findOOXMLSignatureEOCD(body []byte) (int, error) {
	if len(body) < 22 {
		return 0, fmt.Errorf("ooxml zip end record not found")
	}
	start := len(body) - 22 - maxZipCommentBytes
	if start < 0 {
		start = 0
	}
	for offset := len(body) - 22; offset >= start; offset-- {
		if binary.LittleEndian.Uint32(body[offset:offset+4]) != 0x06054b50 {
			continue
		}
		commentLen := int(binary.LittleEndian.Uint16(body[offset+20 : offset+22]))
		if offset+22+commentLen != len(body) {
			continue
		}
		if isZip64OOXMLRecord(body, offset) {
			continue
		}
		centralSize := uint64(binary.LittleEndian.Uint32(body[offset+12 : offset+16]))
		centralOffset := uint64(binary.LittleEndian.Uint32(body[offset+16 : offset+20]))
		if centralOffset+centralSize == uint64(offset) {
			return offset, nil
		}
	}
	return 0, fmt.Errorf("ooxml zip end record not found or unsupported ZIP64 layout")
}

func isZip64OOXMLRecord(body []byte, offset int) bool {
	if binary.LittleEndian.Uint16(body[offset+4:offset+6]) >= 45 || binary.LittleEndian.Uint16(body[offset+6:offset+8]) >= 45 ||
		binary.LittleEndian.Uint16(body[offset+8:offset+10]) == 0xffff || binary.LittleEndian.Uint16(body[offset+10:offset+12]) == 0xffff ||
		binary.LittleEndian.Uint32(body[offset+12:offset+16]) == 0xffffffff || binary.LittleEndian.Uint32(body[offset+16:offset+20]) == 0xffffffff {
		return true
	}
	return offset >= 20 && binary.LittleEndian.Uint32(body[offset-20:offset-16]) == 0x07064b50
}
