package detectors

import (
	"archive/zip"
	"bytes"
	"io"
)

func openOOXMLPackage(body []byte) (*zip.Reader, string) {
	if len(body) > maxOOXMLPackageBytes {
		return nil, "OOXML_TOO_LARGE"
	}
	pkg, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, "INVALID_OOXML"
	}
	if len(pkg.File) > maxOOXMLParts {
		return nil, "OOXML_TOO_MANY_PARTS"
	}
	for _, entry := range pkg.File {
		if entry.Name == "EncryptedPackage" || entry.Flags&0x1 != 0 {
			return nil, "ENCRYPTED_OOXML"
		}
	}
	return pkg, ""
}

func findOOXMLPart(pkg *zip.Reader, name string) *zip.File {
	for _, entry := range pkg.File {
		if entry.Name == name {
			return entry
		}
	}
	return nil
}

func readOOXMLPart(pkg *zip.Reader, entry *zip.File) ([]byte, string) {
	if entry == nil {
		return nil, "OOXML_DOCUMENT_MISSING"
	}
	if entry.UncompressedSize64 > maxOOXMLDocumentBytes {
		return nil, "OOXML_DOCUMENT_TOO_LARGE"
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, "INVALID_OOXML"
	}
	content, readErr := io.ReadAll(io.LimitReader(reader, maxOOXMLDocumentBytes+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		return nil, "INVALID_OOXML"
	}
	if len(content) > maxOOXMLDocumentBytes {
		return nil, "OOXML_DOCUMENT_TOO_LARGE"
	}
	return content, ""
}
