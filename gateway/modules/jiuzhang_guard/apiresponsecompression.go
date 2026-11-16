package jiuzhang_guard

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
)

const (
	apiResponseEncodingIdentity = "identity"
	apiResponseEncodingGzip     = "gzip"
	apiResponseEncodingBr       = "br"
)

var errAPIResponseDecompressedLimit = errors.New("decompressed response body exceeds capture limit")

func apiResponseContentEncoding(h http.Header) (string, bool) {
	values := h.Values("Content-Encoding")
	if len(values) == 0 {
		return apiResponseEncodingIdentity, true
	}
	if len(values) != 1 {
		return "", false
	}
	encoding := strings.ToLower(strings.TrimSpace(values[0]))
	switch encoding {
	case "", apiResponseEncodingIdentity:
		return apiResponseEncodingIdentity, true
	case apiResponseEncodingGzip, apiResponseEncodingBr:
		return encoding, true
	default:
		return "", false
	}
}

func compressedAPIResponseEncoding(encoding string) bool {
	return encoding == apiResponseEncodingGzip || encoding == apiResponseEncodingBr
}

func decodeAPIResponseBody(encoding string, raw []byte, maxBytes int) ([]byte, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if maxBytes < 0 {
		return nil, fmt.Errorf("invalid response capture limit %d", maxBytes)
	}
	var reader io.Reader
	var gzipReader *gzip.Reader
	switch encoding {
	case apiResponseEncodingGzip:
		var err error
		gzipReader, err = gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		reader = gzipReader
	case apiResponseEncodingBr:
		reader = brotli.NewReader(bytes.NewReader(raw))
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, int64(maxBytes)+1))
	var closeErr error
	if gzipReader != nil {
		closeErr = gzipReader.Close()
	}
	if readErr != nil {
		return nil, fmt.Errorf("%s decode: %w", encoding, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("%s close: %w", encoding, closeErr)
	}
	if len(decoded) > maxBytes {
		return nil, fmt.Errorf("%w: decoded %d bytes with capture limit %d", errAPIResponseDecompressedLimit, len(decoded), maxBytes)
	}
	return decoded, nil
}

func encodeAPIResponseBody(encoding string, body []byte) ([]byte, error) {
	var out bytes.Buffer
	switch encoding {
	case apiResponseEncodingGzip:
		writer := gzip.NewWriter(&out)
		if _, err := writer.Write(body); err != nil {
			_ = writer.Close()
			return nil, fmt.Errorf("gzip encode: %w", err)
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("gzip encode close: %w", err)
		}
	case apiResponseEncodingBr:
		writer := brotli.NewWriter(&out)
		if _, err := writer.Write(body); err != nil {
			_ = writer.Close()
			return nil, fmt.Errorf("br encode: %w", err)
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("br encode close: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
	return out.Bytes(), nil
}
