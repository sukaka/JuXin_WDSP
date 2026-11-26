package certificates

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func makeMultipartCertRequest(t *testing.T, fields map[string]string, files map[string]struct {
	filename string
	content  []byte
}) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			t.Fatalf("write field %s: %v", k, err)
		}
	}
	for k, f := range files {
		part, err := mw.CreateFormFile(k, f.filename)
		if err != nil {
			t.Fatalf("create form file %s: %v", k, err)
		}
		if _, err := part.Write(f.content); err != nil {
			t.Fatalf("write form file %s: %v", k, err)
		}
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	ctx := authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.New(),
		Username: "secadmin",
	})
	return req.WithContext(ctx)
}

func makeDERTestCert(t *testing.T, cn string) (certDER, pkcs8KeyDER, pkcs1KeyDER []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9001),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	pkcs8KeyDER, err = x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	pkcs1KeyDER = x509.MarshalPKCS1PrivateKey(key)
	return certDER, pkcs8KeyDER, pkcs1KeyDER
}

func makeDERTestSM2Cert(t *testing.T, cn string, serial int64, usage smx509.KeyUsage) (certDER, pkcs8KeyDER []byte) {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sm2.GenerateKey: %v", err)
	}
	now := time.Now()
	tmpl := &smx509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              usage,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{cn},
	}
	certDER, err = smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("smx509.CreateCertificate: %v", err)
	}
	pkcs8KeyDER, err = smx509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("smx509.MarshalPKCS8PrivateKey: %v", err)
	}
	return certDER, pkcs8KeyDER
}

func TestHandlerUploadMultipartInternationalPEM(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, _ := makeTestCert(t, "file.example.com", []string{"file.example.com"}, now.Add(-time.Hour), now.Add(365*24*time.Hour))

	var captured UploadInput
	h := NewHandler(nil, nil)
	h.uploadFn = func(_ context.Context, in UploadInput) (*Certificate, error) {
		captured = in
		return &Certificate{
			ID:           uuid.New(),
			Name:         in.Name,
			ProtocolType: in.ProtocolType,
			CommonName:   "file.example.com",
			Status:       StatusValid,
		}, nil
	}

	// 模拟 Windows UTF-8 BOM 前缀 PEM 文件 + 证书链文件
	req := makeMultipartCertRequest(t,
		map[string]string{
			"name":          "file-cert-2026",
			"protocol_type": "INTERNATIONAL",
		},
		map[string]struct {
			filename string
			content  []byte
		}{
			"cert_file":  {filename: "file.example.com.pem", content: append(append([]byte{}, utf8BOM...), []byte(certPEM)...)},
			"key_file":   {filename: "file.example.com.key", content: append(append([]byte{}, utf8BOM...), []byte(keyPEM)...)},
			"chain_file": {filename: "chain.pem", content: []byte(certPEM)},
		},
	)
	rec := httptest.NewRecorder()
	h.Upload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if captured.Name != "file-cert-2026" || captured.ProtocolType != ProtocolInternational {
		t.Fatalf("unexpected captured meta: %+v", captured)
	}
	if captured.CertPEM != strings.TrimSpace(certPEM) || captured.KeyPEM != strings.TrimSpace(keyPEM) || captured.ChainPEM != strings.TrimSpace(certPEM) {
		t.Fatalf("PEM content mismatch after BOM trim")
	}
	// 响应不得泄露私钥
	if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
		t.Fatalf("response leaked private key")
	}
}

func TestHandlerUploadMultipartInternationalDER(t *testing.T) {
	certDER, pkcs8KeyDER, pkcs1KeyDER := makeDERTestCert(t, "der.example.com")

	for _, tc := range []struct {
		name   string
		keyDER []byte
	}{
		{name: "pkcs8_der_key", keyDER: pkcs8KeyDER},
		{name: "pkcs1_der_key", keyDER: pkcs1KeyDER},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var captured UploadInput
			h := NewHandler(nil, nil)
			h.uploadFn = func(_ context.Context, in UploadInput) (*Certificate, error) {
				captured = in
				cert, _, err := ParseCertificatePEM(in.CertPEM)
				if err != nil {
					return nil, err
				}
				if err := ValidatePrivateKeyPEM(in.KeyPEM, cert); err != nil {
					return nil, err
				}
				return &Certificate{
					ID:           uuid.New(),
					Name:         in.Name,
					ProtocolType: in.ProtocolType,
					CommonName:   "der.example.com",
					Status:       StatusValid,
				}, nil
			}

			req := makeMultipartCertRequest(t,
				map[string]string{"name": "der-cert"},
				map[string]struct {
					filename string
					content  []byte
				}{
					"cert_file": {filename: "der.cer", content: certDER},
					"key_file":  {filename: "der.key", content: tc.keyDER},
				},
			)
			rec := httptest.NewRecorder()
			h.Upload(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(captured.CertPEM, "-----BEGIN CERTIFICATE-----") {
				t.Fatalf("DER cert was not converted to PEM: %q", captured.CertPEM)
			}
			if !strings.Contains(captured.KeyPEM, "PRIVATE KEY-----") {
				t.Fatalf("DER key was not converted to PEM: %q", captured.KeyPEM)
			}
		})
	}
}

func TestHandlerUploadMultipartGMDualCertPEMAndDER(t *testing.T) {
	signCertDER, signKeyDER := makeDERTestSM2Cert(t, "gm.example.com", 4001, smx509.KeyUsageDigitalSignature)
	encCertDER, encKeyDER := makeDERTestSM2Cert(t, "gm.example.com", 4002, smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment)

	h := NewHandler(nil, nil)
	h.uploadFn = func(_ context.Context, in UploadInput) (*Certificate, error) {
		dual, err := ParseAndValidateGMDualCert(in.CertPEM, in.KeyPEM, in.EncCertPEM, in.EncKeyPEM, in.ChainPEM, time.Now())
		if err != nil {
			return nil, err
		}
		return &Certificate{
			ID:           uuid.New(),
			Name:         in.Name,
			ProtocolType: in.ProtocolType,
			CommonName:   dual.SignParsed.CommonName,
			Status:       StatusValid,
		}, nil
	}

	req := makeMultipartCertRequest(t,
		map[string]string{
			"name":          "gm-file-cert",
			"protocol_type": "SM_TLCP",
		},
		map[string]struct {
			filename string
			content  []byte
		}{
			"cert_file":     {filename: "sign.cer", content: signCertDER},
			"key_file":      {filename: "sign.key", content: signKeyDER},
			"enc_cert_file": {filename: "enc.cer", content: encCertDER},
			"enc_key_file":  {filename: "enc.key", content: encKeyDER},
			"chain_file":    {filename: "ca.cer", content: signCertDER},
		},
	)
	rec := httptest.NewRecorder()
	h.Upload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GM multipart upload status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestHandlerUploadMultipartValidationErrors(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, _ := makeTestCert(t, "err.example.com", []string{"err.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
	encryptedKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("dummy")}))

	h := NewHandler(nil, nil)
	h.uploadFn = func(_ context.Context, in UploadInput) (*Certificate, error) {
		if in.Name == "dup-name" {
			return nil, ErrNameExists
		}
		return &Certificate{ID: uuid.New(), Name: in.Name, ProtocolType: in.ProtocolType}, nil
	}

	cases := []struct {
		name       string
		fields     map[string]string
		files      map[string]struct {
			filename string
			content  []byte
		}
		wantStatus int
		wantSubstr string
	}{
		{
			name:   "missing_cert_file",
			fields: map[string]string{"name": "no-cert"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"key_file": {filename: "a.key", content: []byte(keyPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "请上传证书文件",
		},
		{
			name:   "missing_key_file",
			fields: map[string]string{"name": "no-key"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "a.pem", content: []byte(certPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "请上传私钥文件",
		},
		{
			name:   "gm_missing_enc_cert",
			fields: map[string]string{"name": "gm-incomplete", "protocol_type": "SM_TLCP"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "sign.pem", content: []byte(certPEM)},
				"key_file":  {filename: "sign.key", content: []byte(keyPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "请上传加密证书文件",
		},
		{
			name:   "empty_cert_file",
			fields: map[string]string{"name": "empty"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "empty.pem", content: nil},
				"key_file":  {filename: "a.key", content: []byte(keyPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "不能为空",
		},
		{
			name:   "oversized_cert_file",
			fields: map[string]string{"name": "too-big"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "big.pem", content: bytes.Repeat([]byte("A"), maxCertFileBytes+1)},
				"key_file":  {filename: "a.key", content: []byte(keyPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "超过 64KB 限制",
		},
		{
			name:   "swapped_key_into_cert_slot",
			fields: map[string]string{"name": "swapped-1"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "wrong.key", content: []byte(keyPEM)},
				"key_file":  {filename: "a.key", content: []byte(keyPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "检测到私钥内容",
		},
		{
			name:   "swapped_cert_into_key_slot",
			fields: map[string]string{"name": "swapped-2"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "a.pem", content: []byte(certPEM)},
				"key_file":  {filename: "wrong.pem", content: []byte(certPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "检测到证书内容",
		},
		{
			name:   "encrypted_private_key",
			fields: map[string]string{"name": "enc-key"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "a.pem", content: []byte(certPEM)},
				"key_file":  {filename: "enc.key", content: []byte(encryptedKeyPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "口令加密",
		},
		{
			name:   "garbage_binary_cert",
			fields: map[string]string{"name": "garbage"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "bad.der", content: []byte{0x01, 0x02, 0x03, 0x04}},
				"key_file":  {filename: "a.key", content: []byte(keyPEM)},
			},
			wantStatus: http.StatusBadRequest,
			wantSubstr: "格式无效",
		},
		{
			name:   "duplicate_name_conflict",
			fields: map[string]string{"name": "dup-name"},
			files: map[string]struct {
				filename string
				content  []byte
			}{
				"cert_file": {filename: "a.pem", content: []byte(certPEM)},
				"key_file":  {filename: "a.key", content: []byte(keyPEM)},
			},
			wantStatus: http.StatusConflict,
			wantSubstr: "证书名称已存在",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := makeMultipartCertRequest(t, tc.fields, tc.files)
			rec := httptest.NewRecorder()
			h.Upload(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.wantSubstr) {
				t.Fatalf("body %q does not contain %q", rec.Body.String(), tc.wantSubstr)
			}
		})
	}
}

func TestHandlerUploadJSONBackwardCompatible(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, _ := makeTestCert(t, "json.example.com", []string{"json.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))

	var captured UploadInput
	h := NewHandler(nil, nil)
	h.uploadFn = func(_ context.Context, in UploadInput) (*Certificate, error) {
		captured = in
		return &Certificate{ID: uuid.New(), Name: in.Name, ProtocolType: ProtocolInternational}, nil
	}

	payload, _ := json.Marshal(map[string]string{
		"name":     "json-cert",
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certificates", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.New(),
		Username: "secadmin",
	}))
	rec := httptest.NewRecorder()
	h.Upload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if captured.Name != "json-cert" || captured.CertPEM != certPEM || captured.KeyPEM != keyPEM {
		t.Fatalf("unexpected captured JSON input: %+v", captured)
	}
}
