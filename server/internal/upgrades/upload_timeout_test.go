package upgrades

import (
	"bufio"
	"bytes"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestUploadPackageUsesDedicatedDeadlineForSlowRequest(t *testing.T) {
	content, pub, _ := embeddedPackageBytes(t, "1.7.1", "1.7.2", 222)
	h, _, executor, _ := newUploadTestHandler(t, pub)
	h.SetUploadTimeout(5 * time.Second)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := &authz.Principal{UserID: uuid.New(), Username: "tester"}
		h.UploadPackage(w, r.WithContext(authz.WithPrincipal(r.Context(), principal)))
	})
	server := httptest.NewUnstartedServer(handler)
	server.Config.ReadTimeout = time.Second
	server.Config.WriteTimeout = time.Second
	server.Start()
	defer server.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "pkg-timeout.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	payload := body.Bytes()
	closing := []byte("\r\n--" + writer.Boundary() + "--\r\n")
	if !bytes.HasSuffix(payload, closing) {
		t.Fatal("multipart closing boundary not found")
	}

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	headers := "POST /api/v1/upgrades/packages/upload HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Content-Type: " + writer.FormDataContentType() + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(payload)) + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, headers); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(payload[:len(payload)-len(closing)]); err != nil {
		t.Fatal(err)
	}
	// 超过普通读写期限后才发送 multipart 结束边界；上传路由必须已扩展当前请求期限。
	time.Sleep(1500 * time.Millisecond)
	if _, err := conn.Write(closing); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("slow upload status = %d, body=%s", response.StatusCode, responseBody)
	}
	if executor.calls != 1 {
		t.Fatalf("verified slow upload did not register execution: %d", executor.calls)
	}
}

func TestUploadPackageRejectsUnsupportedDeadlineControl(t *testing.T) {
	h := NewHandler(nil, nil, nil).SetUploadDir(t.TempDir(), 1024)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/upgrades/packages/upload", strings.NewReader("not-read"))
	h.UploadPackage(recorder, request)
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("unsupported deadline control status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}
