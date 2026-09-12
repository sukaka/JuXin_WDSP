// handler_test.go gRPC 描述符集 CRUD 单测（fake 仓储 + spy 审计，不依赖数据库）：
// 上传（multipart、缺省名推导、大小/名称/线格式护栏、同名 409）、列表、删除（404）、
// 写操作审计（对象类型/动作/结果）。
package apigrpcdesc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// fakeRepo 内存仓储（接口路径 fake；pgx 路径由集成测试覆盖）。
type fakeRepo struct {
	items     map[string]*Descriptor
	createErr error
	deleteErr error
}

func newFakeRepo() *fakeRepo { return &fakeRepo{items: map[string]*Descriptor{}} }

func (f *fakeRepo) Create(_ context.Context, name string, content []byte, createdBy string) (*Descriptor, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	if _, dup := f.items[name]; dup {
		return nil, ErrDuplicateName
	}
	services, err := ParseFileDescriptorSet(content)
	if err != nil {
		return nil, err
	}
	d := &Descriptor{ID: uuid.New(), Name: name, SizeBytes: len(content),
		Services: services, Status: "ENABLED", CreatedBy: createdBy}
	f.items[name] = d
	return d, nil
}

func (f *fakeRepo) List(_ context.Context) ([]Descriptor, error) {
	out := []Descriptor{}
	for _, d := range f.items {
		out = append(out, *d)
	}
	return out, nil
}

func (f *fakeRepo) Delete(_ context.Context, id uuid.UUID) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for k, d := range f.items {
		if d.ID == id {
			delete(f.items, k)
			return nil
		}
	}
	return ErrNotFound
}

type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

// testDescriptorSet 合法的最小描述符集（服务 pkg.Echo / 方法 Ping）。
func testDescriptorSet() []byte {
	return fileDescriptorSet(fileProto("pkg",
		serviceProto("Echo", methodProto("Ping", ".pkg.PingReq", ".pkg.PingResp", false, false))))
}

func withTester(r *http.Request) *http.Request {
	p := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	return r.WithContext(authz.WithPrincipal(r.Context(), p))
}

func newUploadRequest(t *testing.T, name, filename string, content []byte) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if name != "" {
		if err := mw.WriteField("name", name); err != nil {
			t.Fatal(err)
		}
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-security/grpc-descriptors", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return withTester(req)
}

func TestHandlerUpload(t *testing.T) {
	repo := newFakeRepo()
	spy := &spyAudits{}
	h := &Handler{repo: repo, audits: spy}

	// 显式名称上传成功：201 + 摘要解析 + 审计 create
	w := httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "orders-desc", "orders.pb", testDescriptorSet()))
	if w.Code != http.StatusCreated {
		t.Fatalf("upload status = %d, body %s", w.Code, w.Body.String())
	}
	var env struct {
		Data Descriptor `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	d := env.Data
	if d.Name != "orders-desc" || d.Status != "ENABLED" || d.CreatedBy != "tester" {
		t.Fatalf("descriptor = %+v", d)
	}
	if len(d.Services) != 1 || d.Services[0].Service != "pkg.Echo" || len(d.Services[0].Methods) != 1 {
		t.Fatalf("services summary = %+v", d.Services)
	}
	if len(spy.entries) != 1 || spy.entries[0].Action != "create" ||
		spy.entries[0].ObjectType != "api_grpc_descriptor" || spy.entries[0].Result != audits.ResultSuccess {
		t.Fatalf("audit entries = %+v", spy.entries)
	}

	// 同名冲突：409
	w = httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "orders-desc", "orders.pb", testDescriptorSet()))
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want 409", w.Code)
	}

	// 缺省名推导（文件名去 .pb 后缀）
	w = httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "", "echo.pb", testDescriptorSet()))
	if w.Code != http.StatusCreated {
		t.Fatalf("default-name upload status = %d, body %s", w.Code, w.Body.String())
	}
	if repo.items["echo"] == nil {
		t.Fatalf("default name not derived: %+v", repo.items)
	}
}

func TestHandlerUploadGuards(t *testing.T) {
	repo := newFakeRepo()
	h := &Handler{repo: repo}

	// 线格式非法：400（错误包装 ErrBadDescriptorSet）
	w := httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "bad", "bad.pb", []byte{0x80}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad wire status = %d, want 400", w.Code)
	}
	// 名称为空且文件名推导为空：400
	w = httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "", "", testDescriptorSet()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty name status = %d, want 400", w.Code)
	}
	// 名称非法字符：400
	w = httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "bad\x00name", "x.pb", testDescriptorSet()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad name status = %d, want 400", w.Code)
	}
	// 空文件：400
	w = httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "empty", "x.pb", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty file status = %d, want 400", w.Code)
	}
	// 超 1MiB：400
	w = httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "big", "x.pb", make([]byte, MaxContentBytes+1)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized status = %d, want 400", w.Code)
	}
	// 仓储内部错误：500
	repo.createErr = errors.New("db down")
	w = httptest.NewRecorder()
	h.Upload(w, newUploadRequest(t, "x", "x.pb", testDescriptorSet()))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("internal error status = %d, want 500", w.Code)
	}
}

func TestHandlerListAndDelete(t *testing.T) {
	repo := newFakeRepo()
	spy := &spyAudits{}
	h := &Handler{repo: repo, audits: spy}
	if _, err := repo.Create(context.Background(), "a", testDescriptorSet(), "tester"); err != nil {
		t.Fatal(err)
	}

	// 列表：200 + items
	req := withTester(httptest.NewRequest(http.MethodGet, "/api/v1/api-security/grpc-descriptors", nil))
	w := httptest.NewRecorder()
	h.List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d", w.Code)
	}
	var env struct {
		Data struct {
			Items []Descriptor `json:"items"`
			Total int          `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	body := env.Data
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0].Name != "a" {
		t.Fatalf("list body = %+v", body)
	}

	// 删除不存在：404
	req = withTester(httptest.NewRequest(http.MethodDelete, "/api/v1/api-security/grpc-descriptors/"+uuid.NewString(), nil))
	req.SetPathValue("id", uuid.NewString())
	w = httptest.NewRecorder()
	h.Delete(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("delete missing status = %d, want 404", w.Code)
	}

	// 删除成功：200 + 审计 delete
	id := repo.items["a"].ID
	req = withTester(httptest.NewRequest(http.MethodDelete, "/api/v1/api-security/grpc-descriptors/"+id.String(), nil))
	req.SetPathValue("id", id.String())
	w = httptest.NewRecorder()
	h.Delete(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d", w.Code)
	}
	if len(repo.items) != 0 {
		t.Fatal("item not deleted")
	}
	if len(spy.entries) != 1 || spy.entries[0].Action != "delete" ||
		spy.entries[0].ObjectType != "api_grpc_descriptor" {
		t.Fatalf("audit entries = %+v", spy.entries)
	}

	// id 非法：400
	req = withTester(httptest.NewRequest(http.MethodDelete, "/api/v1/api-security/grpc-descriptors/not-a-uuid", nil))
	req.SetPathValue("id", "not-a-uuid")
	w = httptest.NewRecorder()
	h.Delete(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad id status = %d, want 400", w.Code)
	}
}
