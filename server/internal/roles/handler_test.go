package roles

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeRows struct {
	pgx.Rows
	data [][]any
	idx  int
	err  error
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return r.err }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Next() bool {
	if r.idx >= len(r.data) {
		return false
	}
	r.idx++
	return true
}
func (r *fakeRows) Scan(dest ...any) error {
	row := r.data[r.idx-1]
	for i := range dest {
		switch d := dest[i].(type) {
		case *uuid.UUID:
			*d = row[i].(uuid.UUID)
		case *string:
			*d = row[i].(string)
		case *bool:
			*d = row[i].(bool)
		}
	}
	return nil
}
func (r *fakeRows) Values() ([]any, error) { return nil, nil }
func (r *fakeRows) RawValues() [][]byte    { return nil }
func (r *fakeRows) Conn() *pgx.Conn        { return nil }

type fakeRow struct {
	scanFn func(dest ...any) error
}

func (r fakeRow) Scan(dest ...any) error {
	return r.scanFn(dest...)
}

type fakeDB struct {
	queryFn    func(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	queryRowFn func(ctx context.Context, sql string, args ...any) pgx.Row
}

func (f *fakeDB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return f.queryFn(ctx, sql, args...)
}

func (f *fakeDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return f.queryRowFn(ctx, sql, args...)
}

func TestRolesHandlersEmptySlicesSerializeAsJSONArray(t *testing.T) {
	roleID := uuid.New()
	db := &fakeDB{
		queryFn: func(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
			return &fakeRows{data: nil}, nil
		},
		queryRowFn: func(_ context.Context, sql string, _ ...any) pgx.Row {
			return fakeRow{scanFn: func(dest ...any) error {
				if strings.Contains(sql, "FROM roles") {
					*(dest[0].(*uuid.UUID)) = roleID
					*(dest[1].(*string)) = "SECURITY_ADMIN"
					*(dest[2].(*string)) = "安全管理员"
					*(dest[3].(*string)) = "desc"
					*(dest[4].(*bool)) = true
					return nil
				}
				*(dest[0].(*int)) = 0
				return nil
			}}
		},
	}
	h := &Handler{db: db}

	// 1. ListRoles empty -> {"items":[]}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	rec := httptest.NewRecorder()
	h.ListRoles(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListRoles status = %d, want 200", rec.Code)
	}
	var listResp struct {
		Data struct {
			Items []Role `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal ListRoles: %v", err)
	}
	if listResp.Data.Items == nil || len(listResp.Data.Items) != 0 {
		t.Fatalf("ListRoles items = %#v, want non-nil empty slice", listResp.Data.Items)
	}
	if strings.Contains(rec.Body.String(), `"items":null`) {
		t.Fatalf("ListRoles serialized items as null: %s", rec.Body.String())
	}

	// 2. GetRole empty permissions -> {"permissions":[]}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/roles/"+roleID.String(), nil)
	req.SetPathValue("id", roleID.String())
	rec = httptest.NewRecorder()
	h.GetRole(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetRole status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"permissions":null`) {
		t.Fatalf("GetRole serialized permissions as null: %s", rec.Body.String())
	}

	// 3. RolePermissions empty -> {"items":[]}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/roles/"+roleID.String()+"/permissions", nil)
	req.SetPathValue("id", roleID.String())
	rec = httptest.NewRecorder()
	h.RolePermissions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("RolePermissions status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"items":null`) {
		t.Fatalf("RolePermissions serialized items as null: %s", rec.Body.String())
	}

	// 4. ListPermissions empty -> {"items":[]}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/permissions", nil)
	rec = httptest.NewRecorder()
	h.ListPermissions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListPermissions status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), `"items":null`) {
		t.Fatalf("ListPermissions serialized items as null: %s", rec.Body.String())
	}
}

func TestRolesHandlersPopulatedData(t *testing.T) {
	roleID := uuid.New()
	permID := uuid.New()
	db := &fakeDB{
		queryFn: func(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
			if strings.Contains(sql, "FROM roles") {
				return &fakeRows{data: [][]any{
					{roleID, "SYSTEM_ADMIN", "系统管理员", "系统管理", true},
				}}, nil
			}
			return &fakeRows{data: [][]any{
				{permID, "users.read", "查看用户", "users", "读取用户列表"},
			}}, nil
		},
	}
	h := &Handler{db: db}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
	rec := httptest.NewRecorder()
	h.ListRoles(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListRoles status = %d, want 200", rec.Code)
	}
	var resp struct {
		Data struct {
			Items []Role `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Data.Items) != 1 || resp.Data.Items[0].Code != "SYSTEM_ADMIN" {
		t.Fatalf("unexpected roles: %+v", resp.Data.Items)
	}
}
