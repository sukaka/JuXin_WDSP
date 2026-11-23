package audits

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBuildListWhereAndExportPageLimit(t *testing.T) {
	id1 := uuid.New()
	where, args := buildListWhere(ListFilter{
		Username: "auditor",
		IDs:      []uuid.UUID{id1},
	})
	if !strings.Contains(where, "username ILIKE $1") || !strings.Contains(where, "id = ANY($2::uuid[])") {
		t.Fatalf("unexpected where: %s", where)
	}
	if len(args) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(args))
	}
	// 导出上限 10000 不得被截回默认 20
	if _, ps := normalizePage(1, 10000, 10000); ps != 10000 {
		t.Fatalf("export pageSize = %d, want 10000", ps)
	}
	// 列表单页上限仍保持 100
	if _, ps := normalizePage(1, 10000, 100); ps != 20 {
		t.Fatalf("list pageSize = %d, want 20", ps)
	}
}

func TestExportRejectsInvalidIDs(t *testing.T) {
	h := NewHandler(nil)
	for _, rawQuery := range []string{"ids=", "ids=not-a-uuid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/audits/export?"+rawQuery, nil)
		rr := httptest.NewRecorder()
		h.Export(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q: status = %d, want 400", rawQuery, rr.Code)
		}
	}
}
