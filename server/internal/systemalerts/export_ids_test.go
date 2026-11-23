package systemalerts

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestBuildListWhereAndExportLimit(t *testing.T) {
	id1 := uuid.New()
	where, args := buildListWhere(ListFilter{
		Severity: "HIGH",
		IDs:      []uuid.UUID{id1},
	})
	if !strings.Contains(where, "severity = $1") || !strings.Contains(where, "id = ANY($2::uuid[])") {
		t.Fatalf("unexpected where: %s", where)
	}
	if len(args) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(args))
	}
	if _, ps := normalizePage(1, exportLimit, exportLimit); ps != exportLimit {
		t.Fatalf("export pageSize = %d, want %d", ps, exportLimit)
	}
	if _, ps := normalizePage(1, exportLimit, 1000); ps != 20 {
		t.Fatalf("list pageSize = %d, want 20", ps)
	}
}

func TestExportRejectsInvalidIDs(t *testing.T) {
	h := NewHandler(nil, nil)
	principal := &authz.Principal{UserID: uuid.New(), Username: "sysadmin"}
	for _, rawQuery := range []string{"ids=", "ids=bad-uuid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/system-alerts/export?"+rawQuery, nil)
		req = req.WithContext(authz.WithPrincipal(req.Context(), principal))
		rr := httptest.NewRecorder()
		h.Export(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q: status = %d, want 400", rawQuery, rr.Code)
		}
	}
}
