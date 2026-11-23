package loginlogs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestBuildListWhereExportLimitAndCSVEscape(t *testing.T) {
	id1 := uuid.New()
	where, args := buildListWhere(ListFilter{
		Username: "admin",
		IDs:      []uuid.UUID{id1},
	})
	if !strings.Contains(where, "username ILIKE $1") || !strings.Contains(where, "id = ANY($2::uuid[])") {
		t.Fatalf("unexpected where: %s", where)
	}
	if len(args) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(args))
	}
	if _, ps := normalizePage(1, 10000, 10000); ps != 10000 {
		t.Fatalf("export pageSize = %d, want 10000", ps)
	}
	if _, ps := normalizePage(1, 10000, 100); ps != 20 {
		t.Fatalf("list pageSize = %d, want 20", ps)
	}
	if got := csvEscape("=CMD()"); got != "'=CMD()" {
		t.Fatalf("csvEscape formula = %q, want '=CMD()", got)
	}
	if got := csvEscape("+1,2"); got != "\"'+1,2\"" {
		t.Fatalf("csvEscape formula+comma = %q", got)
	}
}

func TestExportRejectsInvalidIDs(t *testing.T) {
	h := NewHandler(nil)
	for _, rawQuery := range []string{"ids=", "ids=not-a-uuid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/login-logs/export?"+rawQuery, nil)
		rr := httptest.NewRecorder()
		h.Export(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q: status = %d, want 400", rawQuery, rr.Code)
		}
	}
}
