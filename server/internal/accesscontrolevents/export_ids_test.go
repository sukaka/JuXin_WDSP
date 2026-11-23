package accesscontrolevents

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestBuildWhereWithIDs(t *testing.T) {
	id1 := uuid.New()
	where, args := buildWhere(ListFilter{
		ClientIP: "198.51.100.1",
		IDs:      []uuid.UUID{id1},
	})
	if !strings.Contains(where, "client_ip = $1") || !strings.Contains(where, "id = ANY($2::uuid[])") {
		t.Fatalf("unexpected where: %s", where)
	}
	if len(args) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(args))
	}
}

func TestExportRejectsInvalidIDs(t *testing.T) {
	h := NewHandler(nil, nil)
	principal := &authz.Principal{UserID: uuid.New(), Username: "secops"}
	for _, rawQuery := range []string{"ids=", "ids=invalid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/access-control-events/export?"+rawQuery, nil)
		req = req.WithContext(authz.WithPrincipal(req.Context(), principal))
		rr := httptest.NewRecorder()
		h.Export(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q: status = %d, want 400", rawQuery, rr.Code)
		}
	}
}
