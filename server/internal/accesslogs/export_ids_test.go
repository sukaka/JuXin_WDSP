package accesslogs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestBuildListWhereWithIDsAndFieldPath(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()
	where, args := buildListWhere(ListFilter{
		Domain:    "shop.internal",
		IDs:       []uuid.UUID{id1, id2},
		FieldPath: "body.phone",
	})
	if !strings.Contains(where, "domain ILIKE $1") {
		t.Fatalf("unexpected where: %s", where)
	}
	if !strings.Contains(where, "id = ANY($2::uuid[])") {
		t.Fatalf("where missing id ANY clause: %s", where)
	}
	if !strings.Contains(where, "= $3") {
		t.Fatalf("FieldPath placeholder should shift to $3: %s", where)
	}
	if len(args) != 3 {
		t.Fatalf("len(args) = %d, want 3", len(args))
	}
}

func TestExportRejectsInvalidIDs(t *testing.T) {
	h := NewHandler(nil, nil)
	principal := &authz.Principal{UserID: uuid.New(), Username: "secops"}
	for _, rawQuery := range []string{"ids=", "ids=not-a-uuid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/access-logs/export?"+rawQuery, nil)
		req = req.WithContext(authz.WithPrincipal(req.Context(), principal))
		rr := httptest.NewRecorder()
		h.Export(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q: status = %d, want 400, body = %s", rawQuery, rr.Code, rr.Body.String())
		}
	}
}
