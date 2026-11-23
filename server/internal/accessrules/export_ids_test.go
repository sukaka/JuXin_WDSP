package accessrules

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestBuildListWhereWithIDs(t *testing.T) {
	id1 := uuid.New()
	where, args := buildListWhere(ListFilter{
		RuleType: "DENY",
		IDs:      []uuid.UUID{id1},
	})
	if !strings.Contains(where, "deleted_at IS NULL") ||
		!strings.Contains(where, "rule_type = $1") ||
		!strings.Contains(where, "id = ANY($2::uuid[])") {
		t.Fatalf("unexpected where: %s", where)
	}
	if len(args) != 2 {
		t.Fatalf("len(args) = %d, want 2", len(args))
	}
}

func TestExportRejectsInvalidIDs(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	principal := &authz.Principal{UserID: uuid.New(), Username: "secops"}
	for _, rawQuery := range []string{"ids=", "ids=not-a-uuid"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/access-rules/export?"+rawQuery, nil)
		req = req.WithContext(authz.WithPrincipal(req.Context(), principal))
		rr := httptest.NewRecorder()
		h.Export(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("query %q: status = %d, want 400", rawQuery, rr.Code)
		}
	}
}
