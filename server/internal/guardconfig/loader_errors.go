package guardconfig

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// Only an absent optional table is compatible with an older installation.
// Other query failures must abort candidate publication.
func isMissingLegacyTableError(err error, table string) bool {
	if err == nil || table == "" {
		return false
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "42P01" && strings.Contains(strings.ToLower(pgErr.Message), strings.ToLower(table))
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, strings.ToLower(table)) && strings.Contains(msg, "does not exist")
}

func wrapLegacyLoaderError(table string, err error) error {
	if err == nil || isMissingLegacyTableError(err, table) {
		return nil
	}
	return fmt.Errorf("list %s: %w", table, err)
}
