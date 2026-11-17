package apidataflow

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgxRuntimeFieldRows struct {
	pgx.Rows
}

func (r *pgxRuntimeFieldRows) Close() error {
	r.Rows.Close()
	return nil
}

func NewPGXRuntimeFieldReader(db *pgxpool.Pool) *PGRuntimeFieldReader {
	reader := &PGRuntimeFieldReader{}
	if db != nil {
		reader.query = func(ctx context.Context, query string, args ...any) (runtimeFieldRows, error) {
			rows, err := db.Query(ctx, query, args...)
			if err != nil {
				return nil, err
			}
			return &pgxRuntimeFieldRows{Rows: rows}, nil
		}
	}
	return reader
}
