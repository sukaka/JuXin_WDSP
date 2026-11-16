package database

import (
	"testing"

	"github.com/jiuzhang-waf/server/internal/config"
)

func TestRebind(t *testing.T) {
	tests := []struct {
		name    string
		dialect string
		query   string
		want    string
	}{
		{
			name:    "postgres unchanged",
			dialect: config.DBDialectPostgres,
			query:   "SELECT * FROM users WHERE id=$1 AND status=$2",
			want:    "SELECT * FROM users WHERE id=$1 AND status=$2",
		},
		{
			name:    "kingbase unchanged",
			dialect: config.DBDialectKingbase,
			query:   "SELECT * FROM users WHERE id=$1",
			want:    "SELECT * FROM users WHERE id=$1",
		},
		{
			name:    "dameng positional parameters",
			dialect: config.DBDialectDameng,
			query:   "SELECT * FROM users WHERE id=$1 AND status=$2 AND version>$10",
			want:    "SELECT * FROM users WHERE id=:1 AND status=:2 AND version>:10",
		},
		{
			name:    "quoted strings and identifiers",
			dialect: config.DBDialectDameng,
			query:   `SELECT '$1', "column$2", E'escaped\\\'$3' FROM t WHERE id=$4`,
			want:    `SELECT '$1', "column$2", E'escaped\\\'$3' FROM t WHERE id=:4`,
		},
		{
			name:    "comments",
			dialect: config.DBDialectDameng,
			query:   "SELECT $1 -- $2\n/* $3 /* nested $4 */ still $5 */ FROM t WHERE x=$6",
			want:    "SELECT :1 -- $2\n/* $3 /* nested $4 */ still $5 */ FROM t WHERE x=:6",
		},
		{
			name:    "dollar quoted strings",
			dialect: config.DBDialectDameng,
			query:   "SELECT $$ $1 $$, $body$ $2 $body$, $3",
			want:    "SELECT $$ $1 $$, $body$ $2 $body$, :3",
		},
		{
			name:    "empty query",
			dialect: config.DBDialectDameng,
			query:   "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Rebind(tt.dialect, tt.query)
			if err != nil {
				t.Fatalf("Rebind() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("Rebind() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRebindRejectsInvalidInput(t *testing.T) {
	for _, tt := range []struct {
		name    string
		dialect string
		query   string
	}{
		{name: "unknown dialect", dialect: "mysql", query: "SELECT $1"},
		{name: "zero parameter", dialect: config.DBDialectDameng, query: "SELECT $0"},
		{name: "overflow parameter", dialect: config.DBDialectDameng, query: "SELECT $999999999999999999999999"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Rebind(tt.dialect, tt.query); err == nil {
				t.Fatal("Rebind() accepted invalid input")
			}
		})
	}
}
