package apimodels

import (
	"net/http"
	"reflect"
	"testing"
)

func TestComputeSchemaDiff(t *testing.T) {
	tests := []struct {
		name string
		from map[string]string
		to   map[string]string
		want SchemaDiff
	}{
		{
			name: "新增删除与类型变化",
			from: map[string]string{"id": "integer", "name": "string", "age": "string"},
			to:   map[string]string{"id": "integer", "age": "integer", "email": "string"},
			want: SchemaDiff{
				Added:   []string{"email"},
				Removed: []string{"name"},
				TypeChanged: []TypeChange{
					{Field: "age", From: "string", To: "integer"},
				},
			},
		},
		{
			name: "完全一致",
			from: map[string]string{"id": "integer"},
			to:   map[string]string{"id": "integer"},
			want: SchemaDiff{Added: []string{}, Removed: []string{}, TypeChanged: []TypeChange{}},
		},
		{
			name: "空到非空全部新增",
			from: map[string]string{},
			to:   map[string]string{"b": "string", "a": "integer"},
			want: SchemaDiff{Added: []string{"a", "b"}, Removed: []string{}, TypeChanged: []TypeChange{}},
		},
		{
			name: "非空到空全部删除",
			from: map[string]string{"b": "string", "a": "integer"},
			to:   map[string]string{},
			want: SchemaDiff{Added: []string{}, Removed: []string{"a", "b"}, TypeChanged: []TypeChange{}},
		},
		{
			name: "nil 输入按空 schema 处理",
			from: nil,
			to:   nil,
			want: SchemaDiff{Added: []string{}, Removed: []string{}, TypeChanged: []TypeChange{}},
		},
		{
			name: "多处类型变化按字段名排序",
			from: map[string]string{"z": "string", "m": "string", "a": "string"},
			to:   map[string]string{"z": "integer", "m": "number", "a": "boolean"},
			want: SchemaDiff{
				Added:   []string{},
				Removed: []string{},
				TypeChanged: []TypeChange{
					{Field: "a", From: "string", To: "boolean"},
					{Field: "m", From: "string", To: "number"},
					{Field: "z", From: "string", To: "integer"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeSchemaDiff(tt.from, tt.to)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("computeSchemaDiff()=%+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestRegisterRoutesNoPanic 注册 51.2/51.3 全部路由不得出现模式冲突。
func TestRegisterRoutesNoPanic(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, func(h http.Handler) http.Handler { return h }, NewHandler(nil, nil))
}
