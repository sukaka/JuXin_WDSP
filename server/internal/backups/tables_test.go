package backups

import (
	"testing"
)

// TestRestoreOrderRespectsDeps 拓扑序必须满足全部依赖边（parent 先于 child）。
func TestRestoreOrderRespectsDeps(t *testing.T) {
	var names []string
	for _, td := range Tables {
		names = append(names, td.Name)
	}
	order, err := RestoreOrder(names)
	if err != nil {
		t.Fatalf("restore order: %v", err)
	}
	pos := map[string]int{}
	for i, n := range order {
		pos[n] = i
	}
	for child, parents := range tableDeps {
		for _, p := range parents {
			if pos[p] >= pos[child] {
				t.Errorf("dependency violated: %s(pos %d) should come before %s(pos %d)", p, pos[p], child, pos[child])
			}
		}
	}
}

// TestRestoreOrderDeterministic 相同输入输出一致。
func TestRestoreOrderDeterministic(t *testing.T) {
	names := []string{"upstreams", "users", "roles", "applications", "user_roles", "permissions", "application_domains"}
	a, err := RestoreOrder(names)
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	b, err := RestoreOrder(names)
	if err != nil {
		t.Fatalf("order: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("length mismatch")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic order: %v vs %v", a, b)
		}
	}
	// 子集内依赖仍须保持
	pos := map[string]int{}
	for i, n := range a {
		pos[n] = i
	}
	if pos["applications"] >= pos["upstreams"] {
		t.Error("applications should come before upstreams")
	}
	if pos["users"] >= pos["user_roles"] || pos["roles"] >= pos["user_roles"] {
		t.Error("users/roles should come before user_roles")
	}
}

// TestTopoCycleDetected 依赖环必须报错。
func TestTopoCycleDetected(t *testing.T) {
	nodes := []string{"a", "b"}
	deps := map[string][]string{"a": {"b"}, "b": {"a"}}
	rank := map[string]int{"a": 0, "b": 1}
	if _, err := topoSort(nodes, deps, rank); err == nil {
		t.Error("cycle should be detected")
	}
}

// TestTablesForBackup 备份类型决定导出范围。
func TestTablesForBackup(t *testing.T) {
	full := TablesForBackup(TypeFull)
	foundAudit := false
	for _, td := range full {
		if td.Name == "operation_audits" {
			foundAudit = true
			if td.RecentLimit != AuditExportLimit {
				t.Errorf("audit recent limit = %d, want %d", td.RecentLimit, AuditExportLimit)
			}
		}
	}
	if !foundAudit {
		t.Error("FULL backup should include operation_audits archive")
	}
	cfg := TablesForBackup(TypeConfigOnly)
	for _, td := range cfg {
		if td.Group == GroupAudit {
			t.Error("CONFIG_ONLY backup must not include audit archive")
		}
	}
	if len(cfg) != len(full)-1 {
		t.Errorf("CONFIG_ONLY tables = %d, want %d", len(cfg), len(full)-1)
	}
}

// TestManifestValidate 清单自洽性校验。
func TestManifestValidate(t *testing.T) {
	valid := func() *Manifest {
		return &Manifest{
			Format:        FormatName,
			FormatVersion: FormatVersion,
			BackupID:      "b1",
			BackupType:    TypeConfigOnly,
			SchemaVersion: 11,
			Compression:   "gzip",
			ArchiveFormat: "tar",
			Encryption:    EncryptionMeta{Algorithm: EncryptionAlgorithm, ChunkSize: ChunkSize, ChunkCount: 1},
			Data:          DataMeta{SHA256Encrypted: "abc", SHA256Plain: "def", SizeEncrypted: 10, SizePlain: 8},
			Tables: []TableManifest{
				{Name: "users", Group: GroupDatabase, Columns: []string{"id"}, RowCount: 2, ByteCount: 10, SHA256: "h"},
				{Name: "roles", Group: GroupDatabase, Columns: []string{"id"}, RowCount: 1, ByteCount: 5, SHA256: "h2"},
			},
			TotalRows: 3,
		}
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(m *Manifest)
	}{
		{"bad format", func(m *Manifest) { m.Format = "zip" }},
		{"bad version", func(m *Manifest) { m.FormatVersion = 99 }},
		{"missing id", func(m *Manifest) { m.BackupID = "" }},
		{"bad type", func(m *Manifest) { m.BackupType = "PARTIAL" }},
		{"bad algorithm", func(m *Manifest) { m.Encryption.Algorithm = "AES-128" }},
		{"missing data hash", func(m *Manifest) { m.Data.SHA256Plain = "" }},
		{"unknown table", func(m *Manifest) { m.Tables[0].Name = "pg_shadow" }},
		{"no columns", func(m *Manifest) { m.Tables[0].Columns = nil }},
		{"negative rows", func(m *Manifest) { m.Tables[0].RowCount = -1; m.TotalRows = 1 }},
		{"missing segment hash", func(m *Manifest) { m.Tables[0].SHA256 = "" }},
		{"total mismatch", func(m *Manifest) { m.TotalRows = 99 }},
		{"no tables", func(m *Manifest) { m.Tables = nil; m.TotalRows = 0 }},
	}
	for _, c := range cases {
		m := valid()
		c.mutate(m)
		if err := m.Validate(); err == nil {
			t.Errorf("%s: should be rejected", c.name)
		}
	}
}

// TestCheckSchemaCompat 备份 schema 版本高于当前时拒绝。
func TestCheckSchemaCompat(t *testing.T) {
	if err := CheckSchemaCompat(11, 11); err != nil {
		t.Errorf("equal version should pass: %v", err)
	}
	if err := CheckSchemaCompat(9, 11); err != nil {
		t.Errorf("older backup should pass: %v", err)
	}
	if err := CheckSchemaCompat(12, 11); err == nil {
		t.Error("newer backup must be rejected")
	}
}
