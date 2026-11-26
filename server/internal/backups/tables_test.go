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
	auditCount := 0
	for _, td := range full {
		if td.Group == GroupAudit {
			auditCount++
		}
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
	if len(cfg) != len(full)-auditCount {
		t.Errorf("CONFIG_ONLY tables = %d, want %d", len(cfg), len(full)-auditCount)
	}
}

func TestTablesIncludeWDSPStateAndRestoreDependencies(t *testing.T) {
	required := []string{
		"application_policies", "jwt_trust_policies", "jwt_trust_policy_versions",
		"bot_policies", "bot_policy_versions",
		"ai_crawler_directories", "ai_crawl_policies", "ai_crawl_policy_versions",
		"client_side_policies", "client_side_policy_versions",
		"client_script_inventory", "client_side_violations",
		"api_endpoints", "api_model_versions",
		"api_runtime_policies", "api_runtime_events", "api_runtime_findings",
		"api_schema_violations", "api_object_models", "api_object_relations",
		"api_authorization_decisions", "api_role_baselines", "api_object_ownership",
		"api_field_permissions",
		"api_assets", "api_parameter_models", "api_parameter_statistics",
		"api_parameter_relations", "api_request_schemas", "api_response_schemas",
		"api_masking_rules", "api_sensitive_data_types", "api_file_compliance_rules",
		"api_grpc_descriptors",
	}
	seen := map[string]bool{}
	for _, td := range Tables {
		seen[td.Name] = true
	}
	for _, name := range required {
		if !seen[name] {
			t.Errorf("WDSP table %q is missing from backup scope", name)
		}
	}
	order, err := RestoreOrder([]string{"applications", "application_policies", "api_endpoints", "api_model_versions", "api_runtime_policies"})
	if err != nil {
		t.Fatalf("RestoreOrder() error = %v", err)
	}
	pos := map[string]int{}
	for i, name := range order {
		pos[name] = i
	}
	for child, parent := range map[string]string{
		"application_policies":       "applications",
		"api_endpoints":              "applications",
		"api_model_versions":         "api_endpoints",
		"api_runtime_policies":       "api_model_versions",
		"client_side_policies":       "applications",
		"client_side_policy_versions": "client_side_policies",
		"client_script_inventory":    "applications",
	} {
		// 仅检查传入子集内的边
		if _, okC := pos[child]; !okC {
			continue
		}
		if _, okP := pos[parent]; !okP {
			continue
		}
		if pos[parent] >= pos[child] {
			t.Errorf("%s must restore before %s: %v", parent, child, order)
		}
	}
	// Phase 9B 客户端供应链安全四表分组与拓扑校验
	csGroups := map[string]string{
		"client_side_policies":        GroupConfig,
		"client_side_policy_versions": GroupConfig,
		"client_script_inventory":     GroupConfig,
		"client_side_violations":      GroupAudit,
	}
	for tbl, wantGroup := range csGroups {
		td, ok := TableByName(tbl)
		if !ok {
			t.Errorf("missing client-side table %q", tbl)
			continue
		}
		if td.Group != wantGroup {
			t.Errorf("table %q group = %q, want %q", tbl, td.Group, wantGroup)
		}
	}
	csOrder, err := RestoreOrder([]string{"client_side_policy_versions", "client_script_inventory", "client_side_policies", "applications"})
	if err != nil {
		t.Fatalf("RestoreOrder(client_side) error = %v", err)
	}
	csPos := map[string]int{}
	for i, n := range csOrder {
		csPos[n] = i
	}
	if csPos["applications"] >= csPos["client_side_policies"] ||
		csPos["client_side_policies"] >= csPos["client_side_policy_versions"] ||
		csPos["applications"] >= csPos["client_script_inventory"] {
		t.Errorf("invalid client-side restore order: %v", csOrder)
	}
}

func TestAllWDSPMigrationTablesHaveRestoreClassification(t *testing.T) {
	// 该清单对应 server/migrations 中 WDSP/API 表；新增迁移表时必须在这里
	// 选择 CONFIG、LEARNING、FACT 或 AUDIT，避免只在导出逻辑中漏掉一张表。
	required := []string{
		"api_endpoints", "api_endpoint_aliases", "api_endpoint_path_segments", "api_assets",
		"api_learning_jobs", "api_learning_samples", "api_parameter_models", "api_parameter_statistics",
		"api_parameter_relations", "api_parameter_value_obs", "api_request_schemas", "api_response_schemas",
		"api_classifications", "api_classification_dimensions", "api_custom_taxonomies", "api_identity_profiles",
		"api_object_models", "api_behavior_profiles", "api_call_edges", "api_sensitive_fields",
		"api_runtime_findings", "api_schema_violations", "api_lifecycle_events", "api_model_reviews",
		"api_model_diffs", "api_import_specs", "api_spec_diffs", "api_runtime_events", "api_runtime_policies",
		"api_weaknesses", "api_weakness_actions", "api_endpoint_traffic_buckets", "api_scan_targets",
		"api_scan_authorizations", "api_scan_jobs", "api_scan_findings", "api_file_assets",
		"api_cross_border_events", "api_cross_border_state", "api_ai_schedules", "api_ai_schedule_runs",
		"api_llm_observations", "api_object_relation_candidates", "api_authz_candidate_event_receipts",
		"api_authz_migration_state", "api_authorization_decisions", "api_object_relations", "api_role_baselines",
		"api_object_ownership", "api_field_permissions", "api_masking_rules", "api_sensitive_data_types",
		"api_file_compliance_rules", "api_grpc_descriptors", "api_gateway_nodes",
	}
	allowed := map[string]bool{
		GroupConfig: true, GroupLearning: true, GroupFact: true, GroupAudit: true,
	}
	for _, name := range required {
		td, ok := TableByName(name)
		if !ok {
			t.Errorf("WDSP migration table %q is missing from backup scope", name)
			continue
		}
		if !allowed[td.Group] {
			t.Errorf("WDSP table %q has invalid classification %q", name, td.Group)
		}
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
