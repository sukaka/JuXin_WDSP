package wasmplugins

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ==================== WASM Binary Fixture Builders (Pure Go) ====================

func encodeULEB128(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			break
		}
	}
	return out
}

func encodeWasmName(s string) []byte {
	out := encodeULEB128(uint32(len(s)))
	return append(out, []byte(s)...)
}

func encodeWasmSection(id byte, payload []byte) []byte {
	out := []byte{id}
	out = append(out, encodeULEB128(uint32(len(payload)))...)
	return append(out, payload...)
}

type wasmImportSpec struct {
	mod   string
	field string
	kind  byte
}

type wasmExportSpec struct {
	name string
	kind byte
	idx  uint32
}

func buildTestWasmModule(imports []wasmImportSpec, exports []wasmExportSpec, extraSections ...[]byte) []byte {
	var buf bytes.Buffer
	buf.Write(wasmMagic)
	buf.Write(wasmVersion)

	// Type section (id=1): 1 func type () -> ()
	buf.Write(encodeWasmSection(1, []byte{0x01, 0x60, 0x00, 0x00}))

	if len(imports) > 0 {
		var imp bytes.Buffer
		imp.Write(encodeULEB128(uint32(len(imports))))
		for _, spec := range imports {
			imp.Write(encodeWasmName(spec.mod))
			imp.Write(encodeWasmName(spec.field))
			imp.WriteByte(spec.kind)
			switch spec.kind {
			case wasmKindFunc:
				imp.Write(encodeULEB128(0))
			case wasmKindMemory:
				imp.Write([]byte{0x00, 0x01})
			case wasmKindGlobal:
				imp.Write([]byte{0x7f, 0x00})
			}
		}
		buf.Write(encodeWasmSection(wasmSectionImport, imp.Bytes()))
	}

	// Function section (id=3): 1 local func using type 0
	buf.Write(encodeWasmSection(3, []byte{0x01, 0x00}))
	// Memory section (id=5): 1 memory min=1 page
	buf.Write(encodeWasmSection(5, []byte{0x01, 0x00, 0x01}))

	if len(exports) > 0 {
		var exp bytes.Buffer
		exp.Write(encodeULEB128(uint32(len(exports))))
		for _, e := range exports {
			exp.Write(encodeWasmName(e.name))
			exp.WriteByte(e.kind)
			exp.Write(encodeULEB128(e.idx))
		}
		buf.Write(encodeWasmSection(wasmSectionExport, exp.Bytes()))
	}

	for _, sec := range extraSections {
		buf.Write(sec)
	}

	// Code section (id=10): 1 empty function body (locals=0, end=0x0b)
	buf.Write(encodeWasmSection(10, []byte{0x01, 0x02, 0x00, 0x0b}))
	return buf.Bytes()
}

func validTestWasmBytes() []byte {
	return buildTestWasmModule(
		[]wasmImportSpec{{mod: "wdsp_env", field: "get_path", kind: wasmKindFunc}},
		[]wasmExportSpec{
			{name: "wdsp_on_request", kind: wasmKindFunc, idx: 1},
			{name: "memory", kind: wasmKindMemory, idx: 0},
		},
	)
}

func validTestWasmBytesV2() []byte {
	// Valid module with an extra custom section so SHA-256 differs cleanly from v1.
	custom := encodeWasmSection(0, append(encodeWasmName("producer"), []byte("v2")...))
	return buildTestWasmModule(
		nil,
		[]wasmExportSpec{
			{name: "wdsp_on_request", kind: wasmKindFunc, idx: 0},
			{name: "memory", kind: wasmKindMemory, idx: 0},
		},
		custom,
	)
}

// ==================== Pure-Go WASM Structural Validator Tests ====================

func TestValidateWasmBinary(t *testing.T) {
	t.Run("valid module with wdsp_env import and required exports", func(t *testing.T) {
		if err := ValidateWasmBinary(validTestWasmBytes()); err != nil {
			t.Fatalf("expected valid wasm to pass, got: %v", err)
		}
	})

	t.Run("valid module with DataCount section before Code section", func(t *testing.T) {
		dataCount := encodeWasmSection(wasmSectionDataCount, []byte{0x00})
		raw := buildTestWasmModule(
			nil,
			[]wasmExportSpec{
				{name: "wdsp_on_request", kind: wasmKindFunc, idx: 0},
				{name: "memory", kind: wasmKindMemory, idx: 0},
			},
			dataCount,
		)
		if err := ValidateWasmBinary(raw); err != nil {
			t.Fatalf("valid module with DataCount before Code rejected: %v", err)
		}
	})

	cases := []struct {
		name    string
		payload []byte
		wantSub string
	}{
		{"empty", nil, "不能为空"},
		{"too short", []byte{0x00, 0x61, 0x73}, "魔数"},
		{"bad magic", []byte{'P', 'K', 0x03, 0x04, 0x01, 0x00, 0x00, 0x00}, "魔数"},
		{"bad version 2", []byte{0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00}, "版本"},
		{"exceeds 4MiB", make([]byte, MaxWasmBinaryBytes+1), "超过上限"},
		{"unknown section id", append(append([]byte{}, wasmMagic...), append(wasmVersion, 0x1f, 0x00)...), "未知"},
		{"truncated section length", append(append([]byte{}, wasmMagic...), append(wasmVersion, 0x07, 0x80)...), "LEB128"},
		{"LEB128 uint32 overflow", append(append([]byte{}, wasmMagic...), append(wasmVersion, 0x07, 0x80, 0x80, 0x80, 0x80, 0x10)...), "LEB128"},
		{"section length exceeds EOF", append(append([]byte{}, wasmMagic...), append(wasmVersion, 0x07, 0x20, 0x00)...), "超出剩余字节"},
		{"duplicate standard section", func() []byte {
			var b bytes.Buffer
			b.Write(wasmMagic)
			b.Write(wasmVersion)
			b.Write(encodeWasmSection(5, []byte{0x01, 0x00, 0x01}))
			b.Write(encodeWasmSection(5, []byte{0x01, 0x00, 0x01}))
			return b.Bytes()
		}(), "重复"},
		{"out of order section", func() []byte {
			var b bytes.Buffer
			b.Write(wasmMagic)
			b.Write(wasmVersion)
			b.Write(encodeWasmSection(7, []byte{0x00}))
			b.Write(encodeWasmSection(5, []byte{0x01, 0x00, 0x01}))
			return b.Bytes()
		}(), "顺序非法"},
		{"WASI snapshot preview1 import rejected", buildTestWasmModule(
			[]wasmImportSpec{{mod: "wasi_snapshot_preview1", field: "fd_write", kind: wasmKindFunc}},
			[]wasmExportSpec{
				{name: "wdsp_on_request", kind: wasmKindFunc, idx: 1},
				{name: "memory", kind: wasmKindMemory, idx: 0},
			},
		), "WASI"},
		{"WASI preview2 component namespace import rejected", buildTestWasmModule(
			[]wasmImportSpec{{mod: "wasi:cli/environment", field: "get-environment", kind: wasmKindFunc}},
			[]wasmExportSpec{
				{name: "wdsp_on_request", kind: wasmKindFunc, idx: 1},
				{name: "memory", kind: wasmKindMemory, idx: 0},
			},
		), "WASI"},
		{"unauthorized non-wdsp_env import rejected", buildTestWasmModule(
			[]wasmImportSpec{{mod: "env", field: "open_socket", kind: wasmKindFunc}},
			[]wasmExportSpec{
				{name: "wdsp_on_request", kind: wasmKindFunc, idx: 1},
				{name: "memory", kind: wasmKindMemory, idx: 0},
			},
		), "未授权宿主模块"},
		{"missing wdsp_on_request export", buildTestWasmModule(
			nil,
			[]wasmExportSpec{{name: "memory", kind: wasmKindMemory, idx: 0}},
		), "wdsp_on_request"},
		{"wdsp_on_request exported as global instead of func", buildTestWasmModule(
			nil,
			[]wasmExportSpec{
				{name: "wdsp_on_request", kind: wasmKindGlobal, idx: 0},
				{name: "memory", kind: wasmKindMemory, idx: 0},
			},
		), "wdsp_on_request"},
		{"missing memory export", buildTestWasmModule(
			nil,
			[]wasmExportSpec{{name: "wdsp_on_request", kind: wasmKindFunc, idx: 0}},
		), "memory"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateWasmBinary(tc.payload)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !errors.Is(err, ErrInvalidWasm) {
				t.Fatalf("expected ErrInvalidWasm wrap, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// ==================== Config Validation & CompileForGuard Tests ====================

func TestValidateConfigBounds(t *testing.T) {
	if errs := ValidateConfigFields("valid_plugin-1.0", true, "desc", ABIVersionWDSPV1, ModeProtect, 0, 1, 256, 0, FailPolicyClosed, []string{"/api/", "/v2/login"}); len(errs) > 0 {
		t.Fatalf("lower-bound valid config rejected: %+v", errs)
	}
	if errs := ValidateConfigFields("A", true, "", ABIVersionWDSPV1, ModeOff, 10000, 50, 16384, 65536, FailPolicyOpen, nil); len(errs) > 0 {
		t.Fatalf("upper-bound valid config rejected: %+v", errs)
	}

	// Out-of-bounds checks
	errs := ValidateConfigFields("-bad-start", true, "bad\x00desc", "wdsp_v2", "UNKNOWN", 10001, 51, 128, 65537, "DROP", []string{"no-slash", "/has?query", "/has#frag"})
	wantFields := map[string]bool{
		"name":             false,
		"description":      false,
		"abi_version":      false,
		"mode":             false,
		"priority":         false,
		"timeout_ms":       false,
		"max_memory_kb":    false,
		"max_body_bytes":   false,
		"fail_policy":      false,
		"path_prefixes[0]": false,
		"path_prefixes[1]": false,
		"path_prefixes[2]": false,
	}
	for _, e := range errs {
		if _, ok := wantFields[e.Field]; ok {
			wantFields[e.Field] = true
		}
	}
	for f, seen := range wantFields {
		if !seen {
			t.Errorf("expected validation error on field %q; got %+v", f, errs)
		}
	}

	// >32 path prefixes rejected
	tooMany := make([]string, MaxPathPrefixes+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("/p/%d", i)
	}
	if errs := ValidateConfigFields("ok", true, "", ABIVersionWDSPV1, ModeOff, 100, 2, 4096, 65536, FailPolicyOpen, tooMany); len(errs) == 0 {
		t.Fatal("expected >32 path_prefixes to fail validation")
	}
}

func TestCompileForGuardMergeAndSort(t *testing.T) {
	app1 := uuid.New()
	app2 := uuid.New()
	bin1 := validTestWasmBytes()
	bin2 := validTestWasmBytesV2()
	sha1 := ComputeSHA256Hex(bin1)
	sha2 := ComputeSHA256Hex(bin2)

	compiled, err := CompileForGuard(
		[]AppScope{{ID: app1, Code: "app-one"}, {ID: app2, Code: "app-two"}},
		[]GuardPluginRow{
			{
				ID: uuid.New(), ApplicationID: nil, Name: "global-mid", Version: 1, ABIVersion: ABIVersionWDSPV1,
				Mode: ModeObserve, SHA256: sha1, WasmBinary: bin1, Priority: 100, TimeoutMs: 2, MaxMemoryKB: 4096,
				MaxBodyBytes: 65536, FailPolicy: FailPolicyOpen, PathPrefixes: []string{"/"},
			},
			{
				ID: uuid.New(), ApplicationID: &app1, Name: "app1-first", Version: 2, ABIVersion: ABIVersionWDSPV1,
				Mode: ModeProtect, SHA256: sha2, WasmBinary: bin2, Priority: 10, TimeoutMs: 5, MaxMemoryKB: 8192,
				MaxBodyBytes: 1024, FailPolicy: FailPolicyClosed, PathPrefixes: []string{"/api/"},
			},
		},
	)
	if err != nil {
		t.Fatalf("CompileForGuard: %v", err)
	}
	if len(compiled) != 2 {
		t.Fatalf("expected 2 apps in compiled map, got %d", len(compiled))
	}
	c1 := compiled["app-one"]
	if c1 == nil || c1.SchemaVersion != 1 || c1.ApplicationID != app1.String() || len(c1.Plugins) != 2 {
		t.Fatalf("unexpected app-one compiled config: %+v", c1)
	}
	if c1.Plugins[0].Name != "app1-first" || c1.Plugins[1].Name != "global-mid" {
		t.Fatalf("expected priority sort [app1-first, global-mid], got [%s, %s]", c1.Plugins[0].Name, c1.Plugins[1].Name)
	}
	if c1.Plugins[0].WasmBase64 != base64.StdEncoding.EncodeToString(bin2) {
		t.Fatal("wasm_base64 encoding mismatch")
	}
	c2 := compiled["app-two"]
	if c2 == nil || len(c2.Plugins) != 1 || c2.Plugins[0].Name != "global-mid" {
		t.Fatalf("app-two should inherit only global plugin, got %+v", c2)
	}

	// Tampered SHA-256 must fail-hard
	if _, err := CompileForGuard(
		[]AppScope{{ID: app1, Code: "app-one"}},
		[]GuardPluginRow{{
			ID: uuid.New(), Name: "tampered", Version: 1, ABIVersion: ABIVersionWDSPV1,
			Mode: ModeProtect, SHA256: strings.Repeat("0", 64), WasmBinary: bin1,
			Priority: 10, TimeoutMs: 2, MaxMemoryKB: 4096, MaxBodyBytes: 65536, FailPolicy: FailPolicyOpen,
		}},
	); err == nil {
		t.Fatal("tampered sha256 must fail-hard in CompileForGuard")
	}

	// Merged count > 16 must fail-hard
	rows := make([]GuardPluginRow, 0, 17)
	for i := 0; i < 10; i++ {
		rows = append(rows, GuardPluginRow{
			ID: uuid.New(), Name: fmt.Sprintf("g-%d", i), Version: 1, ABIVersion: ABIVersionWDSPV1,
			Mode: ModeObserve, SHA256: sha1, WasmBinary: bin1, Priority: i, TimeoutMs: 2, MaxMemoryKB: 4096, MaxBodyBytes: 65536, FailPolicy: FailPolicyOpen,
		})
	}
	for i := 0; i < 7; i++ {
		rows = append(rows, GuardPluginRow{
			ID: uuid.New(), ApplicationID: &app1, Name: fmt.Sprintf("a-%d", i), Version: 1, ABIVersion: ABIVersionWDSPV1,
			Mode: ModeObserve, SHA256: sha1, WasmBinary: bin1, Priority: i, TimeoutMs: 2, MaxMemoryKB: 4096, MaxBodyBytes: 65536, FailPolicy: FailPolicyOpen,
		})
	}
	if _, err := CompileForGuard([]AppScope{{ID: app1, Code: "app-one"}}, rows); err == nil {
		t.Fatal("merged global+app >16 plugins must fail-hard")
	}
}

// ==================== HTTP Handler End-to-End Tests ====================

type storedVersion struct {
	meta   PluginVersion
	binary []byte
	snap   ConfigSnapshot
}

type fakeRepo struct {
	plugins  map[uuid.UUID]*Plugin
	binaries map[uuid.UUID][]byte
	versions map[uuid.UUID][]storedVersion
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		plugins:  map[uuid.UUID]*Plugin{},
		binaries: map[uuid.UUID][]byte{},
		versions: map[uuid.UUID][]storedVersion{},
	}
}

func (f *fakeRepo) List(_ context.Context, filter ListFilter) ([]Plugin, int, error) {
	items := []Plugin{}
	for _, p := range f.plugins {
		if filter.GlobalOnly && p.ApplicationID != nil {
			continue
		}
		if filter.ApplicationID != nil && (p.ApplicationID == nil || *p.ApplicationID != *filter.ApplicationID) {
			continue
		}
		if filter.Mode != "" && p.Mode != filter.Mode {
			continue
		}
		if filter.Keyword != "" &&
			!strings.Contains(strings.ToLower(p.Name), strings.ToLower(filter.Keyword)) &&
			!strings.Contains(strings.ToLower(p.Description), strings.ToLower(filter.Keyword)) {
			continue
		}
		cp := *p
		cp.PathPrefixes = append([]string(nil), p.PathPrefixes...)
		items = append(items, cp)
	}
	total := len(items)
	start := (filter.Page - 1) * filter.PageSize
	if start >= total {
		return []Plugin{}, total, nil
	}
	end := start + filter.PageSize
	if end > total {
		end = total
	}
	return items[start:end], total, nil
}

func (f *fakeRepo) GetByID(_ context.Context, id uuid.UUID) (*Plugin, error) {
	p, ok := f.plugins[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	cp.PathPrefixes = append([]string(nil), p.PathPrefixes...)
	return &cp, nil
}

func (f *fakeRepo) ListVersions(_ context.Context, pluginID uuid.UUID) ([]PluginVersion, error) {
	src := f.versions[pluginID]
	out := make([]PluginVersion, 0, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		out = append(out, src[i].meta)
	}
	return out, nil
}

func sameScope(a, b *uuid.UUID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func (f *fakeRepo) Create(_ context.Context, in CreateInput) (*Plugin, error) {
	scopeCount := 0
	for _, existing := range f.plugins {
		if sameScope(existing.ApplicationID, in.ApplicationID) {
			scopeCount++
			if existing.Name == in.Name {
				return nil, ErrDuplicateName
			}
		}
	}
	if scopeCount >= MaxPluginsPerScope {
		return nil, ErrScopeLimitReached
	}
	now := time.Now().UTC()
	id := uuid.New()
	p := &Plugin{
		ID:            id,
		ApplicationID: in.ApplicationID,
		Name:          in.Name,
		Description:   in.Description,
		Version:       1,
		ABIVersion:    in.ABIVersion,
		Mode:          in.Mode,
		SHA256:        in.SHA256,
		WasmSize:      len(in.WasmBinary),
		Priority:      in.Priority,
		TimeoutMs:     in.TimeoutMs,
		MaxMemoryKB:   in.MaxMemoryKB,
		MaxBodyBytes:  in.MaxBodyBytes,
		FailPolicy:    in.FailPolicy,
		PathPrefixes:  append([]string(nil), in.PathPrefixes...),
		UpdatedBy:     in.CreatedBy,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	f.plugins[id] = p
	f.binaries[id] = append([]byte(nil), in.WasmBinary...)
	f.versions[id] = []storedVersion{{
		meta: PluginVersion{
			ID: uuid.New(), Version: 1, ABIVersion: in.ABIVersion, Mode: in.Mode,
			SHA256: in.SHA256, WasmSize: len(in.WasmBinary), Reason: in.Reason, CreatedBy: in.CreatedBy, CreatedAt: now,
		},
		binary: append([]byte(nil), in.WasmBinary...),
		snap: ConfigSnapshot{
			Description: in.Description, Priority: in.Priority, TimeoutMs: in.TimeoutMs,
			MaxMemoryKB: in.MaxMemoryKB, MaxBodyBytes: in.MaxBodyBytes, FailPolicy: in.FailPolicy,
			PathPrefixes: append([]string(nil), in.PathPrefixes...),
		},
	}}
	return f.GetByID(context.Background(), id)
}

func (f *fakeRepo) Update(_ context.Context, in UpdateInput) (*Plugin, error) {
	p, ok := f.plugins[in.ID]
	if !ok {
		return nil, ErrNotFound
	}
	if p.Version != in.ExpectedVersion {
		return nil, ErrConflict
	}
	bin := f.binaries[in.ID]
	sha := p.SHA256
	if len(in.WasmBinary) > 0 {
		bin = append([]byte(nil), in.WasmBinary...)
		sha = in.SHA256
	} else if in.ExpectedSHA256 != "" && VerifySHA256ConstantTime(in.ExpectedSHA256, p.SHA256) != "" {
		return nil, ErrSHA256Mismatch
	}
	if in.Description != nil {
		p.Description = *in.Description
	}
	p.Version++
	p.Mode = in.Mode
	p.SHA256 = sha
	p.WasmSize = len(bin)
	p.Priority = in.Priority
	p.TimeoutMs = in.TimeoutMs
	p.MaxMemoryKB = in.MaxMemoryKB
	p.MaxBodyBytes = in.MaxBodyBytes
	p.FailPolicy = in.FailPolicy
	p.PathPrefixes = append([]string(nil), in.PathPrefixes...)
	p.UpdatedBy = in.UpdatedBy
	p.UpdatedAt = time.Now().UTC()
	f.binaries[in.ID] = bin
	f.versions[in.ID] = append(f.versions[in.ID], storedVersion{
		meta: PluginVersion{
			ID: uuid.New(), Version: p.Version, ABIVersion: p.ABIVersion, Mode: p.Mode,
			SHA256: p.SHA256, WasmSize: p.WasmSize, Reason: in.Reason, CreatedBy: in.UpdatedBy, CreatedAt: p.UpdatedAt,
		},
		binary: bin,
		snap: ConfigSnapshot{
			Description: p.Description, Priority: p.Priority, TimeoutMs: p.TimeoutMs,
			MaxMemoryKB: p.MaxMemoryKB, MaxBodyBytes: p.MaxBodyBytes, FailPolicy: p.FailPolicy,
			PathPrefixes: append([]string(nil), p.PathPrefixes...),
		},
	})
	return f.GetByID(context.Background(), in.ID)
}

func (f *fakeRepo) Rollback(_ context.Context, in RollbackInput) (*Plugin, error) {
	p, ok := f.plugins[in.ID]
	if !ok {
		return nil, ErrNotFound
	}
	if p.Version != in.ExpectedVersion {
		return nil, ErrConflict
	}
	var target *storedVersion
	for i := range f.versions[in.ID] {
		if f.versions[in.ID][i].meta.Version == in.TargetVersion {
			target = &f.versions[in.ID][i]
			break
		}
	}
	if target == nil {
		return nil, ErrVersionNotFound
	}
	p.Version++
	p.Description = target.snap.Description
	p.ABIVersion = target.meta.ABIVersion
	p.Mode = target.meta.Mode
	p.SHA256 = target.meta.SHA256
	p.WasmSize = len(target.binary)
	p.Priority = target.snap.Priority
	p.TimeoutMs = target.snap.TimeoutMs
	p.MaxMemoryKB = target.snap.MaxMemoryKB
	p.MaxBodyBytes = target.snap.MaxBodyBytes
	p.FailPolicy = target.snap.FailPolicy
	p.PathPrefixes = append([]string(nil), target.snap.PathPrefixes...)
	p.UpdatedBy = in.UpdatedBy
	p.UpdatedAt = time.Now().UTC()
	f.binaries[in.ID] = append([]byte(nil), target.binary...)
	f.versions[in.ID] = append(f.versions[in.ID], storedVersion{
		meta: PluginVersion{
			ID: uuid.New(), Version: p.Version, ABIVersion: p.ABIVersion, Mode: p.Mode,
			SHA256: p.SHA256, WasmSize: p.WasmSize, Reason: in.Reason, CreatedBy: in.UpdatedBy, CreatedAt: p.UpdatedAt,
		},
		binary: append([]byte(nil), target.binary...),
		snap:   target.snap,
	})
	return f.GetByID(context.Background(), in.ID)
}

func (f *fakeRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := f.plugins[id]; !ok {
		return ErrNotFound
	}
	delete(f.plugins, id)
	delete(f.binaries, id)
	delete(f.versions, id)
	return nil
}

type fakeAppGetter struct {
	apps map[uuid.UUID]*applications.Application
}

func (f fakeAppGetter) GetByID(_ context.Context, id uuid.UUID) (*applications.Application, error) {
	a, ok := f.apps[id]
	if !ok {
		return nil, applications.ErrNotFound
	}
	return a, nil
}

type spyAudit struct {
	records []audits.RecordInput
}

func (s *spyAudit) Record(_ context.Context, in audits.RecordInput) error {
	s.records = append(s.records, in)
	return nil
}

func newTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/wasm-plugins", h.List)
	mux.HandleFunc("POST /api/v1/wasm-plugins", h.Create)
	mux.HandleFunc("GET /api/v1/wasm-plugins/{id}", h.Get)
	mux.HandleFunc("PUT /api/v1/wasm-plugins/{id}", h.Update)
	mux.HandleFunc("POST /api/v1/wasm-plugins/{id}/rollback", h.Rollback)
	mux.HandleFunc("DELETE /api/v1/wasm-plugins/{id}", h.Delete)
	return mux
}

func doJSONReq(mux http.Handler, method, target string, body interface{}) *httptest.ResponseRecorder {
	var rBody bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&rBody).Encode(body)
	}
	req := httptest.NewRequest(method, target, &rBody)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		Username: "secadmin",
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestHandlerFullLifecycleAndSecurity(t *testing.T) {
	appID := uuid.New()
	repo := newFakeRepo()
	au := &spyAudit{}
	h := &Handler{
		store:  repo,
		apps:   fakeAppGetter{apps: map[uuid.UUID]*applications.Application{appID: {ID: appID, Code: "shop"}}},
		audits: au,
	}
	mux := newTestMux(h)

	v1Bin := validTestWasmBytes()
	v1B64 := base64.StdEncoding.EncodeToString(v1Bin)
	v1SHA := ComputeSHA256Hex(v1Bin)

	v2Bin := validTestWasmBytesV2()
	v2B64 := base64.StdEncoding.EncodeToString(v2Bin)
	v2SHA := ComputeSHA256Hex(v2Bin)

	// 1. POST create global plugin v1
	rec := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins", map[string]interface{}{
		"name":            "global-guard",
		"description":     "v1 global detector",
		"mode":            "OBSERVE",
		"wasm_base64":     v1B64,
		"expected_sha256": v1SHA,
		"priority":        100,
		"timeout_ms":      2,
		"max_memory_kb":   4096,
		"max_body_bytes":  65536,
		"fail_policy":     "FAIL_OPEN",
		"path_prefixes":   []string{"/api/"},
		"reason":          "initial upload",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST create expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "wasm_binary") || strings.Contains(rec.Body.String(), "wasm_base64") || strings.Contains(rec.Body.String(), v1B64) {
		t.Fatalf("POST response must NEVER leak raw wasm_binary/wasm_base64: %s", rec.Body.String())
	}
	var createEnv struct {
		Data struct {
			Plugin Plugin `json:"plugin"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createEnv); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	created := createEnv.Data.Plugin
	if created.Version != 1 || created.SHA256 != v1SHA || created.WasmSize != len(v1Bin) || created.ABIVersion != ABIVersionWDSPV1 {
		t.Fatalf("unexpected created plugin: %+v", created)
	}

	// 2. POST duplicate name in global scope -> 409
	recDup := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins", map[string]interface{}{
		"name":        "global-guard",
		"mode":        "OFF",
		"wasm_base64": v1B64,
		"reason":      "dup",
	})
	if recDup.Code != http.StatusConflict {
		t.Fatalf("duplicate name expected 409, got %d: %s", recDup.Code, recDup.Body.String())
	}

	// 3. POST expected_sha256 mismatch -> 400
	recBadSHA := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins", map[string]interface{}{
		"name":            "bad-sha",
		"mode":            "OFF",
		"wasm_base64":     v1B64,
		"expected_sha256": strings.Repeat("f", 64),
		"reason":          "sha test",
	})
	if recBadSHA.Code != http.StatusBadRequest {
		t.Fatalf("expected_sha256 mismatch expected 400, got %d", recBadSHA.Code)
	}

	// 4. POST app-scoped plugin (and verify unknown app -> 404)
	recNoApp := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins", map[string]interface{}{
		"name":           "orphan",
		"application_id": uuid.New().String(),
		"mode":           "OBSERVE",
		"wasm_base64":    v1B64,
		"reason":         "bad app",
	})
	if recNoApp.Code != http.StatusNotFound {
		t.Fatalf("unknown application_id expected 404, got %d", recNoApp.Code)
	}
	recApp := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins", map[string]interface{}{
		"name":           "shop-guard",
		"application_id": appID.String(),
		"mode":           "PROTECT",
		"wasm_base64":    v1B64,
		"reason":         "shop detector",
	})
	if recApp.Code != http.StatusCreated {
		t.Fatalf("app-scoped create expected 201, got %d: %s", recApp.Code, recApp.Body.String())
	}

	// 5. GET list filters (all / global / app / mode / keyword) & zero binary leakage
	recListGlobal := doJSONReq(mux, http.MethodGet, "/api/v1/wasm-plugins?application_id=global", nil)
	if recListGlobal.Code != http.StatusOK {
		t.Fatalf("GET list global expected 200, got %d", recListGlobal.Code)
	}
	if strings.Contains(recListGlobal.Body.String(), "wasm_binary") || strings.Contains(recListGlobal.Body.String(), "wasm_base64") || strings.Contains(recListGlobal.Body.String(), v1B64) {
		t.Fatalf("GET list must NEVER leak raw binary: %s", recListGlobal.Body.String())
	}
	var listEnv struct {
		Data struct {
			Items    []Plugin `json:"items"`
			Total    int      `json:"total"`
			Page     int      `json:"page"`
			PageSize int      `json:"page_size"`
		} `json:"data"`
	}
	_ = json.Unmarshal(recListGlobal.Body.Bytes(), &listEnv)
	if listEnv.Data.Total != 1 || len(listEnv.Data.Items) != 1 || listEnv.Data.Items[0].Name != "global-guard" {
		t.Fatalf("expected 1 global plugin, got %+v", listEnv.Data)
	}

	// 6. PUT update keeping existing binary (wasm_base64 omitted) -> v2
	recUpdKeep := doJSONReq(mux, http.MethodPut, "/api/v1/wasm-plugins/"+created.ID.String(), map[string]interface{}{
		"expected_version": 1,
		"mode":             "PROTECT",
		"priority":         50,
		"timeout_ms":       5,
		"max_memory_kb":    8192,
		"max_body_bytes":   0,
		"fail_policy":      "FAIL_CLOSED",
		"path_prefixes":    []string{"/api/v1/"},
		"reason":           "enable protect without re-upload",
	})
	if recUpdKeep.Code != http.StatusOK {
		t.Fatalf("PUT keep binary expected 200, got %d: %s", recUpdKeep.Code, recUpdKeep.Body.String())
	}
	var updEnv struct {
		Data struct {
			Plugin Plugin `json:"plugin"`
		} `json:"data"`
	}
	_ = json.Unmarshal(recUpdKeep.Body.Bytes(), &updEnv)
	if updEnv.Data.Plugin.Version != 2 || updEnv.Data.Plugin.SHA256 != v1SHA || updEnv.Data.Plugin.MaxBodyBytes != 0 || updEnv.Data.Plugin.FailPolicy != FailPolicyClosed {
		t.Fatalf("unexpected v2 plugin after keep-binary update: %+v", updEnv.Data.Plugin)
	}

	// 7. PUT optimistic lock conflict (expected_version=1 when current=2) -> 409
	recConflict := doJSONReq(mux, http.MethodPut, "/api/v1/wasm-plugins/"+created.ID.String(), map[string]interface{}{
		"expected_version": 1,
		"mode":             "OFF",
		"reason":           "stale write",
	})
	if recConflict.Code != http.StatusConflict {
		t.Fatalf("stale expected_version expected 409, got %d", recConflict.Code)
	}

	// 8. PUT replacing binary -> v3
	recUpdBin := doJSONReq(mux, http.MethodPut, "/api/v1/wasm-plugins/"+created.ID.String(), map[string]interface{}{
		"expected_version": 2,
		"mode":             "PROTECT",
		"wasm_base64":      v2B64,
		"expected_sha256":  v2SHA,
		"priority":         20,
		"timeout_ms":       3,
		"max_memory_kb":    4096,
		"max_body_bytes":   1024,
		"fail_policy":      "FAIL_OPEN",
		"path_prefixes":    []string{"/v2/"},
		"reason":           "upgrade wasm binary to v2",
	})
	if recUpdBin.Code != http.StatusOK {
		t.Fatalf("PUT replace binary expected 200, got %d: %s", recUpdBin.Code, recUpdBin.Body.String())
	}
	_ = json.Unmarshal(recUpdBin.Body.Bytes(), &updEnv)
	if updEnv.Data.Plugin.Version != 3 || updEnv.Data.Plugin.SHA256 != v2SHA {
		t.Fatalf("expected v3 with v2SHA, got %+v", updEnv.Data.Plugin)
	}

	// 9. POST rollback to v1 -> creates v4 with v1 binary & config while keeping v1/v2/v3 immutable
	recRBConflict := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins/"+created.ID.String()+"/rollback", map[string]interface{}{
		"target_version":   1,
		"expected_version": 2,
		"reason":           "stale rollback",
	})
	if recRBConflict.Code != http.StatusConflict {
		t.Fatalf("rollback conflict expected 409, got %d", recRBConflict.Code)
	}
	recRB := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins/"+created.ID.String()+"/rollback", map[string]interface{}{
		"target_version":   1,
		"expected_version": 3,
		"reason":           "revert to v1 baseline",
	})
	if recRB.Code != http.StatusOK {
		t.Fatalf("rollback expected 200, got %d: %s", recRB.Code, recRB.Body.String())
	}
	_ = json.Unmarshal(recRB.Body.Bytes(), &updEnv)
	if updEnv.Data.Plugin.Version != 4 || updEnv.Data.Plugin.SHA256 != v1SHA || updEnv.Data.Plugin.Mode != ModeObserve || updEnv.Data.Plugin.Priority != 100 {
		t.Fatalf("expected v4 rolled back to v1 binary+config, got %+v", updEnv.Data.Plugin)
	}

	// 10. GET detail verifies 4 immutable versions (v4..v1) and zero raw binary leak
	recGet := doJSONReq(mux, http.MethodGet, "/api/v1/wasm-plugins/"+created.ID.String(), nil)
	if recGet.Code != http.StatusOK {
		t.Fatalf("GET detail expected 200, got %d", recGet.Code)
	}
	if strings.Contains(recGet.Body.String(), "wasm_binary") || strings.Contains(recGet.Body.String(), "wasm_base64") || strings.Contains(recGet.Body.String(), v1B64) || strings.Contains(recGet.Body.String(), v2B64) {
		t.Fatalf("GET detail must NEVER leak raw wasm_binary/wasm_base64: %s", recGet.Body.String())
	}
	var detailEnv struct {
		Data struct {
			Plugin   Plugin          `json:"plugin"`
			Versions []PluginVersion `json:"versions"`
		} `json:"data"`
	}
	_ = json.Unmarshal(recGet.Body.Bytes(), &detailEnv)
	if len(detailEnv.Data.Versions) != 4 || detailEnv.Data.Versions[0].Version != 4 || detailEnv.Data.Versions[3].Version != 1 {
		t.Fatalf("expected 4 immutable versions [4..1], got %+v", detailEnv.Data.Versions)
	}

	// 11. DELETE plugin -> 200 { deleted: true, id }
	recDel := doJSONReq(mux, http.MethodDelete, "/api/v1/wasm-plugins/"+created.ID.String(), nil)
	if recDel.Code != http.StatusOK {
		t.Fatalf("DELETE expected 200, got %d: %s", recDel.Code, recDel.Body.String())
	}
	var delEnv struct {
		Data struct {
			Deleted bool   `json:"deleted"`
			ID      string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal(recDel.Body.Bytes(), &delEnv)
	if !delEnv.Data.Deleted || delEnv.Data.ID != created.ID.String() {
		t.Fatalf("unexpected delete response: %+v", delEnv.Data)
	}

	// 12. Verify audits were recorded cleanly (module=wasm_plugins, object_type=wasm_plugin, zero binary leak)
	if len(au.records) < 6 {
		t.Fatalf("expected >=6 audit records, got %d", len(au.records))
	}
	for _, rec := range au.records {
		if rec.Module != "wasm_plugins" || rec.ObjectType != "wasm_plugin" {
			t.Errorf("unexpected audit module/object_type: %+v", rec)
		}
		if strings.Contains(rec.AfterSummary, v1B64) || strings.Contains(rec.AfterSummary, v2B64) {
			t.Errorf("audit summary must NEVER contain raw wasm_base64: %s", rec.AfterSummary)
		}
	}
}

func TestHandlerScopeLimit16(t *testing.T) {
	repo := newFakeRepo()
	h := &Handler{store: repo}
	mux := newTestMux(h)
	b64 := base64.StdEncoding.EncodeToString(validTestWasmBytes())

	for i := 0; i < MaxPluginsPerScope; i++ {
		rec := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins", map[string]interface{}{
			"name":        fmt.Sprintf("p-%02d", i),
			"mode":        "OFF",
			"wasm_base64": b64,
			"reason":      "fill scope",
		})
		if rec.Code != http.StatusCreated {
			t.Fatalf("plugin %d create expected 201, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	// 17th plugin in same scope must be rejected with 400
	rec17 := doJSONReq(mux, http.MethodPost, "/api/v1/wasm-plugins", map[string]interface{}{
		"name":        "p-17",
		"mode":        "OFF",
		"wasm_base64": b64,
		"reason":      "exceed limit",
	})
	if rec17.Code != http.StatusBadRequest {
		t.Fatalf("17th plugin in scope expected 400, got %d: %s", rec17.Code, rec17.Body.String())
	}
}
