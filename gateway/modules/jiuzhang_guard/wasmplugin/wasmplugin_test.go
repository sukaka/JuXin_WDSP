package wasmplugin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"
)

// ---------- 最小纯 Go WebAssembly 二进制构造器（零外部编译器依赖） ----------

type wasmFuncType struct {
	params  []byte
	results []byte
}

type wasmImport struct {
	mod     string
	name    string
	typeIdx uint32
}

type wasmExport struct {
	name string
	kind byte // 0x00=func, 0x02=memory
	idx  uint32
}

type wasmDataSeg struct {
	offset int32
	data   []byte
}

type wasmFuncBody struct {
	locals []struct {
		count uint32
		val   byte
	}
	code []byte
}

type wasmModuleSpec struct {
	types       []wasmFuncType
	imports     []wasmImport
	funcTypes   []uint32
	hasMemory   bool
	memMinPages uint32
	exports     []wasmExport
	bodies      []wasmFuncBody
	dataSegs    []wasmDataSeg
}

const valI32 byte = 0x7f

func uleb128(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

func sleb128(v int32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		done := (v == 0 && (b&0x40) == 0) || (v == -1 && (b&0x40) != 0)
		if !done {
			b |= 0x80
		}
		out = append(out, b)
		if done {
			return out
		}
	}
}

func wasmStr(s string) []byte {
	return append(uleb128(uint32(len(s))), []byte(s)...)
}

func wasmSection(id byte, payload []byte) []byte {
	out := []byte{id}
	out = append(out, uleb128(uint32(len(payload)))...)
	return append(out, payload...)
}

func i32Const(v int32) []byte {
	return append([]byte{0x41}, sleb128(v)...)
}

func callFn(idx uint32) []byte {
	return append([]byte{0x10}, uleb128(idx)...)
}

func localGet(idx uint32) []byte {
	return append([]byte{0x20}, uleb128(idx)...)
}

func localSet(idx uint32) []byte {
	return append([]byte{0x21}, uleb128(idx)...)
}

func (m wasmModuleSpec) build() []byte {
	bin := append([]byte(nil), wasmMagicHeader...)

	// Section 1: Type
	if len(m.types) > 0 {
		p := uleb128(uint32(len(m.types)))
		for _, t := range m.types {
			p = append(p, 0x60)
			p = append(p, uleb128(uint32(len(t.params)))...)
			p = append(p, t.params...)
			p = append(p, uleb128(uint32(len(t.results)))...)
			p = append(p, t.results...)
		}
		bin = append(bin, wasmSection(1, p)...)
	}

	// Section 2: Import
	if len(m.imports) > 0 {
		p := uleb128(uint32(len(m.imports)))
		for _, imp := range m.imports {
			p = append(p, wasmStr(imp.mod)...)
			p = append(p, wasmStr(imp.name)...)
			p = append(p, 0x00) // func import
			p = append(p, uleb128(imp.typeIdx)...)
		}
		bin = append(bin, wasmSection(2, p)...)
	}

	// Section 3: Function
	if len(m.funcTypes) > 0 {
		p := uleb128(uint32(len(m.funcTypes)))
		for _, ti := range m.funcTypes {
			p = append(p, uleb128(ti)...)
		}
		bin = append(bin, wasmSection(3, p)...)
	}

	// Section 5: Memory
	if m.hasMemory {
		p := []byte{0x01, 0x00} // 1 memory, limits: min only
		p = append(p, uleb128(m.memMinPages)...)
		bin = append(bin, wasmSection(5, p)...)
	}

	// Section 7: Export
	if len(m.exports) > 0 {
		p := uleb128(uint32(len(m.exports)))
		for _, ex := range m.exports {
			p = append(p, wasmStr(ex.name)...)
			p = append(p, ex.kind)
			p = append(p, uleb128(ex.idx)...)
		}
		bin = append(bin, wasmSection(7, p)...)
	}

	// Section 10: Code
	if len(m.bodies) > 0 {
		p := uleb128(uint32(len(m.bodies)))
		for _, b := range m.bodies {
			var body []byte
			body = append(body, uleb128(uint32(len(b.locals)))...)
			for _, loc := range b.locals {
				body = append(body, uleb128(loc.count)...)
				body = append(body, loc.val)
			}
			body = append(body, b.code...)
			body = append(body, 0x0b) // end
			p = append(p, uleb128(uint32(len(body)))...)
			p = append(p, body...)
		}
		bin = append(bin, wasmSection(10, p)...)
	}

	// Section 11: Data
	if len(m.dataSegs) > 0 {
		p := uleb128(uint32(len(m.dataSegs)))
		for _, seg := range m.dataSegs {
			p = append(p, 0x00) // active memory 0
			p = append(p, i32Const(seg.offset)...)
			p = append(p, 0x0b) // end offset expr
			p = append(p, uleb128(uint32(len(seg.data)))...)
			p = append(p, seg.data...)
		}
		bin = append(bin, wasmSection(11, p)...)
	}

	return bin
}

// buildStaticResultWasm 构造调用 wdsp_env.set_result(action, score, rule, reason) 的最小 Wasm 二进制。
func buildStaticResultWasm(action, score int32, rule, reason string) []byte {
	const (
		rulePtr   int32 = 0x100
		reasonPtr int32 = 0x400
	)
	var code []byte
	code = append(code, i32Const(action)...)
	code = append(code, i32Const(score)...)
	code = append(code, i32Const(rulePtr)...)
	code = append(code, i32Const(int32(len(rule)))...)
	code = append(code, i32Const(reasonPtr)...)
	code = append(code, i32Const(int32(len(reason)))...)
	code = append(code, callFn(0)...)

	var data []wasmDataSeg
	if len(rule) > 0 {
		data = append(data, wasmDataSeg{offset: rulePtr, data: []byte(rule)})
	}
	if len(reason) > 0 {
		data = append(data, wasmDataSeg{offset: reasonPtr, data: []byte(reason)})
	}

	return wasmModuleSpec{
		types: []wasmFuncType{
			{params: []byte{valI32, valI32, valI32, valI32, valI32, valI32}}, // 0: set_result
			{}, // 1: wdsp_on_request
		},
		imports: []wasmImport{
			{mod: HostModuleName, name: hostFnSetResult, typeIdx: 0}, // func 0
		},
		funcTypes:   []uint32{1}, // func 1
		hasMemory:   true,
		memMinPages: 1,
		exports: []wasmExport{
			{name: ExportMemoryName, kind: 0x02, idx: 0},
			{name: ExportEntrypointName, kind: 0x00, idx: 1},
		},
		bodies:   []wasmFuncBody{{code: code}},
		dataSegs: data,
	}.build()
}

// buildEchoGetterWasm 构造调用 get_method / get_path / get_query / get_body 并将结果回写至 set_result.reason 的插件。
func buildEchoGetterWasm(getterName, rule string, action int32) []byte {
	const (
		rulePtr int32 = 0x100
		bufPtr  int32 = 0x300
		bufMax  int32 = 256
	)
	var code []byte
	// local 0 = n = getter(bufPtr, bufMax)
	code = append(code, i32Const(bufPtr)...)
	code = append(code, i32Const(bufMax)...)
	code = append(code, callFn(0)...) // func 0: getter
	code = append(code, localSet(0)...)
	// set_result(action, local0, rulePtr, len(rule), bufPtr, local0)
	code = append(code, i32Const(action)...)
	code = append(code, localGet(0)...)
	code = append(code, i32Const(rulePtr)...)
	code = append(code, i32Const(int32(len(rule)))...)
	code = append(code, i32Const(bufPtr)...)
	code = append(code, localGet(0)...)
	code = append(code, callFn(1)...) // func 1: set_result

	return wasmModuleSpec{
		types: []wasmFuncType{
			{params: []byte{valI32, valI32}, results: []byte{valI32}},         // 0: getter
			{params: []byte{valI32, valI32, valI32, valI32, valI32, valI32}}, // 1: set_result
			{}, // 2: wdsp_on_request
		},
		imports: []wasmImport{
			{mod: HostModuleName, name: getterName, typeIdx: 0},      // func 0
			{mod: HostModuleName, name: hostFnSetResult, typeIdx: 1}, // func 1
		},
		funcTypes:   []uint32{2}, // func 2
		hasMemory:   true,
		memMinPages: 1,
		exports: []wasmExport{
			{name: ExportMemoryName, kind: 0x02, idx: 0},
			{name: ExportEntrypointName, kind: 0x00, idx: 2},
		},
		bodies: []wasmFuncBody{{
			locals: []struct {
				count uint32
				val   byte
			}{{count: 1, val: valI32}},
			code: code,
		}},
		dataSegs: []wasmDataSeg{{offset: rulePtr, data: []byte(rule)}},
	}.build()
}

// buildHeaderProbeWasm 构造探测指定请求头的 Wasm 插件：
// 若 get_header 返回 >= 0，则调用 set_result(BLOCK, len, "hdr.present", val)；
// 若返回 -1，则调用 set_result(OBSERVE, 0, "hdr.redacted", "missing_or_blocked")。
func buildHeaderProbeWasm(headerName string) []byte {
	const (
		namePtr        int32 = 0x100
		rulePresentPtr int32 = 0x200
		ruleRedacted   int32 = 0x280
		reasonRedacted int32 = 0x300
		outBufPtr      int32 = 0x400
		outBufMax      int32 = 256
	)
	const (
		rPresent  = "hdr.present"
		rRedacted = "hdr.redacted"
		mRedacted = "missing_or_blocked"
	)
	var code []byte
	// local 0 = get_header(namePtr, len(name), outBufPtr, outBufMax)
	code = append(code, i32Const(namePtr)...)
	code = append(code, i32Const(int32(len(headerName)))...)
	code = append(code, i32Const(outBufPtr)...)
	code = append(code, i32Const(outBufMax)...)
	code = append(code, callFn(0)...)
	code = append(code, localSet(0)...)

	// if local0 < 0 -> OBSERVE hdr.redacted else BLOCK hdr.present with value in reason
	code = append(code, localGet(0)...)
	code = append(code, i32Const(0)...)
	code = append(code, 0x48)       // i32.lt_s
	code = append(code, 0x04, 0x40) // if (void)
	code = append(code, i32Const(ActionObserve)...)
	code = append(code, i32Const(0)...)
	code = append(code, i32Const(ruleRedacted)...)
	code = append(code, i32Const(int32(len(rRedacted)))...)
	code = append(code, i32Const(reasonRedacted)...)
	code = append(code, i32Const(int32(len(mRedacted)))...)
	code = append(code, callFn(1)...)
	code = append(code, 0x05) // else
	code = append(code, i32Const(ActionBlock)...)
	code = append(code, localGet(0)...)
	code = append(code, i32Const(rulePresentPtr)...)
	code = append(code, i32Const(int32(len(rPresent)))...)
	code = append(code, i32Const(outBufPtr)...)
	code = append(code, localGet(0)...)
	code = append(code, callFn(1)...)
	code = append(code, 0x0b) // end if

	return wasmModuleSpec{
		types: []wasmFuncType{
			{params: []byte{valI32, valI32, valI32, valI32}, results: []byte{valI32}}, // 0: get_header
			{params: []byte{valI32, valI32, valI32, valI32, valI32, valI32}},         // 1: set_result
			{}, // 2: wdsp_on_request
		},
		imports: []wasmImport{
			{mod: HostModuleName, name: hostFnGetHeader, typeIdx: 0}, // func 0
			{mod: HostModuleName, name: hostFnSetResult, typeIdx: 1}, // func 1
		},
		funcTypes:   []uint32{2}, // func 2
		hasMemory:   true,
		memMinPages: 1,
		exports: []wasmExport{
			{name: ExportMemoryName, kind: 0x02, idx: 0},
			{name: ExportEntrypointName, kind: 0x00, idx: 2},
		},
		bodies: []wasmFuncBody{{
			locals: []struct {
				count uint32
				val   byte
			}{{count: 1, val: valI32}},
			code: code,
		}},
		dataSegs: []wasmDataSeg{
			{offset: namePtr, data: []byte(headerName)},
			{offset: rulePresentPtr, data: []byte(rPresent)},
			{offset: ruleRedacted, data: []byte(rRedacted)},
			{offset: reasonRedacted, data: []byte(mRedacted)},
		},
	}.build()
}

// buildInfiniteLoopWasm 构造纯死循环（loop br 0 end）Wasm 恶意二进制。
func buildInfiniteLoopWasm() []byte {
	return wasmModuleSpec{
		types:       []wasmFuncType{{}},
		funcTypes:   []uint32{0},
		hasMemory:   true,
		memMinPages: 1,
		exports: []wasmExport{
			{name: ExportMemoryName, kind: 0x02, idx: 0},
			{name: ExportEntrypointName, kind: 0x00, idx: 0},
		},
		bodies: []wasmFuncBody{{
			code: []byte{0x03, 0x40, 0x0c, 0x00, 0x0b}, // loop (void) br 0 end
		}},
	}.build()
}

// buildInitialMemoryWasm 构造声明 initialPages 初始线性内存页的 Wasm 二进制。
func buildInitialMemoryWasm(initialPages uint32) []byte {
	return wasmModuleSpec{
		types:       []wasmFuncType{{}},
		funcTypes:   []uint32{0},
		hasMemory:   true,
		memMinPages: initialPages,
		exports: []wasmExport{
			{name: ExportMemoryName, kind: 0x02, idx: 0},
			{name: ExportEntrypointName, kind: 0x00, idx: 0},
		},
		bodies: []wasmFuncBody{{code: nil}},
	}.build()
}

// buildMemoryGrowWasm 构造运行期尝试 memory.grow(deltaPages) 的 Wasm 二进制：
// 扩容失败返回 -1 时上报 OBSERVE "mem.grow_denied"；成功时上报 BLOCK "mem.grow_allowed"。
func buildMemoryGrowWasm(deltaPages int32) []byte {
	const (
		ruleDeniedPtr  int32 = 0x100
		ruleAllowedPtr int32 = 0x140
	)
	const (
		rDenied  = "mem.grow_denied"
		rAllowed = "mem.grow_allowed"
	)
	var code []byte
	// local 0 = memory.grow(deltaPages)
	code = append(code, i32Const(deltaPages)...)
	code = append(code, 0x40, 0x00) // memory.grow 0
	code = append(code, localSet(0)...)
	// if local0 == -1 -> OBSERVE denied else BLOCK allowed
	code = append(code, localGet(0)...)
	code = append(code, i32Const(-1)...)
	code = append(code, 0x46)       // i32.eq
	code = append(code, 0x04, 0x40) // if
	code = append(code, i32Const(ActionObserve)...)
	code = append(code, i32Const(0)...)
	code = append(code, i32Const(ruleDeniedPtr)...)
	code = append(code, i32Const(int32(len(rDenied)))...)
	code = append(code, i32Const(ruleDeniedPtr)...)
	code = append(code, i32Const(int32(len(rDenied)))...)
	code = append(code, callFn(0)...)
	code = append(code, 0x05) // else
	code = append(code, i32Const(ActionBlock)...)
	code = append(code, i32Const(99)...)
	code = append(code, i32Const(ruleAllowedPtr)...)
	code = append(code, i32Const(int32(len(rAllowed)))...)
	code = append(code, i32Const(ruleAllowedPtr)...)
	code = append(code, i32Const(int32(len(rAllowed)))...)
	code = append(code, callFn(0)...)
	code = append(code, 0x0b)

	return wasmModuleSpec{
		types: []wasmFuncType{
			{params: []byte{valI32, valI32, valI32, valI32, valI32, valI32}},
			{},
		},
		imports:     []wasmImport{{mod: HostModuleName, name: hostFnSetResult, typeIdx: 0}},
		funcTypes:   []uint32{1},
		hasMemory:   true,
		memMinPages: 1,
		exports: []wasmExport{
			{name: ExportMemoryName, kind: 0x02, idx: 0},
			{name: ExportEntrypointName, kind: 0x00, idx: 1},
		},
		bodies: []wasmFuncBody{{
			locals: []struct {
				count uint32
				val   byte
			}{{count: 1, val: valI32}},
			code: code,
		}},
		dataSegs: []wasmDataSeg{
			{offset: ruleDeniedPtr, data: []byte(rDenied)},
			{offset: ruleAllowedPtr, data: []byte(rAllowed)},
		},
	}.build()
}

// buildWASIImportWasm 构造尝试导入 wasi_snapshot_preview1.fd_write 的恶意 Wasm 二进制。
func buildWASIImportWasm() []byte {
	return wasmModuleSpec{
		types: []wasmFuncType{
			{params: []byte{valI32, valI32, valI32, valI32}, results: []byte{valI32}},
			{},
		},
		imports: []wasmImport{
			{mod: "wasi_snapshot_preview1", name: "fd_write", typeIdx: 0},
		},
		funcTypes:   []uint32{1},
		hasMemory:   true,
		memMinPages: 1,
		exports: []wasmExport{
			{name: ExportMemoryName, kind: 0x02, idx: 0},
			{name: ExportEntrypointName, kind: 0x00, idx: 1},
		},
		bodies: []wasmFuncBody{{code: nil}},
	}.build()
}

// buildCrossRequestIsolationWasm 验证每请求独立线性内存：
// 读取 mem[0]，若非 0 说明发生跨请求内存泄漏（上报 BLOCK "mem.leaked"）；否则写入 0x42 并上报 OBSERVE "mem.clean"。
func buildCrossRequestIsolationWasm() []byte {
	const (
		ruleCleanPtr  int32 = 0x100
		ruleLeakedPtr int32 = 0x140
	)
	const (
		rClean  = "mem.clean"
		rLeaked = "mem.leaked"
	)
	var code []byte
	// if i32.load8_u(0) != 0 -> BLOCK mem.leaked else store8(0, 0x42); OBSERVE mem.clean
	code = append(code, i32Const(0)...)
	code = append(code, 0x2d, 0x00, 0x00) // i32.load8_u align=0 offset=0
	code = append(code, i32Const(0)...)
	code = append(code, 0x47)       // i32.ne
	code = append(code, 0x04, 0x40) // if
	code = append(code, i32Const(ActionBlock)...)
	code = append(code, i32Const(100)...)
	code = append(code, i32Const(ruleLeakedPtr)...)
	code = append(code, i32Const(int32(len(rLeaked)))...)
	code = append(code, i32Const(ruleLeakedPtr)...)
	code = append(code, i32Const(int32(len(rLeaked)))...)
	code = append(code, callFn(0)...)
	code = append(code, 0x05) // else
	code = append(code, i32Const(0)...)
	code = append(code, i32Const(0x42)...)
	code = append(code, 0x3a, 0x00, 0x00) // i32.store8 align=0 offset=0
	code = append(code, i32Const(ActionObserve)...)
	code = append(code, i32Const(1)...)
	code = append(code, i32Const(ruleCleanPtr)...)
	code = append(code, i32Const(int32(len(rClean)))...)
	code = append(code, i32Const(ruleCleanPtr)...)
	code = append(code, i32Const(int32(len(rClean)))...)
	code = append(code, callFn(0)...)
	code = append(code, 0x0b)

	return wasmModuleSpec{
		types: []wasmFuncType{
			{params: []byte{valI32, valI32, valI32, valI32, valI32, valI32}},
			{},
		},
		imports:     []wasmImport{{mod: HostModuleName, name: hostFnSetResult, typeIdx: 0}},
		funcTypes:   []uint32{1},
		hasMemory:   true,
		memMinPages: 1,
		exports: []wasmExport{
			{name: ExportMemoryName, kind: 0x02, idx: 0},
			{name: ExportEntrypointName, kind: 0x00, idx: 1},
		},
		bodies: []wasmFuncBody{{code: code}},
		dataSegs: []wasmDataSeg{
			{offset: ruleCleanPtr, data: []byte(rClean)},
			{offset: ruleLeakedPtr, data: []byte(rLeaked)},
		},
	}.build()
}

func wasmSHA256(bin []byte) string {
	sum := sha256.Sum256(bin)
	return hex.EncodeToString(sum[:])
}

func makePlugin(id, name, mode string, bin []byte) PluginConfig {
	return PluginConfig{
		ID:           id,
		Name:         name,
		Version:      1,
		ABIVersion:   ABIVersionV1,
		Mode:         mode,
		SHA256:       wasmSHA256(bin),
		WasmBase64:   base64.StdEncoding.EncodeToString(bin),
		Priority:     100,
		TimeoutMS:    50,
		MaxMemoryKB:  4096,
		MaxBodyBytes: 65536,
		FailPolicy:   FailOpen,
	}
}

// ---------- 测试用例 ----------

func TestWasmPolicyStrictParsingAndSHA256Tamper(t *testing.T) {
	bin := buildStaticResultWasm(ActionAllow, 0, "ok", "allow")
	b64 := base64.StdEncoding.EncodeToString(bin)
	sum := wasmSHA256(bin)

	// 1. 合法配置 + 缺省默认值 + 显式 max_body_bytes: 0 保留
	validRaw := json.RawMessage(`{
		"schema_version": 1,
		"application_id": "app-wasm-1",
		"plugins": [{
			"id": "p-1",
			"name": "custom_waf_v1",
			"version": 2,
			"abi_version": "wdsp_v1",
			"mode": "PROTECT",
			"sha256": "` + sum + `",
			"wasm_base64": "` + b64 + `",
			"max_body_bytes": 0,
			"path_prefixes": ["/api/v1"]
		}]
	}`)
	cfg, err := ParseAndValidateConfig(validRaw)
	if err != nil {
		t.Fatalf("ParseAndValidateConfig valid failed: %v", err)
	}
	if len(cfg.Plugins) != 1 {
		t.Fatalf("want 1 plugin, got %d", len(cfg.Plugins))
	}
	p := cfg.Plugins[0]
	if p.TimeoutMS != DefaultTimeoutMS || p.MaxMemoryKB != DefaultMemoryKB || p.FailPolicy != FailOpen {
		t.Fatalf("defaults mismatch: %+v", p)
	}
	if p.MaxBodyBytes != 0 {
		t.Fatalf("explicit max_body_bytes=0 must be preserved, got %d", p.MaxBodyBytes)
	}

	// 2. 未知字段拒绝（DisallowUnknownFields）
	unknownRaw := json.RawMessage(`{"schema_version":1,"application_id":"app-1","unknown_field":true,"plugins":[]}`)
	if _, err := ParseAndValidateConfig(unknownRaw); err == nil {
		t.Fatal("expected error for unknown top-level field")
	}

	// 3. SHA-256 篡改（单字节翻转）必须 fail-closed 拒绝
	tampered := append([]byte(nil), bin...)
	tampered[len(tampered)-1] ^= 0xff
	tamperedRaw := json.RawMessage(`{
		"schema_version": 1,
		"application_id": "app-wasm-1",
		"plugins": [{
			"id": "p-tamper",
			"name": "tampered",
			"version": 1,
			"abi_version": "wdsp_v1",
			"mode": "PROTECT",
			"sha256": "` + sum + `",
			"wasm_base64": "` + base64.StdEncoding.EncodeToString(tampered) + `"
		}]
	}`)
	if _, err := ParseAndValidateConfig(tamperedRaw); err == nil {
		t.Fatal("expected fail-closed reject on SHA-256 tamper")
	}

	// 4. 超过单应用 16 插件上限拒绝
	many := &Config{SchemaVersion: 1, ApplicationID: "app-1"}
	for i := 0; i < MaxPluginsPerApp+1; i++ {
		many.Plugins = append(many.Plugins, makePlugin("id-"+string(rune('a'+i)), "plg_"+string(rune('a'+i)), ModeObserve, bin))
	}
	if err := ValidateConfig(many); err == nil {
		t.Fatal("expected error when plugins exceed 16")
	}

	// 5. 非法 path_prefixes（含 ? 或 # 或不以 / 开头）拒绝
	badPrefix := makePlugin("p-pfx", "bad_pfx", ModeObserve, bin)
	badPrefix.PathPrefixes = []string{"/api?x=1"}
	if err := ValidateConfig(&Config{SchemaVersion: 1, Plugins: []PluginConfig{badPrefix}}); err == nil {
		t.Fatal("expected error for path_prefix containing '?'")
	}
	badPrefix.PathPrefixes = []string{"api/no-slash"}
	if err := ValidateConfig(&Config{SchemaVersion: 1, Plugins: []PluginConfig{badPrefix}}); err == nil {
		t.Fatal("expected error for path_prefix not starting with '/'")
	}

	// 6. 显式 timeout_ms=0 / 51 超出范围拒绝
	badTimeout := json.RawMessage(`{
		"schema_version": 1,
		"plugins": [{
			"id": "p-to", "name": "to", "version": 1, "abi_version": "wdsp_v1",
			"mode": "PROTECT", "sha256": "` + sum + `", "wasm_base64": "` + b64 + `",
			"timeout_ms": 0
		}]
	}`)
	if _, err := ParseAndValidateConfig(badTimeout); err == nil {
		t.Fatal("expected error for explicit timeout_ms=0")
	}
}

func TestWasmActionsAndHostEnvCalls(t *testing.T) {
	// 1. 测试 ALLOW / OBSERVE / BLOCK / RATE_LIMIT 及分数夹紧 + 控制字符清洗
	blockBin := buildStaticResultWasm(ActionBlock, 250, "custom.block\r\n", "bad\x00"+strings.Repeat("z", 200))
	rlBin := buildStaticResultWasm(ActionRateLimit, -5, "custom.rl", "too_fast")
	obsBin := buildStaticResultWasm(ActionObserve, 42, "custom.obs", "suspicious")
	allowBin := buildStaticResultWasm(ActionAllow, 0, "custom.allow", "clean")

	// ALLOW + OBSERVE + BLOCK 按优先级（10 -> 20 -> 30）执行，并在 PROTECT BLOCK 处终止（priority 40 的 RATE_LIMIT 不执行）
	pAllow := makePlugin("p-allow", "allow_first", ModeProtect, allowBin)
	pAllow.Priority = 10
	pObs := makePlugin("p-obs", "obs_second", ModeProtect, obsBin)
	pObs.Priority = 20
	pBlock := makePlugin("p-block", "block_third", ModeProtect, blockBin)
	pBlock.Priority = 30
	pRL := makePlugin("p-rl", "rl_fourth", ModeProtect, rlBin)
	pRL.Priority = 40

	eng, err := NewEngine(&Config{
		SchemaVersion: 1,
		ApplicationID: "app-1",
		Plugins:       []PluginConfig{pRL, pBlock, pAllow, pObs}, // 刻意乱序验证按 priority 排序
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	req := httptest.NewRequest(http.MethodPost, "https://example.com/api/v1/orders?foo=bar", strings.NewReader("hello-body"))
	res := eng.Evaluate(context.Background(), req, []byte("hello-body"))
	if res.FinalAction != VerdictBlock || res.Blocking == nil {
		t.Fatalf("want VerdictBlock, got %+v", res)
	}
	if res.Blocking.PluginName != "block_third" || res.Blocking.RuleID != "custom.block" {
		t.Fatalf("unexpected blocking outcome: %+v", res.Blocking)
	}
	if res.Blocking.ScoreDelta != MaxScoreDelta {
		t.Fatalf("scoreDelta should clamp to %d, got %d", MaxScoreDelta, res.Blocking.ScoreDelta)
	}
	if len(res.Blocking.Reason) != MaxReasonLen || strings.ContainsRune(res.Blocking.Reason, '\x00') {
		t.Fatalf("reason should be sanitized and clamped to 128, got len=%d %q", len(res.Blocking.Reason), res.Blocking.Reason)
	}
	if len(res.Signals) != 1 || res.Signals[0].RuleID != "custom.obs" || res.Signals[0].ScoreDelta != 42 {
		t.Fatalf("expected 1 OBSERVE signal before BLOCK, got %+v", res.Signals)
	}

	// 2. RATE_LIMIT 在 PROTECT 下生效、在 OBSERVE 下仅收集 would_rate_limit
	engRL, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{pRL}})
	if err != nil {
		t.Fatalf("NewEngine RL: %v", err)
	}
	defer engRL.Close()
	rlRes := engRL.Evaluate(context.Background(), req, nil)
	if rlRes.FinalAction != VerdictRateLimit || rlRes.Blocking == nil || rlRes.Blocking.ScoreDelta != 0 {
		t.Fatalf("want VerdictRateLimit with clamped score 0, got %+v", rlRes)
	}

	pObsBlock := makePlugin("p-ob", "obs_mode_block", ModeObserve, blockBin)
	engObs, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{pObsBlock}})
	if err != nil {
		t.Fatalf("NewEngine obs: %v", err)
	}
	defer engObs.Close()
	obsRes := engObs.Evaluate(context.Background(), req, nil)
	if obsRes.FinalAction != VerdictAllow || obsRes.Blocking != nil || len(obsRes.Signals) != 1 || obsRes.Signals[0].ActionTaken != "would_block" {
		t.Fatalf("OBSERVE mode must not block and must collect would_block signal, got %+v", obsRes)
	}

	// 3. 验证 get_method / get_path（规范路径）/ get_query / get_body（含 max_body_bytes 截断）
	pMethod := makePlugin("p-m", "echo_method", ModeProtect, buildEchoGetterWasm(hostFnGetMethod, "echo.method", ActionObserve))
	pPath := makePlugin("p-p", "echo_path", ModeProtect, buildEchoGetterWasm(hostFnGetPath, "echo.path", ActionObserve))
	pQuery := makePlugin("p-q", "echo_query", ModeProtect, buildEchoGetterWasm(hostFnGetQuery, "echo.query", ActionObserve))
	pBody := makePlugin("p-b", "echo_body", ModeProtect, buildEchoGetterWasm(hostFnGetBody, "echo.body", ActionObserve))
	pBody.MaxBodyBytes = 5
	pMethod.Priority, pPath.Priority, pQuery.Priority, pBody.Priority = 1, 2, 3, 4

	engEcho, err := NewEngine(&Config{
		SchemaVersion: 1,
		Plugins:       []PluginConfig{pMethod, pPath, pQuery, pBody},
	})
	if err != nil {
		t.Fatalf("NewEngine echo: %v", err)
	}
	defer engEcho.Close()

	req2 := httptest.NewRequest(http.MethodPut, "https://example.com/api/../api/v1/items?page=2&sort=asc", nil)
	echoRes := engEcho.Evaluate(context.Background(), req2, []byte("0123456789"))
	if echoRes.FinalAction != VerdictAllow || len(echoRes.Signals) != 4 {
		t.Fatalf("want 4 echo signals, got %+v", echoRes)
	}
	if echoRes.Signals[0].Reason != "PUT" {
		t.Fatalf("get_method mismatch: %q", echoRes.Signals[0].Reason)
	}
	if echoRes.Signals[1].Reason != "/api/v1/items" {
		t.Fatalf("get_path must return canonical path, got %q", echoRes.Signals[1].Reason)
	}
	if echoRes.Signals[2].Reason != "page=2&sort=asc" {
		t.Fatalf("get_query mismatch: %q", echoRes.Signals[2].Reason)
	}
	if echoRes.Signals[3].Reason != "01234" {
		t.Fatalf("get_body must truncate to max_body_bytes=5, got %q", echoRes.Signals[3].Reason)
	}
}

func TestWasmCredentialHeaderRedaction(t *testing.T) {
	blockedHeaders := []string{
		"Authorization",
		"authorization",
		"Cookie",
		"COOKIE",
		"Proxy-Authorization",
		"DPoP",
		"dpop",
		"X-Api-Key",
		"x-api-key",
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/me", nil)
	req.Header.Set("Authorization", "Bearer super-secret-jwt")
	req.Header.Set("Cookie", "session=top-secret")
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	req.Header.Set("DPoP", "eyJhbGciOiJFUzI1NiJ9.proof")
	req.Header.Set("X-Api-Key", "sk-live-secret-key")
	req.Header.Set("X-Safe-Header", "tenant-alpha")

	for _, hdr := range blockedHeaders {
		p := makePlugin("p-"+hdr, "probe_hdr", ModeProtect, buildHeaderProbeWasm(hdr))
		eng, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{p}})
		if err != nil {
			t.Fatalf("NewEngine(%s): %v", hdr, err)
		}
		res := eng.Evaluate(context.Background(), req, nil)
		_ = eng.Close()
		if res.FinalAction != VerdictAllow {
			t.Fatalf("credential header %q was NOT redacted! guest got value: %+v", hdr, res.Blocking)
		}
		if len(res.Signals) != 1 || res.Signals[0].RuleID != "hdr.redacted" {
			t.Fatalf("expected hdr.redacted for %q, got %+v", hdr, res)
		}
	}

	// 对照：普通非凭据头 X-Safe-Header 正常可读
	pSafe := makePlugin("p-safe", "probe_safe", ModeProtect, buildHeaderProbeWasm("X-Safe-Header"))
	engSafe, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{pSafe}})
	if err != nil {
		t.Fatalf("NewEngine safe: %v", err)
	}
	defer engSafe.Close()
	safeRes := engSafe.Evaluate(context.Background(), req, nil)
	if safeRes.FinalAction != VerdictBlock || safeRes.Blocking == nil || safeRes.Blocking.Reason != "tenant-alpha" {
		t.Fatalf("benign header should be readable by guest, got %+v", safeRes)
	}
}

func TestWasmInfiniteLoopTimeoutFailOpenAndFailClosed(t *testing.T) {
	loopBin := buildInfiniteLoopWasm()

	// 1. FAIL_OPEN：超时干净中止，请求放行并记录错误
	pOpen := makePlugin("p-loop-open", "loop_open", ModeProtect, loopBin)
	pOpen.TimeoutMS = 10
	pOpen.FailPolicy = FailOpen
	engOpen, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{pOpen}})
	if err != nil {
		t.Fatalf("NewEngine loop open: %v", err)
	}
	defer engOpen.Close()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/loop", nil)
	start := time.Now()
	resOpen := engOpen.Evaluate(context.Background(), req, nil)
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Fatalf("infinite loop was not killed promptly: elapsed=%v", elapsed)
	}
	if resOpen.FinalAction != VerdictAllow || len(resOpen.Errors) != 1 {
		t.Fatalf("FAIL_OPEN timeout must pass with error recorded, got %+v", resOpen)
	}
	if !strings.Contains(resOpen.Errors[0].Error, "timeout") {
		t.Fatalf("expected timeout error message, got %q", resOpen.Errors[0].Error)
	}

	// 验证同一 Runtime 在一次超时后仍健康可用（不被毒化关闭）
	resOpen2 := engOpen.Evaluate(context.Background(), req, nil)
	if resOpen2.FinalAction != VerdictAllow || len(resOpen2.Errors) != 1 || !strings.Contains(resOpen2.Errors[0].Error, "timeout") {
		t.Fatalf("subsequent call after timeout failed unexpectedly: %+v", resOpen2)
	}

	// 2. PROTECT + FAIL_CLOSED：超时返回 VerdictFailClosed（网关映射 503）
	pClosed := makePlugin("p-loop-closed", "loop_closed", ModeProtect, loopBin)
	pClosed.TimeoutMS = 10
	pClosed.FailPolicy = FailClosed
	engClosed, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{pClosed}})
	if err != nil {
		t.Fatalf("NewEngine loop closed: %v", err)
	}
	defer engClosed.Close()

	resClosed := engClosed.Evaluate(context.Background(), req, nil)
	if resClosed.FinalAction != VerdictFailClosed || resClosed.Blocking == nil {
		t.Fatalf("PROTECT + FAIL_CLOSED timeout must return VerdictFailClosed, got %+v", resClosed)
	}
	if !strings.Contains(resClosed.Blocking.Error, "timeout") {
		t.Fatalf("expected timeout error on fail-closed outcome, got %q", resClosed.Blocking.Error)
	}
}

func TestWasmMemoryLimitEnforcement(t *testing.T) {
	// 1. 声明初始 8 页（512 KiB）超过 max_memory_kb=256（4 页）→ 编译期拒载
	pInitOver := makePlugin("p-mem-init", "mem_init_over", ModeProtect, buildInitialMemoryWasm(8))
	pInitOver.MaxMemoryKB = 256
	if _, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{pInitOver}}); err == nil {
		t.Fatal("expected compile rejection for initial memory 8 pages > limit 4 pages")
	}

	// 2. 运行期 memory.grow(5)（1+5=6 页 > 4 页上限）→ WithMemoryLimitPages 拒绝扩容返回 -1
	pGrowOver := makePlugin("p-mem-grow-over", "mem_grow_over", ModeProtect, buildMemoryGrowWasm(5))
	pGrowOver.MaxMemoryKB = 256 // 4 pages
	engOver, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{pGrowOver}})
	if err != nil {
		t.Fatalf("NewEngine grow over: %v", err)
	}
	defer engOver.Close()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/test", nil)
	resOver := engOver.Evaluate(context.Background(), req, nil)
	if resOver.FinalAction != VerdictAllow || len(resOver.Signals) != 1 || resOver.Signals[0].RuleID != "mem.grow_denied" {
		t.Fatalf("memory.grow(5) must be denied by WithMemoryLimitPages(4), got %+v", resOver)
	}

	// 3. 对照：memory.grow(2)（1+2=3 页 <= 4 页上限）正常允许
	pGrowOK := makePlugin("p-mem-grow-ok", "mem_grow_ok", ModeProtect, buildMemoryGrowWasm(2))
	pGrowOK.MaxMemoryKB = 256 // 4 pages
	engOK, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{pGrowOK}})
	if err != nil {
		t.Fatalf("NewEngine grow ok: %v", err)
	}
	defer engOK.Close()

	resOK := engOK.Evaluate(context.Background(), req, nil)
	if resOK.FinalAction != VerdictBlock || resOK.Blocking == nil || resOK.Blocking.RuleID != "mem.grow_allowed" {
		t.Fatalf("memory.grow(2) within 4 pages should succeed, got %+v", resOK)
	}
}

func TestWasmWASIImportRejected(t *testing.T) {
	wasiBin := buildWASIImportWasm()
	p := makePlugin("p-wasi", "evil_wasi", ModeProtect, wasiBin)

	// 1. 静态导入白名单在 NewEngine / ValidateCompiled 阶段 fail-closed 拒绝
	if _, err := NewEngine(&Config{SchemaVersion: 1, Plugins: []PluginConfig{p}}); err == nil {
		t.Fatal("NewEngine must reject WASI-importing WASM binary")
	}

	// 2. 纵深验证：即便跳过静态检查直接实例化，无 WASI 宿主注册的沙箱 Runtime 仍在 InstantiateModule 拒绝
	ctx := context.Background()
	rt, err := newPluginRuntime(ctx, p.MemoryLimitPages())
	if err != nil {
		t.Fatalf("newPluginRuntime: %v", err)
	}
	defer rt.Close(ctx)
	compiled, err := rt.CompileModule(ctx, wasiBin)
	if err != nil {
		t.Fatalf("CompileModule: %v", err)
	}
	defer compiled.Close(ctx)
	if mod, err := rt.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName("").WithStartFunctions()); err == nil {
		_ = mod.Close(ctx)
		t.Fatal("InstantiateModule must fail for WASI import when no WASI host is registered")
	}
}

func TestWasmCrossRequestIsolationAndConcurrentRace(t *testing.T) {
	pIso := makePlugin("p-iso", "mem_isolation", ModeProtect, buildCrossRequestIsolationWasm())
	pIso.Priority = 10
	pHdr := makePlugin("p-hdr", "hdr_check", ModeProtect, buildHeaderProbeWasm("Authorization"))
	pHdr.Priority = 20
	pPath := makePlugin("p-path", "path_check", ModeProtect, buildEchoGetterWasm(hostFnGetPath, "echo.path", ActionObserve))
	pPath.Priority = 30
	pPath.PathPrefixes = []string{"/api"}

	eng, err := NewEngine(&Config{
		SchemaVersion: 1,
		ApplicationID: "app-race",
		Plugins:       []PluginConfig{pIso, pHdr, pPath},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer eng.Close()

	// 先串行 10 次确定性验证每请求独立线性内存（100% 3 信号、0 超时）
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodPost, "https://example.com/api/v1/resource", nil)
		req.Header.Set("Authorization", "Bearer secret-seq")
		res := eng.Evaluate(context.Background(), req, []byte("payload"))
		if res.FinalAction != VerdictAllow || len(res.Errors) != 0 || len(res.Signals) != 3 ||
			res.Signals[0].RuleID != "mem.clean" || res.Signals[1].RuleID != "hdr.redacted" || res.Signals[2].Reason != "/api/v1/resource" {
			t.Fatalf("sequential isolation iter %d failed: %+v", i, res)
		}
	}

	const workers = 32
	const iters = 10
	var wg sync.WaitGroup
	errCh := make(chan string, workers*iters)
	var mu sync.Mutex
	fullSuccess := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				req := httptest.NewRequest(http.MethodPost, "https://example.com/api/v1/resource", nil)
				req.Header.Set("Authorization", "Bearer secret-per-goroutine")
				res := eng.Evaluate(context.Background(), req, []byte("payload"))
				if res.FinalAction != VerdictAllow {
					errCh <- "unexpected non-allow verdict (possible memory leak or credential leak): " + string(res.FinalAction)
					return
				}
				for _, sig := range res.Signals {
					switch sig.PluginName {
					case "mem_isolation":
						if sig.RuleID != "mem.clean" {
							errCh <- fmt.Sprintf("cross-request memory leak: %+v", sig)
							return
						}
					case "hdr_check":
						if sig.RuleID != "hdr.redacted" {
							errCh <- fmt.Sprintf("credential header leaked: %+v", sig)
							return
						}
					case "path_check":
						if sig.Reason != "/api/v1/resource" {
							errCh <- fmt.Sprintf("unexpected path echo: %+v", sig)
							return
						}
					}
				}
				for _, e := range res.Errors {
					if !strings.Contains(e.Error, "timeout") {
						errCh <- fmt.Sprintf("unexpected non-timeout plugin error under concurrency: %+v", e)
						return
					}
				}
				if len(res.Signals) == 3 && len(res.Errors) == 0 {
					mu.Lock()
					fullSuccess++
					mu.Unlock()
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Fatal(msg)
	}
	if fullSuccess < (workers*iters*8)/10 {
		t.Fatalf("too many timeout errors under concurrency: fullSuccess=%d/%d", fullSuccess, workers*iters)
	}

	// 验证幂等 Close 及 Close 后调用安全返回 ALLOW 不 panic
	if err := eng.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close 2 (idempotent): %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/api/v1/resource", nil)
	if res := eng.Evaluate(context.Background(), req, nil); res.FinalAction != VerdictAllow {
		t.Fatalf("Evaluate after Close should return ALLOW safely, got %+v", res)
	}
}
