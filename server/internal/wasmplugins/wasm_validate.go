// wasm_validate.go 纯 Go WebAssembly 二进制结构与安全契约校验器（零外部依赖）：
//   - 校验文件体积 8B..4MiB、\x00asm 魔数与版本号 1；
//   - 严格解析 LEB128 节边界与标准节顺序，拒绝截断、越界、重复节与未知节；
//   - 解析 Import 节：严禁任何 WASI 导入及非 wdsp_env 宿主模块导入；
//   - 解析 Export 节：要求必须导出函数 "wdsp_on_request" 与内存 "memory"。
package wasmplugins

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

var (
	wasmMagic   = []byte{0x00, 0x61, 0x73, 0x6d} // \x00asm
	wasmVersion = []byte{0x01, 0x00, 0x00, 0x00} // version 1 (little-endian)
)

const (
	wasmSectionCustom    = 0
	wasmSectionImport    = 2
	wasmSectionExport    = 7
	wasmSectionDataCount = 12

	wasmKindFunc   = 0x00
	wasmKindTable  = 0x01
	wasmKindMemory = 0x02
	wasmKindGlobal = 0x03
	wasmKindTag    = 0x04

	allowedHostModule = "wdsp_env"

	requiredExportFunc   = "wdsp_on_request"
	requiredExportMemory = "memory"
)

// ErrInvalidWasm 表示上传的 Wasm 二进制未通过结构或安全契约校验。
var ErrInvalidWasm = errors.New("invalid wasm binary")

// ValidateWasmBinary 严格校验上传的 WebAssembly 二进制字节流（纯 Go，零外部依赖）。
func ValidateWasmBinary(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("%w: Wasm 二进制不能为空", ErrInvalidWasm)
	}
	if len(data) > MaxWasmBinaryBytes {
		return fmt.Errorf("%w: Wasm 二进制大小 %d 字节超过上限 %d 字节（4MiB）", ErrInvalidWasm, len(data), MaxWasmBinaryBytes)
	}
	if len(data) < 8 || !bytes.Equal(data[:4], wasmMagic) {
		return fmt.Errorf("%w: 无效的 WebAssembly 魔数头（必须为 \\x00asm）", ErrInvalidWasm)
	}
	if !bytes.Equal(data[4:8], wasmVersion) {
		return fmt.Errorf("%w: 不支持的 WebAssembly 版本（仅支持版本 1）", ErrInvalidWasm)
	}

	var (
		offset           = 8
		lastOrder        = 0
		seenSections     = [13]bool{}
		hasOnRequestFunc bool
		hasMemoryExport  bool
	)

	for offset < len(data) {
		secID := data[offset]
		offset++

		if secID > wasmSectionDataCount {
			return fmt.Errorf("%w: 未知的 Wasm 节标识 %d", ErrInvalidWasm, secID)
		}
		if secID != wasmSectionCustom {
			if seenSections[secID] {
				return fmt.Errorf("%w: 重复的标准 Wasm 节 %d", ErrInvalidWasm, secID)
			}
			seenSections[secID] = true
			order := wasmSectionOrder(secID)
			if order <= lastOrder {
				return fmt.Errorf("%w: Wasm 节顺序非法（节 %d）", ErrInvalidWasm, secID)
			}
			lastOrder = order
		}

		secSize, next, err := readVarUint32(data, offset)
		if err != nil {
			return fmt.Errorf("%w: 节 %d 长度 LEB128 非法: %v", ErrInvalidWasm, secID, err)
		}
		offset = next
		if uint64(secSize) > uint64(len(data)-offset) {
			return fmt.Errorf("%w: 节 %d 声明长度 %d 超出剩余字节 %d", ErrInvalidWasm, secID, secSize, len(data)-offset)
		}
		payload := data[offset : offset+int(secSize)]
		offset += int(secSize)

		switch secID {
		case wasmSectionImport:
			if err := validateImportSection(payload); err != nil {
				return err
			}
		case wasmSectionExport:
			hasFunc, hasMem, err := validateExportSection(payload)
			if err != nil {
				return err
			}
			hasOnRequestFunc = hasFunc
			hasMemoryExport = hasMem
		}
	}

	if !hasOnRequestFunc {
		return fmt.Errorf("%w: 缺少必需的导出函数 %q", ErrInvalidWasm, requiredExportFunc)
	}
	if !hasMemoryExport {
		return fmt.Errorf("%w: 缺少必需的导出内存 %q", ErrInvalidWasm, requiredExportMemory)
	}
	return nil
}

// wasmSectionOrder 返回 WebAssembly 规范规定的标准节相对顺序（DataCount=12 位于 Element=9 与 Code=10 之间）。
func wasmSectionOrder(id byte) int {
	switch {
	case id >= 1 && id <= 9:
		return int(id)
	case id == wasmSectionDataCount:
		return 10
	case id == 10:
		return 11
	case id == 11:
		return 12
	default:
		return 0
	}
}

func validateImportSection(payload []byte) error {
	count, pos, err := readVarUint32(payload, 0)
	if err != nil {
		return fmt.Errorf("%w: Import 节条目数非法: %v", ErrInvalidWasm, err)
	}
	// 每条 import 至少占用 3 字节（空模块名长度 + 空字段名长度 + 描述符类型）
	if uint64(count) > uint64(len(payload)-pos) {
		return fmt.Errorf("%w: Import 节条目数 %d 超出节体积", ErrInvalidWasm, count)
	}
	for i := uint32(0); i < count; i++ {
		modName, next, err := readWasmName(payload, pos)
		if err != nil {
			return fmt.Errorf("%w: Import 第 %d 项模块名非法: %v", ErrInvalidWasm, i, err)
		}
		pos = next
		if _, next, err = readWasmName(payload, pos); err != nil {
			return fmt.Errorf("%w: Import 第 %d 项字段名非法: %v", ErrInvalidWasm, i, err)
		}
		pos = next
		if isWASIModule(modName) {
			return fmt.Errorf("%w: 禁止导入 WASI 模块 %q（插件运行在零系统权限沙箱中）", ErrInvalidWasm, modName)
		}
		if modName != allowedHostModule {
			return fmt.Errorf("%w: 不允许导入未授权宿主模块 %q（仅允许 %q）", ErrInvalidWasm, modName, allowedHostModule)
		}
		if pos >= len(payload) {
			return fmt.Errorf("%w: Import 第 %d 项缺少描述符", ErrInvalidWasm, i)
		}
		kind := payload[pos]
		pos++
		switch kind {
		case wasmKindFunc:
			if _, pos, err = readVarUint32(payload, pos); err != nil {
				return fmt.Errorf("%w: Import 函数类型索引非法: %v", ErrInvalidWasm, err)
			}
		case wasmKindTable:
			if pos >= len(payload) {
				return fmt.Errorf("%w: Import 表类型截断", ErrInvalidWasm)
			}
			pos++ // reftype
			if pos, err = skipWasmLimits(payload, pos); err != nil {
				return fmt.Errorf("%w: Import 表限制非法: %v", ErrInvalidWasm, err)
			}
		case wasmKindMemory:
			if pos, err = skipWasmLimits(payload, pos); err != nil {
				return fmt.Errorf("%w: Import 内存限制非法: %v", ErrInvalidWasm, err)
			}
		case wasmKindGlobal:
			if pos+2 > len(payload) {
				return fmt.Errorf("%w: Import 全局变量类型截断", ErrInvalidWasm)
			}
			if payload[pos+1] > 1 {
				return fmt.Errorf("%w: Import 全局变量可变性标志非法", ErrInvalidWasm)
			}
			pos += 2
		case wasmKindTag:
			if pos >= len(payload) {
				return fmt.Errorf("%w: Import Tag 描述符截断", ErrInvalidWasm)
			}
			pos++ // attribute
			if _, pos, err = readVarUint32(payload, pos); err != nil {
				return fmt.Errorf("%w: Import Tag 类型索引非法: %v", ErrInvalidWasm, err)
			}
		default:
			return fmt.Errorf("%w: Import 未知描述符类型 0x%02x", ErrInvalidWasm, kind)
		}
	}
	if pos != len(payload) {
		return fmt.Errorf("%w: Import 节末尾存在未解析字节", ErrInvalidWasm)
	}
	return nil
}

func validateExportSection(payload []byte) (hasOnRequestFunc, hasMemory bool, err error) {
	count, pos, err := readVarUint32(payload, 0)
	if err != nil {
		return false, false, fmt.Errorf("%w: Export 节条目数非法: %v", ErrInvalidWasm, err)
	}
	if uint64(count) > uint64(len(payload)-pos) {
		return false, false, fmt.Errorf("%w: Export 节条目数 %d 超出节体积", ErrInvalidWasm, count)
	}
	for i := uint32(0); i < count; i++ {
		name, next, err := readWasmName(payload, pos)
		if err != nil {
			return false, false, fmt.Errorf("%w: Export 第 %d 项名称非法: %v", ErrInvalidWasm, i, err)
		}
		pos = next
		if pos >= len(payload) {
			return false, false, fmt.Errorf("%w: Export 第 %d 项缺少类型字节", ErrInvalidWasm, i)
		}
		kind := payload[pos]
		pos++
		if kind > wasmKindTag {
			return false, false, fmt.Errorf("%w: Export 第 %d 项未知导出类型 0x%02x", ErrInvalidWasm, i, kind)
		}
		if _, pos, err = readVarUint32(payload, pos); err != nil {
			return false, false, fmt.Errorf("%w: Export 第 %d 项索引非法: %v", ErrInvalidWasm, i, err)
		}
		if name == requiredExportFunc && kind == wasmKindFunc {
			hasOnRequestFunc = true
		}
		if name == requiredExportMemory && kind == wasmKindMemory {
			hasMemory = true
		}
	}
	if pos != len(payload) {
		return false, false, fmt.Errorf("%w: Export 节末尾存在未解析字节", ErrInvalidWasm)
	}
	return hasOnRequestFunc, hasMemory, nil
}

func isWASIModule(mod string) bool {
	lower := strings.ToLower(strings.TrimSpace(mod))
	return lower == "wasi" ||
		strings.HasPrefix(lower, "wasi_") ||
		strings.HasPrefix(lower, "wasi:")
}

func readVarUint32(data []byte, pos int) (uint32, int, error) {
	var result uint32
	for shift := uint(0); shift < 35; shift += 7 {
		if pos >= len(data) {
			return 0, pos, errors.New("unexpected EOF in LEB128")
		}
		b := data[pos]
		pos++
		if shift == 28 && (b&0xf0) != 0 {
			return 0, pos, errors.New("LEB128 uint32 overflow")
		}
		result |= uint32(b&0x7f) << shift
		if (b & 0x80) == 0 {
			return result, pos, nil
		}
	}
	return 0, pos, errors.New("LEB128 exceeds 5 bytes")
}

func readWasmName(data []byte, pos int) (string, int, error) {
	n, next, err := readVarUint32(data, pos)
	if err != nil {
		return "", pos, err
	}
	if uint64(n) > uint64(len(data)-next) {
		return "", next, errors.New("name length exceeds section bounds")
	}
	raw := data[next : next+int(n)]
	if !utf8.Valid(raw) {
		return "", next, errors.New("name is not valid UTF-8")
	}
	return string(raw), next + int(n), nil
}

func skipWasmLimits(data []byte, pos int) (int, error) {
	if pos >= len(data) {
		return pos, errors.New("limits flag truncated")
	}
	flags := data[pos]
	pos++
	if flags > 0x03 {
		return pos, fmt.Errorf("invalid limits flags 0x%02x", flags)
	}
	var err error
	if _, pos, err = readVarUint32(data, pos); err != nil {
		return pos, err
	}
	if (flags & 0x01) != 0 {
		if _, pos, err = readVarUint32(data, pos); err != nil {
			return pos, err
		}
	}
	return pos, nil
}
