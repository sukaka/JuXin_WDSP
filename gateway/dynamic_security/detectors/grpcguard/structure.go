// structure.go gRPC 消息结构校验（NG-GRPC §1.4/D4 首期检查集，dynamicpb
// 解码产物只读遍历——不重序列化正常请求，解析即弃）：
//
//   - 嵌套深度 ≤8（与现状 walk 深度冻结同源）；
//   - repeated 元素数 ≤1024/字段；map 条目数 ≤1024/字段；
//   - 消息遍历产出字段数 ≤256（防超大消息撑爆求值预算——与现状 256 常量冻结复用）；
//   - string/bytes 字段长度 ≤256KiB/字段（结构预算——与值级规则求值截断 256
//     字符不同层：结构超长本身即违规事实，§11.2-4 教训）；
//   - 枚举值域：值不在描述符枚举域 → enum_out_of_range；
//   - oneof 语义：dynamicpb 解码天然保证单值（解码期异常即 decode_error，不另立违规）；
//   - 未知字段：容许并计数（proto3 前瞻兼容正常形态，不作违规——感知但不惩罚，
//     计数进观测证据 unknown_fields）；
//   - 不做 required 缺失判定（proto3 语义外）；默认值不误当缺失。
//
// 证据纪律：字段路径（proto 名点路径）+规则名+读取量，不落值。
package grpcguard

import (
	"strconv"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// 结构预算冻结值（§1.4）。
const (
	MaxStructureDepth       = 8         // 嵌套深度上限
	MaxRepeatedElements     = 1024      // repeated 元素数/字段上限
	MaxMapEntries           = 1024      // map 条目数/字段上限
	MaxWalkFields           = 256       // 遍历产出字段数上限
	MaxStringBytesLen       = 256 << 10 // string/bytes 字段长度上限（256KiB）
	maxStructureViolations  = 32        // 违规收集上限（防报告膨胀；超出截断计数）
	maxUnknownFieldsCounted = 1024      // 未知字段计数上限（计数预算）
)

// Violation 一条结构违规（证据三元：规则/路径/读取量——不落值）。
type Violation struct {
	Rule string // depth_exceeded/repeated_exceeded/map_exceeded/field_count_exceeded/string_bytes_exceeded/enum_out_of_range
	Path string // proto 字段名点路径
	Read string // 读取量（越界计数/长度/枚举值）
}

// CheckStructure 结构校验主入口：遍历动态消息产出违规集合与未知字段计数
// （解析即弃，遍历只读）。违规收集达上限即停止遍历（剩余以合计摘要呈现）。
func CheckStructure(m protoreflect.Message) ([]Violation, int) {
	if m == nil {
		return nil, 0
	}
	w := &structureWalker{}
	w.walk(m, "", 1)
	return w.violations, w.unknownFields
}

// structureWalker 遍历状态（单请求单 goroutine 使用）。
type structureWalker struct {
	violations    []Violation
	unknownFields int
	fields        int // 遍历产出字段计数（MaxWalkFields 预算）
	stopped       bool
}

// add 违规记账（达上限置停止位）。
func (w *structureWalker) add(rule, path, read string) {
	if len(w.violations) >= maxStructureViolations {
		w.stopped = true
		return
	}
	w.violations = append(w.violations, Violation{Rule: rule, Path: path, Read: read})
}

// walk 递归遍历（depth 从 1 起：顶层消息字段为深度 1）。
func (w *structureWalker) walk(m protoreflect.Message, prefix string, depth int) {
	if w.stopped || m == nil {
		return
	}
	if depth > MaxStructureDepth {
		w.add("depth_exceeded", prefix, strconv.Itoa(depth))
		return
	}
	// 未知字段容许计数（感知但不惩罚；proto3 前瞻兼容正常形态）
	w.unknownFields += countUnknownFields(m.GetUnknown(), maxUnknownFieldsCounted-w.unknownFields)
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if w.stopped {
			return false
		}
		w.fields++
		if w.fields > MaxWalkFields {
			w.add("field_count_exceeded", prefix, strconv.Itoa(w.fields))
			w.stopped = true
			return false
		}
		path := string(fd.Name())
		if prefix != "" {
			path = prefix + "." + path
		}
		w.checkField(fd, v, path, depth)
		return !w.stopped
	})
}

// checkField 单字段检查（repeated/map/标量分派）。
func (w *structureWalker) checkField(fd protoreflect.FieldDescriptor, v protoreflect.Value, path string, depth int) {
	switch {
	case fd.IsMap():
		mp := v.Map()
		if mp.Len() > MaxMapEntries {
			w.add("map_exceeded", path, strconv.Itoa(mp.Len()))
		}
		// map 值消息递归（键标量不查长度——键受 1024 条目预算约束）；
		// map 键/值枚举的逐条值域校验列为后续增强点（本批不判，如实标注）
		if fd.MapValue().Kind() == protoreflect.MessageKind || fd.MapValue().Kind() == protoreflect.GroupKind {
			mp.Range(func(_ protoreflect.MapKey, val protoreflect.Value) bool {
				w.fields++
				if w.fields > MaxWalkFields {
					w.add("field_count_exceeded", path, strconv.Itoa(w.fields))
					w.stopped = true
					return false
				}
				w.walk(val.Message(), path, depth+1)
				return !w.stopped
			})
		}
	case fd.IsList():
		l := v.List()
		if l.Len() > MaxRepeatedElements {
			w.add("repeated_exceeded", path, strconv.Itoa(l.Len()))
		}
		isMsg := fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind
		for i := 0; i < l.Len(); i++ {
			if w.stopped {
				return
			}
			// 元素计入遍历产出预算（工作预算即「遍历产出字段数」承载）
			w.fields++
			if w.fields > MaxWalkFields {
				w.add("field_count_exceeded", path, strconv.Itoa(w.fields))
				w.stopped = true
				return
			}
			if isMsg {
				w.walk(l.Get(i).Message(), path, depth+1)
			} else {
				w.checkScalar(fd, l.Get(i), path)
			}
		}
	default:
		if fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind {
			w.walk(v.Message(), path, depth+1)
			return
		}
		w.checkScalar(fd, v, path)
	}
}

// checkScalar 标量字段检查（string/bytes 长度预算 + 枚举值域）。
func (w *structureWalker) checkScalar(fd protoreflect.FieldDescriptor, v protoreflect.Value, path string) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		if l := len(v.String()); l > MaxStringBytesLen {
			w.add("string_bytes_exceeded", path, strconv.Itoa(l))
		}
	case protoreflect.BytesKind:
		if l := len(v.Bytes()); l > MaxStringBytesLen {
			w.add("string_bytes_exceeded", path, strconv.Itoa(l))
		}
	case protoreflect.EnumKind:
		w.checkEnumValues(fd, &v, path)
	}
}

// checkEnumValues 枚举值域检查（值不在描述符枚举域即违规；v 为 nil 时跳过
// ——map 值枚举逐条在调用侧处理，本批 map 值枚举不做逐条值域校验并如实
// 标注为后续增强点，map 键/标量/repeated 枚举全量覆盖）。
func (w *structureWalker) checkEnumValues(fd protoreflect.FieldDescriptor, v *protoreflect.Value, path string) {
	if fd.Kind() != protoreflect.EnumKind || v == nil {
		return
	}
	num := v.Enum()
	if fd.Enum().Values().ByNumber(num) == nil {
		w.add("enum_out_of_range", path, strconv.Itoa(int(num)))
	}
}

// countUnknownFields 未知字段计数（wire 级 ConsumeField 逐字段步进；
// budget 为剩余计数预算，耗尽即停——计数不精确不惩罚语义）。
func countUnknownFields(raw protoreflect.RawFields, budget int) int {
	if budget <= 0 {
		return 0
	}
	n := 0
	for len(raw) > 0 && n < budget {
		_, _, l := protowire.ConsumeField(raw)
		if l <= 0 {
			break
		}
		raw = raw[l:]
		n++
	}
	return n
}
