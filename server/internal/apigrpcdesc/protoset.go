// Package apigrpcdesc gRPC 描述符集管理面（W14-DESC / P2-05 深化）：
// FileDescriptorSet（protoc --descriptor_set_out 产物）上传登记、列表、删除，
// 上传时解析服务/方法清单摘要（services jsonb）供管理面展示。
//
// server module 不持有 protobuf 库（go.mod 无此依赖，任务书约束不引入新第三方库），
// 故摘要解析为零依赖的 protobuf 线格式（wire format）结构读取：仅下钻
// FileDescriptorSet.file(1) → FileDescriptorProto.package(2)/service(6) →
// ServiceDescriptorProto.name(1)/method(2) → MethodDescriptorProto
// .name(1)/input_type(2)/output_type(3)/client_streaming(5)/server_streaming(6)，
// 未知字段按线型（varint/64bit/LEN/32bit）精确跳过。线格式损坏即如实报错拒绝上传；
// 语义级校验（类型引用可解析性）由网关装配期 protodesc 编译兜底（失败集 Warn 跳过，
// 对应服务降级为 v1 帧结构观测）。
package apigrpcdesc

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// ErrBadDescriptorSet FileDescriptorSet 线格式非法（上传拒绝，400）。
var ErrBadDescriptorSet = errors.New("invalid FileDescriptorSet")

// 摘要解析护栏（content 本身 ≤1MiB，护栏防摘要结构与名称膨胀）。
const (
	maxFiles             = 256 // FileDescriptorSet.file 条数上限
	maxServices          = 512 // 全文件服务合计上限
	maxMethodsPerService = 512 // 单服务方法数上限
	maxSummaryNameLen    = 256 // 服务/方法/类型名单项长度上限（字符）
)

// MethodSummary 方法摘要（对应 MethodDescriptorProto 关键字段）。
type MethodSummary struct {
	Name            string `json:"name"`
	InputType       string `json:"input_type"`       // 全限定类型名（前导点，如 .pkg.Req）
	OutputType      string `json:"output_type"`      // 全限定类型名（前导点）
	ClientStreaming bool   `json:"client_streaming"` // 客户端流式
	ServerStreaming bool   `json:"server_streaming"` // 服务端流式
}

// ServiceSummary 服务摘要（service 为 package.Service 全名，无包名时为裸服务名）。
type ServiceSummary struct {
	Service string          `json:"service"`
	Methods []MethodSummary `json:"methods"`
}

// wireReader protobuf 线格式读取器（只读游标；任何越界/截断即报错）。
type wireReader struct {
	buf []byte
	off int
}

func (r *wireReader) eof() bool { return r.off >= len(r.buf) }

// varint 读取变长整数（protobuf varint 至多 10 字节；溢出/截断报错）。
func (r *wireReader) varint() (uint64, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		if r.off >= len(r.buf) {
			return 0, ErrBadDescriptorSet
		}
		b := r.buf[r.off]
		r.off++
		if i == 9 && b > 1 {
			return 0, fmt.Errorf("%w: varint overflow", ErrBadDescriptorSet)
		}
		v |= uint64(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("%w: varint too long", ErrBadDescriptorSet)
}

// tag 读取字段标签：字段号（≥1）与线型（0/1/2/5；3/4 组线型已废弃，描述符 proto
// 不含组，遇之报错——不静默跳过无法精确界定边界的形态）。
func (r *wireReader) tag() (fieldNum, wireType int, err error) {
	v, err := r.varint()
	if err != nil {
		return 0, 0, err
	}
	fieldNum, wireType = int(v>>3), int(v&0x7)
	if fieldNum <= 0 {
		return 0, 0, fmt.Errorf("%w: zero field number", ErrBadDescriptorSet)
	}
	switch wireType {
	case 0, 1, 2, 5:
	default:
		return 0, 0, fmt.Errorf("%w: unsupported wire type %d", ErrBadDescriptorSet, wireType)
	}
	return fieldNum, wireType, nil
}

// bytes 读取 LEN 字段载荷（长度声明越界即报错，绝不截断容忍）。
func (r *wireReader) bytes() ([]byte, error) {
	n, err := r.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(r.buf)-r.off) {
		return nil, fmt.Errorf("%w: length exceeds remaining", ErrBadDescriptorSet)
	}
	out := r.buf[r.off : r.off+int(n)]
	r.off += int(n)
	return out, nil
}

// skip 按线型跳过一个未知字段（线型已经 tag() 校验为 0/1/2/5）。
func (r *wireReader) skip(wireType int) error {
	switch wireType {
	case 0: // varint
		_, err := r.varint()
		return err
	case 1: // 64-bit
		if len(r.buf)-r.off < 8 {
			return fmt.Errorf("%w: truncated fixed64", ErrBadDescriptorSet)
		}
		r.off += 8
		return nil
	case 2: // LEN
		_, err := r.bytes()
		return err
	case 5: // 32-bit
		if len(r.buf)-r.off < 4 {
			return fmt.Errorf("%w: truncated fixed32", ErrBadDescriptorSet)
		}
		r.off += 4
		return nil
	}
	return fmt.Errorf("%w: unsupported wire type %d", ErrBadDescriptorSet, wireType)
}

// summaryString 校验并返回摘要字符串（非空、合法 UTF-8、长度封顶；非法即报错拒绝，
// 摘要会入库 jsonb 并随展示面输出，不做字符集宽容）。
func summaryString(raw []byte, what string) (string, error) {
	s := string(raw)
	if s == "" {
		return "", fmt.Errorf("%w: empty %s", ErrBadDescriptorSet, what)
	}
	if !utf8.ValidString(s) {
		return "", fmt.Errorf("%w: %s not utf-8", ErrBadDescriptorSet, what)
	}
	if utf8.RuneCountInString(s) > maxSummaryNameLen {
		return "", fmt.Errorf("%w: %s too long", ErrBadDescriptorSet, what)
	}
	return s, nil
}

// ParseFileDescriptorSet 解析 FileDescriptorSet 字节，产出服务/方法清单摘要。
// 线格式结构非法（截断/长度越界/未知线型/非法名称）如实返回错误（调用方 400 拒绝上传）；
// 空文件集（无任何 file 条目）视为非法（无描述能力的空集无登记意义）。
// 仅做线格式结构校验，类型引用可解析性由网关装配期 protodesc 编译兜底。
func ParseFileDescriptorSet(content []byte) ([]ServiceSummary, error) {
	if len(content) == 0 {
		return nil, fmt.Errorf("%w: empty content", ErrBadDescriptorSet)
	}
	r := &wireReader{buf: content}
	services := []ServiceSummary{}
	files := 0
	for !r.eof() {
		fieldNum, wireType, err := r.tag()
		if err != nil {
			return nil, err
		}
		if fieldNum != 1 || wireType != 2 { // FileDescriptorSet.file 是唯一顶层重复字段
			if err := r.skip(wireType); err != nil {
				return nil, err
			}
			continue
		}
		raw, err := r.bytes()
		if err != nil {
			return nil, err
		}
		files++
		if files > maxFiles {
			return nil, fmt.Errorf("%w: too many files (%d)", ErrBadDescriptorSet, files)
		}
		fileServices, err := parseFileServices(raw)
		if err != nil {
			return nil, err
		}
		services = append(services, fileServices...)
		if len(services) > maxServices {
			return nil, fmt.Errorf("%w: too many services (%d)", ErrBadDescriptorSet, len(services))
		}
	}
	if files == 0 {
		return nil, fmt.Errorf("%w: no file entries", ErrBadDescriptorSet)
	}
	return services, nil
}

// parseFileServices 解析 FileDescriptorProto：package(2) 与 service(6)。
func parseFileServices(raw []byte) ([]ServiceSummary, error) {
	r := &wireReader{buf: raw}
	pkg := ""
	out := []ServiceSummary{}
	for !r.eof() {
		fieldNum, wireType, err := r.tag()
		if err != nil {
			return nil, err
		}
		switch {
		case fieldNum == 2 && wireType == 2: // package
			b, err := r.bytes()
			if err != nil {
				return nil, err
			}
			// 包名可为空（无包声明）；非空时校验长度与 UTF-8
			if len(b) > 0 {
				s, err := summaryString(b, "package name")
				if err != nil {
					return nil, err
				}
				pkg = s
			}
		case fieldNum == 6 && wireType == 2: // service
			b, err := r.bytes()
			if err != nil {
				return nil, err
			}
			svc, err := parseService(b, pkg)
			if err != nil {
				return nil, err
			}
			out = append(out, svc)
		default:
			if err := r.skip(wireType); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// parseService 解析 ServiceDescriptorProto：name(1) 与 method(2)。
func parseService(raw []byte, pkg string) (ServiceSummary, error) {
	r := &wireReader{buf: raw}
	svc := ServiceSummary{Methods: []MethodSummary{}}
	name := ""
	for !r.eof() {
		fieldNum, wireType, err := r.tag()
		if err != nil {
			return svc, err
		}
		switch {
		case fieldNum == 1 && wireType == 2: // name
			b, err := r.bytes()
			if err != nil {
				return svc, err
			}
			s, err := summaryString(b, "service name")
			if err != nil {
				return svc, err
			}
			name = s
		case fieldNum == 2 && wireType == 2: // method
			b, err := r.bytes()
			if err != nil {
				return svc, err
			}
			m, err := parseMethod(b)
			if err != nil {
				return svc, err
			}
			svc.Methods = append(svc.Methods, m)
			if len(svc.Methods) > maxMethodsPerService {
				return svc, fmt.Errorf("%w: too many methods in service", ErrBadDescriptorSet)
			}
		default:
			if err := r.skip(wireType); err != nil {
				return svc, err
			}
		}
	}
	if name == "" {
		return svc, fmt.Errorf("%w: service without name", ErrBadDescriptorSet)
	}
	if pkg != "" {
		svc.Service = pkg + "." + name
	} else {
		svc.Service = name
	}
	return svc, nil
}

// parseMethod 解析 MethodDescriptorProto：name(1)/input_type(2)/output_type(3)/
// client_streaming(5)/server_streaming(6)。input/output_type 缺省（理论上 protoc
// 产物恒有）按空串容忍——摘要是展示数据，运行时判定以网关编译产物为准。
func parseMethod(raw []byte) (MethodSummary, error) {
	r := &wireReader{buf: raw}
	m := MethodSummary{}
	for !r.eof() {
		fieldNum, wireType, err := r.tag()
		if err != nil {
			return m, err
		}
		switch {
		case fieldNum == 1 && wireType == 2: // name
			b, err := r.bytes()
			if err != nil {
				return m, err
			}
			s, err := summaryString(b, "method name")
			if err != nil {
				return m, err
			}
			m.Name = s
		case fieldNum == 2 && wireType == 2: // input_type
			b, err := r.bytes()
			if err != nil {
				return m, err
			}
			if len(b) > 0 {
				s, err := summaryString(b, "input type")
				if err != nil {
					return m, err
				}
				m.InputType = s
			}
		case fieldNum == 3 && wireType == 2: // output_type
			b, err := r.bytes()
			if err != nil {
				return m, err
			}
			if len(b) > 0 {
				s, err := summaryString(b, "output type")
				if err != nil {
					return m, err
				}
				m.OutputType = s
			}
		case fieldNum == 5 && wireType == 0: // client_streaming
			v, err := r.varint()
			if err != nil {
				return m, err
			}
			m.ClientStreaming = v != 0
		case fieldNum == 6 && wireType == 0: // server_streaming
			v, err := r.varint()
			if err != nil {
				return m, err
			}
			m.ServerStreaming = v != 0
		default:
			if err := r.skip(wireType); err != nil {
				return m, err
			}
		}
	}
	if m.Name == "" {
		return m, fmt.Errorf("%w: method without name", ErrBadDescriptorSet)
	}
	return m, nil
}
