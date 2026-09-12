// Package grpcdesc gRPC 描述符注册表（W14-DESC / P2-05 深化，任务书描述符驱动
// 字段级解析 v1）：装配期把发布通道下发的 FileDescriptorSet 编译为动态消息注册表
// （protodesc.NewFiles + dynamicpb），请求期按 :path 的 /package.Service/Method
// 查找方法描述符并解码请求消息（frames[0]，仅未压缩帧），供字段级观测。
//
// 纪律：
//   - 注册表装配后只读（protoreflect 描述符不可变），请求期并发安全；
//   - 每集独立 protodesc.NewFiles 编译：依赖须在集内自闭合
//     （protoc --descriptor_set_out --include_imports 标准产物）；
//   - 单集编译失败如实返回带集名的错误，由装配方决定拒绝或 Warn 跳过
//     （jiuzhang_guard 采用 Warn 跳过：描述符解析为增量观测能力，
//     失败集对应服务降级为 v1 帧结构观测，不拖垮整体防护配置）；
//   - 解码输入为帧校验通过的完整首帧（≤ MaxGRPCFrameBytes，默认 4MiB，
//     与单消息解码上限一致）；解码产物仅在请求内存活，绝不写入事件/日志。
package grpcdesc

import (
	"encoding/base64"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Set 发布通道下发的描述符集（api_grpc_descriptors 数组项；键名为跨分片契约）。
type Set struct {
	Name          string `json:"name"`
	ContentBase64 string `json:"content_base64"`
}

// 装配护栏（与管理面上传护栏同源：单集 ≤1MiB；条数防误配膨胀）。
const (
	// MaxSetBytes 单集解码后字节上限（与管理面 1MiB 上传护栏一致，装配期复核）。
	MaxSetBytes = 1 << 20
	// MaxSets 描述符集条数上限。
	MaxSets = 64
	// maxNameLen 集名长度上限（名称进观测证据 descriptor 字段）。
	maxNameLen = 128
)

// Registry 描述符注册表（装配期编译产物；只读，请求期并发安全）。
type Registry struct {
	methods map[string]methodEntry // "package.Service/Method" → 方法描述符
	sets    int
}

type methodEntry struct {
	md      protoreflect.MethodDescriptor
	setName string
}

// NewRegistry 创建空注册表（AddSet 逐集追加）。
func NewRegistry() *Registry {
	return &Registry{methods: map[string]methodEntry{}}
}

// Sets 已登记描述符集数（装配日志观测）。
func (r *Registry) Sets() int { return r.sets }

// Methods 已索引方法数（装配日志观测）。
func (r *Registry) Methods() int { return len(r.methods) }

// AddSet 编译并登记一个描述符集：集名/体量护栏复核 → base64 解码 →
// FileDescriptorSet 反序列化 → protodesc.NewFiles 语义编译（依赖图与类型引用校验，
// 依赖须集内自闭合）→ 全部服务方法入索引。
// 跨集同名方法（package.Service/Method 全限定名冲突）：后登记集覆盖先登记集
// （管理面按集名唯一，跨集重名属配置意图，后者生效）。
func (r *Registry) AddSet(name, contentBase64 string) error {
	if name == "" || len(name) > maxNameLen {
		return fmt.Errorf("grpc descriptor set: bad name (empty or > %d chars)", maxNameLen)
	}
	if r.sets >= MaxSets {
		return fmt.Errorf("grpc descriptor set %q: too many sets (%d > %d)", name, r.sets+1, MaxSets)
	}
	raw, err := base64.StdEncoding.DecodeString(contentBase64)
	if err != nil {
		return fmt.Errorf("grpc descriptor set %q: bad base64: %w", name, err)
	}
	if len(raw) == 0 || len(raw) > MaxSetBytes {
		return fmt.Errorf("grpc descriptor set %q: content size %d out of range (1..%d)", name, len(raw), MaxSetBytes)
	}
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(raw, fds); err != nil {
		return fmt.Errorf("grpc descriptor set %q: bad FileDescriptorSet: %w", name, err)
	}
	files, err := protodesc.NewFiles(fds)
	if err != nil {
		return fmt.Errorf("grpc descriptor set %q: compile failed: %w", name, err)
	}
	// 全量服务方法入索引（遍历已编译文件注册表）
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			ms := svc.Methods()
			for j := 0; j < ms.Len(); j++ {
				m := ms.Get(j)
				key := string(svc.FullName()) + "/" + string(m.Name())
				r.methods[key] = methodEntry{md: m, setName: name}
			}
		}
		return true
	})
	r.sets++
	return nil
}

// Lookup 按 :path 段查找方法描述符（service 为 package.Service 全名，与分类器
// 拆分口径一致）；返回方法描述符与所属描述符集名。
func (r *Registry) Lookup(service, method string) (protoreflect.MethodDescriptor, string, bool) {
	if r == nil {
		return nil, "", false
	}
	e, ok := r.methods[service+"/"+method]
	if !ok {
		return nil, "", false
	}
	return e.md, e.setName, true
}

// DecodeRequest 用方法描述符解码请求消息（dynamicpb 动态消息）。
// msg 须为帧校验通过的完整未压缩帧载荷（≤ MaxGRPCFrameBytes）；线格式损坏
// （非法 varint/长度越界/未知线型）如实返回错误，由调用方降级为 v1 观测不报错。
func DecodeRequest(md protoreflect.MethodDescriptor, msg []byte) (*dynamicpb.Message, error) {
	m := dynamicpb.NewMessage(md.Input())
	if err := proto.Unmarshal(msg, m); err != nil {
		return nil, err
	}
	return m, nil
}

// StringField 一次 string 字段访问（Path 为 proto 字段名点路径，嵌套消息以 . 连接）。
type StringField struct {
	Path  string
	Value string
}

// WalkStringFields 遍历动态消息，产出 string 字段（proto 字段名点路径）与重复字段计数。
// 护栏：maxDepth 嵌套深度上限（group/消息递归，防深嵌套放大）、maxFields 产出字段数
// 上限（防超大消息撑爆求值预算）；重复字段（含 map）只统计不展开求值（任务书口径）。
// 字段路径取 proto 字段名（fd.Name，描述符 canonical 名；json_name 同属可选项，
// v1 固定取字段名，与 protoset 展示一致）。
func WalkStringFields(m protoreflect.Message, maxDepth, maxFields int) (fields []StringField, repeated int) {
	if maxDepth <= 0 || maxFields <= 0 {
		return nil, 0
	}
	fields = []StringField{}
	walkMessage(m, "", 0, maxDepth, maxFields, &fields, &repeated)
	return fields, repeated
}

// walkMessage 递归遍历：singular string 产出；singular message/group 递归；
// repeated（list/map）只计数。fields 达 maxFields 即停止（预算耗尽）。
func walkMessage(m protoreflect.Message, prefix string, depth, maxDepth, maxFields int, fields *[]StringField, repeated *int) {
	if depth >= maxDepth || len(*fields) >= maxFields {
		return
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if len(*fields) >= maxFields {
			return false
		}
		path := string(fd.Name())
		if prefix != "" {
			path = prefix + "." + path
		}
		switch {
		case fd.IsList() || fd.IsMap():
			// 重复字段只统计（map 亦为 repeated entry 形态）
			*repeated++
		case fd.Kind() == protoreflect.StringKind:
			*fields = append(*fields, StringField{Path: path, Value: v.String()})
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			walkMessage(v.Message(), path, depth+1, maxDepth, maxFields, fields, repeated)
		}
		return true
	})
}
