// spec_source.go API 安全补全第十四波（W14-SRC 源码 API 发现 v1，P2-07）：
// SOURCE_CODE 学习来源接入的辅助逻辑（纯增量文件，不改既有导入流水线）。
//
// 背景：tools/apisrc 静态扫描 Go 源码路由注册（net/http ServeMux 方法模式、
// http.HandleFunc、chi/echo/gin 字面量方法路由），输出 OpenAPI 3.0.3 最小骨架：
//
//	{"source":"SOURCE_CODE","openapi":"3.0.3","info":{...},"paths":{...},"x-apisrc":{...}}
//
// 该文档被 ParseSpecDocument 天然识别为 openapi3（顶层 source/x-apisrc 扩展键
// 不影响解析），直接走现有导入流水线（粘贴/文件导入接口）即可完成接入。
//
// 来源落库说明：api_import_specs 现有列无 source 字段（迁移 000018 建表，
// 列含 format/file_name/content_hash/spec_json 等，000046 增补版本状态机列），
// 本波未分配迁移号，故 v1 保持 format=openapi3 不变，来源标记随文档落库 ——
// ImportSpecWithDiffs 原样存储 normalized 文档，顶层 "source":"SOURCE_CODE"
// 随之进入 spec_json，读取侧经 DetectSpecSource 还原（spec_json->>'source'）。
// 集成方如需一等方式的来源列，建议分配迁移：
//
//	ALTER TABLE api_import_specs ADD COLUMN source VARCHAR(32) NOT NULL DEFAULT 'UPLOAD';
//
// 并在 importSpecCore 落库前以 DetectSpecSource(specDoc) 取值
// （"" 时按入口记 UPLOAD / URL），写入该列。
package apisecurity

// 规范导入来源标记（api_import_specs 无独立来源列，v1 随 spec_json 顶层 source 键落库）。
const (
	// SpecSourceUpload 粘贴/文件上传导入（缺省来源）。
	SpecSourceUpload = "UPLOAD"
	// SpecSourceURL URL 拉取导入（ImportSpecURL 入口）。
	SpecSourceURL = "URL"
	// SpecSourceSourceCode 源码静态发现（tools/apisrc 产物）。
	SpecSourceSourceCode = "SOURCE_CODE"
)

// apisrcMetaKey apisrc 产物顶层的工具元数据扩展键（扫描目录/统计/解析错误，
// 含本机路径信息，导入落库前建议剥离，见 SourceCodeSpecForImport）。
const apisrcMetaKey = "x-apisrc"

// DetectSpecSource 识别导入文档来源：tools/apisrc 产物在顶层携带
// "source":"SOURCE_CODE" 时返回 SpecSourceSourceCode；其余文档返回 ""
// （由调用方按入口决定 UPLOAD / URL）。同样适用于读取侧从 spec_json 还原来源。
func DetectSpecSource(doc map[string]any) string {
	if v, _ := doc["source"].(string); v == SpecSourceSourceCode {
		return SpecSourceSourceCode
	}
	return ""
}

// SourceCodeSpecForImport 返回剥离 apisrc 工具元数据（x-apisrc：扫描目录为本机
// 路径、解析错误明细，属采集侧信息）后的文档副本，供导入落库：
// 顶层 source=SOURCE_CODE 标记保留（随 spec_json 落库作为来源标记），
// openapi/info/paths 原样保留。非 apisrc 产物（无 x-apisrc 键）原样返回入参。
// 不修改入参（返回新副本）。
func SourceCodeSpecForImport(doc map[string]any) map[string]any {
	if _, ok := doc[apisrcMetaKey]; !ok {
		return doc
	}
	out := make(map[string]any, len(doc))
	for k, v := range doc {
		if k == apisrcMetaKey {
			continue
		}
		out[k] = v
	}
	return out
}
