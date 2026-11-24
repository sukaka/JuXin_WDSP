// spec_zip.go 多文件规范 ZIP 归档（.zip）安全解析。
// 安全基线：
//   - 100% 内存解压，绝不落盘、绝不访问宿主机文件系统；
//   - 抗 Zip 炸弹：文件数上限 256、单文件解压上限 16MiB、总解压上限 32MiB（io.LimitReader 强截断）；
//   - 抗 Zip Slip：拒绝绝对路径、.. 越界路径；
//   - 抗 SSRF / 外部引用：仅允许指向同一 ZIP 内文件的相对 $ref，任何 http(s)://、file://、// 或缺失/越界目标一律报 ErrSpecExternalRef；
//   - 抗引用循环/指数展开：active 集合判环 + 深度上限 32 + 节点预算 100000。
//
// 支持场景：
//   1. 多文件 OpenAPI 3 / Swagger 2.0 / AsyncAPI / JSON Schema（主文件通过相对 $ref 引用包内组件/路径文件）；
//   2. 多文件 Protobuf（多个 .proto 联合解析，支持跨文件查找请求 message 字段）；
//   3. 单规范文件打包（OpenAPI / Swagger / Postman / GraphQL / WSDL / XSD / RAML / APIB / HAR / Protobuf）。
package apisecurity

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

const (
	zipMaxEntries           = 256
	zipMaxTotalUncompressed = 32 << 20 // 32 MiB
	zipRefMaxDepth          = 32
)

var zipAllowedSpecExts = map[string]bool{
	".json": true, ".yaml": true, ".yml": true,
	".graphql": true, ".gql": true, ".graphqls": true, ".sdl": true,
	".proto": true, ".wsdl": true, ".xsd": true, ".xml": true,
	".raml": true, ".apib": true, ".har": true,
}

func isZipMagic(body []byte) bool {
	return len(body) >= 4 && body[0] == 'P' && body[1] == 'K' &&
		((body[2] == 0x03 && body[3] == 0x04) || (body[2] == 0x05 && body[3] == 0x06))
}

// parseSpecZip 内存解压并解析规范 ZIP 归档。
func parseSpecZip(body []byte) (string, map[string]any, []SpecOperation, error) {
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w: ZIP 归档损坏或格式错误: %v", ErrSpecInvalidZip, err)
	}
	if len(zr.File) == 0 {
		return "", nil, nil, fmt.Errorf("%w: ZIP 归档为空", ErrSpecInvalidZip)
	}

	files := map[string][]byte{}
	var paths []string
	var totalUncompressed int64
	entryCount := 0

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		clean, skip, err := sanitizeZipEntryPath(f.Name)
		if err != nil {
			return "", nil, nil, err
		}
		if skip {
			continue
		}
		entryCount++
		if entryCount > zipMaxEntries {
			return "", nil, nil, fmt.Errorf("%w: ZIP 内文件数超过上限 %d", ErrSpecTooComplex, zipMaxEntries)
		}
		// 仅保留受支持的规范扩展名（跳过 README/图片等无关附属文件，但仍统计预算防炸弹）
		ext := strings.ToLower(path.Ext(clean))
		if !zipAllowedSpecExts[ext] {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return "", nil, nil, fmt.Errorf("%w: 读取归档条目 %s 失败: %v", ErrSpecInvalidZip, clean, err)
		}
		remain := zipMaxTotalUncompressed - totalUncompressed
		limit := int64(specImportMaxBytes)
		if remain < limit {
			limit = remain
		}
		data, readErr := io.ReadAll(io.LimitReader(rc, limit+1))
		_ = rc.Close()
		if readErr != nil {
			return "", nil, nil, fmt.Errorf("%w: 解压归档条目 %s 失败: %v", ErrSpecInvalidZip, clean, readErr)
		}
		if int64(len(data)) > limit {
			return "", nil, nil, fmt.Errorf("%w: ZIP 解压体积超过安全上限（单文件 16MiB / 总计 32MiB）", ErrSpecTooLarge)
		}
		totalUncompressed += int64(len(data))
		files[clean] = data
		paths = append(paths, clean)
	}

	if len(paths) == 0 {
		return "", nil, nil, fmt.Errorf("%w: ZIP 归档中未找到受支持的规范文件", ErrSpecInvalidZip)
	}
	sort.Strings(paths)

	// 1. 优先识别 JSON/YAML 族主规范文档（支持包内相对 $ref 展开）
	if rootPath, rootDoc, found := findZipStructuredRoot(paths, files); found {
		resolver := &zipRefResolver{
			rootPath: rootPath,
			files:    files,
			cache:    map[string]any{rootPath: rootDoc},
			budget:   &yamlNodeBudget{remaining: specYAMLMaxNodes},
		}
		resolved, err := resolver.resolveNode(rootDoc, rootPath, 0, map[string]bool{rootPath + "#": true})
		if err != nil {
			return "", nil, nil, err
		}
		resolvedMap, ok := resolved.(map[string]any)
		if !ok {
			return "", nil, nil, fmt.Errorf("%w: 展开后的主文档非对象", ErrSpecInvalidZip)
		}
		return parseSpecJSONDoc(resolvedMap)
	}

	// 2. 多文件 .proto 归档：联合解析跨文件 message/service
	var protoPaths []string
	for _, p := range paths {
		if strings.EqualFold(path.Ext(p), ".proto") {
			protoPaths = append(protoPaths, p)
		}
	}
	if len(protoPaths) > 0 {
		sources := make([]string, 0, len(protoPaths))
		for _, p := range protoPaths {
			sources = append(sources, string(bytes.TrimPrefix(files[p], []byte{0xEF, 0xBB, 0xBF})))
		}
		ops, title, err := ParseProtobufSet(sources)
		if err != nil {
			return "", nil, nil, err
		}
		normalized := map[string]any{
			"x-wdsp-spec-format": SpecFormatProtobuf,
			"sources":            sources,
		}
		if title != "" {
			normalized["info"] = map[string]any{"title": title}
		}
		return SpecFormatProtobuf, normalized, ops, nil
	}

	// 3. 其余单文件规范（.raml/.graphql/.wsdl/.xsd/.xml/.apib/.har 等）：按目录层级由浅入深选取首个可解析文件
	ordered := append([]string{}, paths...)
	sort.SliceStable(ordered, func(i, j int) bool {
		di := strings.Count(ordered[i], "/")
		dj := strings.Count(ordered[j], "/")
		if di != dj {
			return di < dj
		}
		return ordered[i] < ordered[j]
	})
	var lastErr error
	for _, p := range ordered {
		format, norm, ops, err := ParseSpecContent(files[p])
		if err == nil {
			return format, norm, ops, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", nil, nil, lastErr
	}
	return "", nil, nil, fmt.Errorf("%w: 归档中无可解析的规范文档", ErrSpecInvalidZip)
}

func sanitizeZipEntryPath(raw string) (clean string, skip bool, err error) {
	if raw == "" {
		return "", true, nil
	}
	normalized := strings.ReplaceAll(raw, "\\", "/")
	if strings.HasPrefix(normalized, "/") || (len(normalized) >= 2 && normalized[1] == ':') {
		return "", false, fmt.Errorf("%w: 归档内包含非法绝对路径 %s", ErrSpecInvalidZip, truncateRefValue(raw))
	}
	for _, seg := range strings.Split(normalized, "/") {
		if seg == ".." {
			return "", false, fmt.Errorf("%w: 归档内包含路径穿越 %s", ErrSpecInvalidZip, truncateRefValue(raw))
		}
	}
	c := path.Clean(normalized)
	if c == "." || c == "" {
		return "", true, nil
	}
	// 忽略 macOS 打包元数据目录/隐藏资源文件
	if strings.HasPrefix(c, "__MACOSX/") || path.Base(c) == ".DS_Store" || strings.HasPrefix(path.Base(c), "._") {
		return "", true, nil
	}
	return c, false, nil
}

// findZipStructuredRoot 在 ZIP 的 JSON/YAML/HAR 文件中挑选主规范文档。
// 优先匹配含顶层 openapi/swagger/asyncapi/postman/har/jsonschema 的浅层文件及常见主文件名。
func findZipStructuredRoot(paths []string, files map[string][]byte) (string, map[string]any, bool) {
	type candidate struct {
		path  string
		doc   map[string]any
		score int
		depth int
	}
	var cands []candidate
	for _, p := range paths {
		ext := strings.ToLower(path.Ext(p))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" && ext != ".har" {
			continue
		}
		doc, err := decodeZipStructuredFile(files[p])
		if err != nil || doc == nil {
			continue
		}
		fmtID := detectExtendedSpecFormat(doc)
		if fmtID == "" {
			continue
		}
		score := 10
		switch fmtID {
		case SpecFormatOpenAPI3, SpecFormatSwagger2, SpecFormatAsyncAPI:
			score = 100
		case SpecFormatPostman, SpecFormatHAR:
			score = 80
		case SpecFormatJSONSchema:
			score = 40
		}
		base := strings.ToLower(strings.TrimSuffix(path.Base(p), ext))
		switch base {
		case "openapi", "swagger", "asyncapi", "api", "spec", "index", "main":
			score += 20
		}
		cands = append(cands, candidate{
			path:  p,
			doc:   doc,
			score: score,
			depth: strings.Count(p, "/"),
		})
	}
	if len(cands) == 0 {
		return "", nil, false
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].score != cands[j].score {
			return cands[i].score > cands[j].score
		}
		if cands[i].depth != cands[j].depth {
			return cands[i].depth < cands[j].depth
		}
		return cands[i].path < cands[j].path
	})
	return cands[0].path, cands[0].doc, true
}

func decodeZipStructuredFile(raw []byte) (map[string]any, error) {
	trimmed := bytes.TrimSpace(bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF}))
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%w: 空文档", ErrSpecUnsupportedFormat)
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		if jsonDepthExceeded(trimmed) {
			return nil, fmt.Errorf("%w: JSON 嵌套深度超过 %d", ErrSpecTooComplex, specJSONMaxDepth)
		}
		var doc map[string]any
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSpecInvalidJSON, err)
		}
		if doc == nil {
			return nil, fmt.Errorf("%w: 顶层必须为 JSON 对象", ErrSpecInvalidJSON)
		}
		return doc, nil
	}
	return decodeSpecYAML(trimmed)
}

type zipRefResolver struct {
	rootPath string
	files    map[string][]byte
	cache    map[string]any
	budget   *yamlNodeBudget
}

func (z *zipRefResolver) loadFile(targetPath string) (any, error) {
	if cached, ok := z.cache[targetPath]; ok {
		return cached, nil
	}
	raw, ok := z.files[targetPath]
	if !ok {
		return nil, fmt.Errorf("%w: ZIP 归档中找不到引用目标 %s", ErrSpecExternalRef, truncateRefValue(targetPath))
	}
	doc, err := decodeZipStructuredFile(raw)
	if err != nil {
		return nil, err
	}
	z.cache[targetPath] = doc
	return doc, nil
}

func (z *zipRefResolver) resolveNode(v any, curFile string, depth int, active map[string]bool) (any, error) {
	if depth > zipRefMaxDepth {
		return nil, fmt.Errorf("%w: ZIP 归档 $ref 展开深度超过 %d", ErrSpecTooComplex, zipRefMaxDepth)
	}
	if err := z.budget.spend(1); err != nil {
		return nil, err
	}
	switch node := v.(type) {
	case map[string]any:
		if refRaw, hasRef := node["$ref"]; hasRef {
			if ref, ok := refRaw.(string); ok {
				if !strings.HasPrefix(ref, "#") {
					return z.resolveRelativeRef(ref, curFile, depth, active)
				}
				// 被引用的子文件内部 JSON Pointer（#/...）需相对子文件本身展开，避免并入主文档后指针失效
				if curFile != z.rootPath && strings.HasPrefix(ref, "#/") {
					return z.resolveSameFileFragment(ref, curFile, depth, active)
				}
			}
		}
		out := make(map[string]any, len(node))
		for k, val := range node {
			rv, err := z.resolveNode(val, curFile, depth+1, active)
			if err != nil {
				return nil, err
			}
			out[k] = rv
		}
		return out, nil
	case []any:
		out := make([]any, len(node))
		for i, item := range node {
			rv, err := z.resolveNode(item, curFile, depth+1, active)
			if err != nil {
				return nil, err
			}
			out[i] = rv
		}
		return out, nil
	default:
		return v, nil
	}
}

func (z *zipRefResolver) resolveSameFileFragment(ref, curFile string, depth int, active map[string]bool) (any, error) {
	refKey := curFile + ref
	if active[refKey] {
		return nil, fmt.Errorf("%w: 检测到 $ref 循环引用 %s", ErrSpecTooComplex, truncateRefValue(refKey))
	}
	targetDoc, err := z.loadFile(curFile)
	if err != nil {
		return nil, err
	}
	targetVal := lookupJSONPointer(targetDoc, ref)
	if targetVal == nil {
		return nil, fmt.Errorf("%w: 引用片段不存在 %s", ErrSpecExternalRef, truncateRefValue(ref))
	}
	active[refKey] = true
	defer delete(active, refKey)
	return z.resolveNode(targetVal, curFile, depth+1, active)
}

func (z *zipRefResolver) resolveRelativeRef(ref, curFile string, depth int, active map[string]bool) (any, error) {
	// 严格禁止网络协议/协议相对/绝对路径外部引用
	lower := strings.ToLower(strings.TrimSpace(ref))
	if strings.HasPrefix(lower, "//") || strings.HasPrefix(lower, "/") || strings.Contains(lower, "://") || strings.HasPrefix(lower, "file:") {
		return nil, fmt.Errorf("%w: %s", ErrSpecExternalRef, truncateRefValue(ref))
	}
	filePart := ref
	fragPart := ""
	if idx := strings.IndexByte(ref, '#'); idx >= 0 {
		filePart = ref[:idx]
		fragPart = ref[idx:] // 保留 #...
	}
	filePart = strings.ReplaceAll(strings.TrimSpace(filePart), "\\", "/")
	if filePart == "" {
		return nil, fmt.Errorf("%w: %s", ErrSpecExternalRef, truncateRefValue(ref))
	}
	joined := path.Clean(path.Join(path.Dir(curFile), filePart))
	if joined == "." || joined == ".." || strings.HasPrefix(joined, "../") || strings.HasPrefix(joined, "/") {
		return nil, fmt.Errorf("%w: 引用越界 %s", ErrSpecExternalRef, truncateRefValue(ref))
	}
	refKey := joined + fragPart
	if active[refKey] {
		return nil, fmt.Errorf("%w: 检测到 $ref 循环引用 %s", ErrSpecTooComplex, truncateRefValue(refKey))
	}
	targetDoc, err := z.loadFile(joined)
	if err != nil {
		return nil, err
	}
	targetVal := targetDoc
	if fragPart != "" && fragPart != "#" && fragPart != "#/" {
		targetVal = lookupJSONPointer(targetDoc, fragPart)
		if targetVal == nil {
			return nil, fmt.Errorf("%w: 引用片段不存在 %s", ErrSpecExternalRef, truncateRefValue(ref))
		}
	}
	active[refKey] = true
	defer delete(active, refKey)
	return z.resolveNode(targetVal, joined, depth+1, active)
}
