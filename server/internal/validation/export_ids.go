package validation

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
)

// MaxExportSelectedIDs 单次按勾选 ID 导出的最大条数。
// 200 个 UUID 在 query string 中约 7.4 KB，安全落在浏览器与反向代理常见 URL 长度上限内。
const MaxExportSelectedIDs = 200

// ParseExportUUIDs 解析并校验导出接口的 UUID 集合查询参数（支持逗号分隔与重复键）。
// - 未传该参数（!q.Has(key)）：返回 nil, nil，表示按普通筛选或全量导出。
// - 已传该参数但为空（如 ?ids= 或 ?ids=,,）：返回错误，防止前端误传空值时意外退化为全量导出。
// - 包含非法 UUID 或超过 MaxExportSelectedIDs：返回明确错误。
// - 自动去重并保持输入顺序。
func ParseExportUUIDs(q url.Values, key string) ([]uuid.UUID, error) {
	if !q.Has(key) {
		return nil, nil
	}
	rawValues := q[key]
	seen := make(map[uuid.UUID]struct{})
	out := make([]uuid.UUID, 0, len(rawValues))
	for _, raw := range rawValues {
		for _, part := range strings.Split(raw, ",") {
			token := strings.TrimSpace(part)
			if token == "" {
				continue
			}
			id, err := uuid.Parse(token)
			if err != nil {
				return nil, fmt.Errorf("无效的 %s 参数：包含非法 UUID", key)
			}
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			if len(out) >= MaxExportSelectedIDs {
				return nil, fmt.Errorf("单次最多选择导出 %d 条记录", MaxExportSelectedIDs)
			}
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s 不能为空", key)
	}
	return out, nil
}
