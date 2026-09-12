// segments.go api_endpoint_path_segments 生产写入方（W16-TABLES）。
//
// 端点 normalized_path 的段形画像：发现链路（UpsertDiscovery 首插）与拆分（Split）
// 派生写入，ON CONFLICT 不覆盖（首插/回填/重放均幂等）。一致性按简单方案处理：
//   - normalized_path 是端点身份键（endpoint_key）的一部分、行内不可变，
//     段形只需在端点行创建时派生一次；
//   - 合并（Merge）删除对方端点行 → 段形随 ON DELETE CASCADE 清除；旧键事件
//     再到达时按发现链路重新建行并重新派生段形；
//   - 存量端点由迁移 000073 一次性回填（同口径 SQL）。
//
// 段位置为去前导斜杠后的 0 起序号，与 apiauthz 对象模型 object_segment
// "path:<pos>" 同口径。段型不落独立列：静态段 literal_value=原文；{name} 占位段
// is_variable=TRUE、variable_name=name（normalizer 产出 id/uuid/hex，即段型
// INTEGER/UUID/HEX；其他自定义占位名亦为变量段）。sample_hashes 留默认 []：
// 发现链路只见模板不见观测值，样本哈希待运行时链路补充。
package apiassets

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// 段列宽上限（对齐迁移 000018 列定义；超长防御性截断）。
const (
	maxSegmentLiteral = 255
	maxSegmentName    = 128
)

// PathSegment 端点路径段形（api_endpoint_path_segments）。
type PathSegment struct {
	EndpointID   uuid.UUID `json:"endpoint_id"`
	Position     int       `json:"position"`
	LiteralValue string    `json:"literal_value"` // 静态段原文（变量段为空）
	IsVariable   bool      `json:"is_variable"`
	VariableName string    `json:"variable_name"` // 占位符名（id/uuid/hex ↔ 段型 INTEGER/UUID/HEX）
}

// isVariableSegment 段是否为 {name} 占位形态（与 apiauthz isPlaceholder 同判据）。
func isVariableSegment(seg string) bool {
	return len(seg) >= 3 && strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}")
}

// derivePathSegments 把 normalized_path 拆成段形（纯函数）。
//
// 位置为去掉一个前导斜杠后的段序号（0 起）：/v1/users/{id} → v1@0、users@1、{id}@2；
// 根路径（/ 或空）无段。退化空段按静态空串保留，保证位置与模板逐段对齐一致
// （正常 normalized_path 经 normalizer 处理无空段）。
func derivePathSegments(normalizedPath string) []PathSegment {
	body := strings.TrimPrefix(normalizedPath, "/")
	if body == "" {
		return nil
	}
	parts := strings.Split(body, "/")
	out := make([]PathSegment, 0, len(parts))
	for i, seg := range parts {
		ps := PathSegment{Position: i}
		if isVariableSegment(seg) {
			name := seg[1 : len(seg)-1]
			if len(name) > maxSegmentName {
				name = name[:maxSegmentName]
			}
			ps.IsVariable = true
			ps.VariableName = name
		} else {
			if len(seg) > maxSegmentLiteral {
				seg = seg[:maxSegmentLiteral]
			}
			ps.LiteralValue = seg
		}
		out = append(out, ps)
	}
	return out
}

// withEndpointID 填充段形的端点归属（派生时位置/内容已定，归属后补；内存仓储用）。
func withEndpointID(segs []PathSegment, id uuid.UUID) []PathSegment {
	for i := range segs {
		segs[i].EndpointID = id
	}
	return segs
}

// upsertPathSegments 在事务内写入端点段形（ON CONFLICT 不覆盖：段形随
// normalized_path 不可变，重写无意义；调用方保证端点行同事务可见）。
// 句柄为 DBTX（W22 抽象）：自管理事务路径传 pgx.Tx，采集器批次事务路径传批次事务。
func upsertPathSegments(ctx context.Context, q DBTX, endpointID uuid.UUID, normalizedPath string) error {
	for _, seg := range derivePathSegments(normalizedPath) {
		if _, err := q.Exec(ctx, `
INSERT INTO api_endpoint_path_segments (endpoint_id, position, literal_value, is_variable, variable_name)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (endpoint_id, position) DO NOTHING`,
			endpointID, seg.Position, seg.LiteralValue, seg.IsVariable, seg.VariableName); err != nil {
			return fmt.Errorf("upsert path segment: %w", err)
		}
	}
	return nil
}

// ListPathSegments 读取端点段形（按位置升序；无段返回空切片）。
// 未挂入 Repository 接口：当前无消费方，供生产方验证与后续只读接口复用。
func (s *Store) ListPathSegments(ctx context.Context, endpointID uuid.UUID) ([]PathSegment, error) {
	rows, err := s.db.Query(ctx, `
SELECT endpoint_id, position, literal_value, is_variable, variable_name
FROM api_endpoint_path_segments WHERE endpoint_id = $1 ORDER BY position ASC`, endpointID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PathSegment{}
	for rows.Next() {
		var ps PathSegment
		if err := rows.Scan(&ps.EndpointID, &ps.Position, &ps.LiteralValue, &ps.IsVariable, &ps.VariableName); err != nil {
			return nil, err
		}
		out = append(out, ps)
	}
	return out, rows.Err()
}
