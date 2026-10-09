// bindings.go gRPC 描述符 per-app 绑定（NG-GRPC G1 批次 B1，设计
// docs/nextgen/NG-GRPC-g1-unary.md §1.3/§1.9 D3/D9）：应用 × 服务（pkg.Service）×
// 描述符集（引用 000076 集名）× 模式。
//
// 语义边界（设计冻结）：
//   - 空绑定 = 全局可见（000076 ENABLED 集全局注册表语义不变）；
//   - 应用存在任一绑定行时该应用深检只用其绑定集——同名服务跨应用隔离
//     （不错配描述符解错消息）；同（应用,服务）恰一条绑定（唯一索引）；
//   - mode OBSERVE（缺省只记录）| PROTECT（字段结构违规按设计 §1.6 协议化执行）；
//   - 描述符集删除级联删绑定（FK 到 name）；应用删除级联；
//   - 未登记服务清单（D3 红线管理面可见性）：流量观测到（api_endpoints
//     protocol_type='GRPC'）但（按绑定语义）未覆盖描述符的 service/method 差集——
//     绑定应用按其绑定集判定、无绑定应用按全局 ENABLED 集判定。
package apigrpcdesc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// 绑定词表与护栏（设计冻结）。
const (
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	maxServiceLen = 256
)

// servicePattern pkg.Service 形态（批次 C 词表裁决（B1 偏差闭环）：对齐 protobuf
// 标识符实际规则——包段小写 snake（[a-z][a-z0-9_]*）、服务名允许大写驼峰
// （[A-Za-z][A-Za-z0-9_]*，真实世界主流形态 echo.EchoService）；收紧项保留：
// 禁空白/禁斜杠以外分隔/禁空段/长度上限（与迁移 000180 CHECK 同式）。
var servicePattern = regexp.MustCompile(`^([a-z][a-z0-9_]*\.)*[A-Za-z][A-Za-z0-9_]*$`)

// 绑定错误哨兵（handler 映射 400/404/409 精确区分）。
var (
	ErrBindingNotFound        = errors.New("grpc binding not found")
	ErrBindingDuplicate       = errors.New("grpc binding already exists for (application, service)")
	ErrDescriptorNotFound     = errors.New("referenced grpc descriptor set not found")
	ErrApplicationNotFound    = errors.New("referenced application not found")
	ErrBindingVersionConflict = errors.New("grpc binding version conflict（乐观锁不匹配，请刷新后重试）")
)

// BindingInput 绑定写入载荷（Create/Update 共用；Update 仅 mode/descriptor_name 生效——
// 应用与服务为绑定身份维度不可改（改即删建，审计链清晰））。
type BindingInput struct {
	ApplicationID  string `json:"application_id"`
	Service        string `json:"service"`
	DescriptorName string `json:"descriptor_name"`
	Mode           string `json:"mode"`
	Version        int    `json:"version"`
}

// Binding 绑定行（读模型）。
type Binding struct {
	ID             uuid.UUID `json:"id"`
	ApplicationID  uuid.UUID `json:"application_id"`
	Service        string    `json:"service"`
	DescriptorName string    `json:"descriptor_name"`
	Mode           string    `json:"mode"`
	Version        int       `json:"version"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// UndocumentedService 未登记服务（按应用分桶）。
type UndocumentedService struct {
	ApplicationID uuid.UUID `json:"application_id"`
	Service       string    `json:"service"`
	Methods       []string  `json:"methods"`
}

// ValidateBindingInput 载荷边界校验（形态/词表——存在性由 FK 与预查双层兜底，
// FK 冲突映射友好 400 不暴露 SQL 原文）。
func ValidateBindingInput(in BindingInput) string {
	if _, err := uuid.Parse(strings.TrimSpace(in.ApplicationID)); err != nil {
		return "application_id 非法（UUID）"
	}
	svc := strings.TrimSpace(in.Service)
	if svc == "" || len(svc) > maxServiceLen || !servicePattern.MatchString(svc) {
		return "service 非法（pkg.Service 点路径形态，≤256 字符）"
	}
	if strings.TrimSpace(in.DescriptorName) == "" || len(strings.TrimSpace(in.DescriptorName)) > maxNameLen {
		return "descriptor_name 必填（≤128 字符）"
	}
	switch strings.ToUpper(strings.TrimSpace(in.Mode)) {
	case "", ModeObserve, ModeProtect:
	default:
		return "mode 非法（OBSERVE|PROTECT，缺省 OBSERVE）"
	}
	return ""
}

// BindingRepository 绑定仓储接口（pgx 实现见 Store；单测注入内存 fake）。
type BindingRepository interface {
	CreateBinding(ctx context.Context, in BindingInput, createdBy string) (*Binding, error)
	ListBindings(ctx context.Context, applicationID uuid.UUID) ([]Binding, error)
	UpdateBinding(ctx context.Context, id uuid.UUID, in BindingInput) (*Binding, error)
	DeleteBinding(ctx context.Context, id uuid.UUID) error
	ListUndocumentedServices(ctx context.Context) ([]UndocumentedService, error)
}

// bindingCols 绑定读列（稳定列序）。
const bindingCols = `id, application_id, service, descriptor_name, mode, version, COALESCE(created_by,''), created_at, updated_at`

func scanBinding(row pgx.Row) (Binding, error) {
	var b Binding
	err := row.Scan(&b.ID, &b.ApplicationID, &b.Service, &b.DescriptorName, &b.Mode,
		&b.Version, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

// fkViolationToErr PG FK 违犯 → 友好哨兵（23503；descriptor_name/application_id 分辨靠约束名）。
func fkViolationToErr(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23503" {
		if strings.Contains(pe.ConstraintName, "descriptor_name") {
			return ErrDescriptorNotFound
		}
		return ErrApplicationNotFound
	}
	return err
}

// CreateBinding 创建绑定（同（应用,服务）409——唯一索引兜底非 TOCTOU 预查；mode 缺省 OBSERVE）。
func (s *Store) CreateBinding(ctx context.Context, in BindingInput, createdBy string) (*Binding, error) {
	mode := strings.ToUpper(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = ModeObserve
	}
	appID, _ := uuid.Parse(strings.TrimSpace(in.ApplicationID))
	b := &Binding{}
	err := s.db.QueryRow(ctx, `INSERT INTO api_grpc_bindings
		(application_id, service, descriptor_name, mode, created_by)
		VALUES ($1,$2,$3,$4,$5) RETURNING `+bindingCols,
		appID, strings.TrimSpace(in.Service), strings.TrimSpace(in.DescriptorName), mode, createdBy).Scan(
		&b.ID, &b.ApplicationID, &b.Service, &b.DescriptorName, &b.Mode, &b.Version, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23505" {
			return nil, ErrBindingDuplicate
		}
		return nil, fkViolationToErr(err)
	}
	return b, nil
}

// ListBindings 绑定列表（application_id 可选过滤；应用+服务稳定排序）。
func (s *Store) ListBindings(ctx context.Context, applicationID uuid.UUID) ([]Binding, error) {
	cond, args := "", []any{}
	if applicationID != uuid.Nil {
		args = append(args, applicationID)
		cond = " WHERE application_id = $1"
	}
	rows, err := s.db.Query(ctx, `SELECT `+bindingCols+` FROM api_grpc_bindings`+cond+
		` ORDER BY application_id, service`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// UpdateBinding 更新绑定（仅 mode/descriptor_name；version 乐观锁不匹配 ErrBindingVersionConflict）。
func (s *Store) UpdateBinding(ctx context.Context, id uuid.UUID, in BindingInput) (*Binding, error) {
	mode := strings.ToUpper(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = ModeObserve
	}
	b := &Binding{}
	err := s.db.QueryRow(ctx, `UPDATE api_grpc_bindings SET descriptor_name=$2, mode=$3,
		version=version+1, updated_at=now() WHERE id=$1 AND version=$4
		RETURNING `+bindingCols,
		id, strings.TrimSpace(in.DescriptorName), mode, in.Version).Scan(
		&b.ID, &b.ApplicationID, &b.Service, &b.DescriptorName, &b.Mode, &b.Version, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// 不存在与版本冲突分辨（精确消息；不存在 404，版本冲突 409）
		var exists bool
		if err2 := s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_grpc_bindings WHERE id=$1)`, id).Scan(&exists); err2 != nil {
			return nil, err2
		}
		if !exists {
			return nil, ErrBindingNotFound
		}
		return nil, ErrBindingVersionConflict
	}
	if err != nil {
		return nil, fkViolationToErr(err)
	}
	return b, nil
}

// DeleteBinding 删除绑定（不存在 ErrBindingNotFound）。
func (s *Store) DeleteBinding(ctx context.Context, id uuid.UUID) error {
	ct, err := s.db.Exec(ctx, `DELETE FROM api_grpc_bindings WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrBindingNotFound
	}
	return nil
}

// ListUndocumentedServices 未登记服务差集（D3 红线管理面可见性）：
// api_endpoints protocol_type='GRPC' 的（应用,service,method）全集，
// 按绑定语义判定登记——绑定应用：service 须在其绑定集（descriptor_name 对应集的
// services 摘要）方法集内；无绑定应用：service.method 在任一全局 ENABLED 集方法集内。
// 输出按应用+服务分桶（methods 稳定排序）。
func (s *Store) ListUndocumentedServices(ctx context.Context) ([]UndocumentedService, error) {
	// 1) 全局 ENABLED 集的 service→methods 与方法集（解析 services JSONB 摘要）
	type svcMethods map[string]map[string]bool
	globalSets := map[string]svcMethods{} // descriptor_name → service → methods
	globalCovered := svcMethods{}         // 全局 ENABLED 并集
	rows, err := s.db.Query(ctx, `SELECT name, services FROM api_grpc_descriptors WHERE status='ENABLED' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var raw []byte
		if err := rows.Scan(&name, &raw); err != nil {
			return nil, err
		}
		var summaries []ServiceSummary
		if err := json.Unmarshal(raw, &summaries); err != nil {
			return nil, fmt.Errorf("decode services summary of %s: %w", name, err)
		}
		sm := svcMethods{}
		for _, svc := range summaries {
			if sm[svc.Service] == nil {
				sm[svc.Service] = map[string]bool{}
				if globalCovered[svc.Service] == nil {
					globalCovered[svc.Service] = map[string]bool{}
				}
			}
			for _, m := range svc.Methods {
				sm[svc.Service][m.Name] = true
				globalCovered[svc.Service][m.Name] = true
			}
		}
		globalSets[name] = sm
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 2) 绑定行（应用→（服务→集）与「应用已绑定」集合）
	bindings, err := s.ListBindings(ctx, uuid.Nil)
	if err != nil {
		return nil, err
	}
	boundApps := map[string]bool{}
	appSvcSet := map[string]map[string]string{} // app → service → descriptor_name
	for _, b := range bindings {
		app := b.ApplicationID.String()
		boundApps[app] = true
		if appSvcSet[app] == nil {
			appSvcSet[app] = map[string]string{}
		}
		appSvcSet[app][b.Service] = b.DescriptorName
	}
	// 3) 流量观测到的 gRPC 端点（api_endpoints protocol_type='GRPC'；endpoint_key
	//    为 "POST /pkg.Service/Method" 形态（EndpointKeyPreserve）——拆 service/method）
	rows2, err := s.db.Query(ctx, `SELECT application_id, endpoint_key FROM api_endpoints
		WHERE protocol_type='GRPC' ORDER BY application_id, endpoint_key`)
	if err != nil {
		return nil, err
	}
	defer rows2.Close()
	undoc := map[string]*UndocumentedService{}
	for rows2.Next() {
		var appID, ek string
		if err := rows2.Scan(&appID, &ek); err != nil {
			return nil, err
		}
		service, method := splitGRPCEndpointKey(ek)
		if service == "" {
			continue
		}
		covered := false
		if boundApps[appID] {
			// 绑定应用：该服务须已绑定且方法在绑定集内
			if setName, ok := appSvcSet[appID][service]; ok {
				covered = globalSets[setName][service][method]
			}
		} else {
			covered = globalCovered[service][method]
		}
		if covered {
			continue
		}
		key := appID + "\x00" + service
		u, ok := undoc[key]
		if !ok {
			appUUID, _ := uuid.Parse(appID)
			u = &UndocumentedService{ApplicationID: appUUID, Service: service, Methods: []string{}}
			undoc[key] = u
		}
		u.Methods = append(u.Methods, method)
	}
	if err := rows2.Err(); err != nil {
		return nil, err
	}
	out := make([]UndocumentedService, 0, len(undoc))
	for _, u := range undoc {
		out = append(out, *u)
	}
	// 稳定排序（应用,服务）
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].ApplicationID.String() < out[i].ApplicationID.String() ||
				(out[j].ApplicationID == out[i].ApplicationID && out[j].Service < out[i].Service) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// splitGRPCEndpointKey 拆 "POST /pkg.Service/Method" → (pkg.Service, Method)；
// 形态不符（非恰好两段）返回空（不作为 gRPC 服务端点——与网关 classifier 口径一致）。
func splitGRPCEndpointKey(ek string) (service, method string) {
	parts := strings.SplitN(strings.TrimSpace(ek), " ", 2)
	if len(parts) != 2 || !strings.HasPrefix(parts[1], "/") {
		return "", ""
	}
	body := strings.TrimPrefix(parts[1], "/")
	segs := strings.Split(body, "/")
	if len(segs) != 2 || segs[0] == "" || segs[1] == "" {
		return "", ""
	}
	return segs[0], segs[1]
}
