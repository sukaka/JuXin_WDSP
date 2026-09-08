// asset_tools.go 资产与策略 Tool：应用/域名/源站/证书/网关/策略/规则/例外。
package aitools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewAssetTools 注册资产与策略 Tool 组。
func NewAssetTools(r *Registry, db *pgxpool.Pool) {
	r.Register(&appSearch{baseTool: baseTool{meta: toolMeta{
		code: "application.search", name: "应用查询", version: "1.0",
		description: "按关键字/状态/防护模式查询应用",
		risk:        RiskReadOnly, permission: "applications.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"keyword": sch("string", "编码或名称关键字（可选）"), "status": sch("string", "状态（可选）"),
			"page": sch("integer", "页码"),
		})}}, db: db})
	r.Register(&appGet{baseTool: baseTool{meta: toolMeta{
		code: "application.get", name: "应用详情", version: "1.0",
		description: "按ID获取应用详情（含域名与源站）",
		risk:        RiskReadOnly, permission: "applications.read", timeout: 10, maxResults: 1,
		schema: obj(map[string]interface{}{"application_id": sch("string", "应用ID")})}}, db: db})
	r.Register(&domainGet{baseTool: baseTool{meta: toolMeta{
		code: "domain.get", name: "域名查询", version: "1.0",
		description: "按域名或应用ID查询域名配置",
		risk:        RiskReadOnly, permission: "applications.read", timeout: 10, maxResults: 50,
		schema: obj(map[string]interface{}{
			"hostname": sch("string", "域名（可选）"), "application_id": sch("string", "应用ID（可选）"),
		})}}, db: db})
	r.Register(&upstreamGet{baseTool: baseTool{meta: toolMeta{
		code: "upstream.get", name: "源站查询", version: "1.0",
		description: "按应用ID查询源站列表（不含敏感凭据）",
		risk:        RiskReadOnly, permission: "applications.read", timeout: 10, maxResults: 50,
		schema: obj(map[string]interface{}{"application_id": sch("string", "应用ID")})}}, db: db})
	r.Register(&certMeta{baseTool: baseTool{meta: toolMeta{
		code: "certificate.get_metadata", name: "证书元数据", version: "1.0",
		description: "查询证书元数据（不含私钥），含到期状态",
		risk:        RiskReadOnly, permission: "certificates.read", timeout: 10, maxResults: 50,
		schema: obj(map[string]interface{}{
			"certificate_id": sch("string", "证书ID（可选）"), "expiring_days": sch("integer", "N天内到期过滤（可选）"),
		})}}, db: db})
	r.Register(&gatewayStatus{baseTool: baseTool{meta: toolMeta{
		code: "gateway.get_status", name: "网关状态", version: "1.0",
		description: "查询网关在线状态、当前配置版本与应用计数",
		risk:        RiskReadOnly, permission: "gateway_status.read", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{})}}, db: db})
	r.Register(&policyGet{baseTool: baseTool{meta: toolMeta{
		code: "policy.get", name: "防护策略查询", version: "1.0",
		description: "查询防护策略（含内置模板）",
		risk:        RiskReadOnly, permission: "protection_policies.read", timeout: 10, maxResults: 50,
		schema: obj(map[string]interface{}{
			"policy_id": sch("string", "策略ID（可选）"), "keyword": sch("string", "关键字（可选）"),
		})}}, db: db})
	r.Register(&policyVersion{baseTool: baseTool{meta: toolMeta{
		code: "policy.version", name: "配置版本查询", version: "1.0",
		description: "查询网关配置版本列表/当前版本元数据",
		risk:        RiskReadOnly, permission: "config_versions.read", timeout: 15, maxResults: 20,
		schema: obj(map[string]interface{}{
			"version_number": sch("string", "版本号（可选，空则当前）"),
		})}}, db: db})
	r.Register(&policyDiff{baseTool: baseTool{meta: toolMeta{
		code: "policy.diff", name: "配置版本差异", version: "1.0",
		description: "比较两个网关配置版本的元数据差异（不含完整配置 blob）",
		risk:        RiskReadOnly, permission: "config_versions.read", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{
			"from_version": sch("string", "源版本号"), "to_version": sch("string", "目标版本号"),
		})}}, db: db})
	r.Register(&ruleSearch{baseTool: baseTool{meta: toolMeta{
		code: "rule.search", name: "WAF规则查询", version: "1.0",
		description: "按规则ID/关键字/攻击类型查询CRS与自定义规则",
		risk:        RiskReadOnly, permission: "waf_rules.read", timeout: 20, maxResults: 50,
		schema: obj(map[string]interface{}{
			"rule_id": sch("integer", "规则ID（可选）"), "keyword": sch("string", "关键字（可选）"),
			"attack_type": sch("string", "攻击类型（可选）"), "page": sch("integer", "页码"),
		})}}, db: db})
	r.Register(&ruleGet{baseTool: baseTool{meta: toolMeta{
		code: "rule.get", name: "WAF规则详情", version: "1.0",
		description: "按规则ID获取规则详情与命中统计",
		risk:        RiskReadOnly, permission: "waf_rules.read", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{"rule_id": sch("integer", "规则ID")})}}, db: db})
	r.Register(&ruleHitStats{baseTool: baseTool{meta: toolMeta{
		code: "rule.hit_statistics", name: "规则命中统计", version: "1.0",
		description: "指定规则在时间范围内的命中/阻断/误报统计",
		risk:        RiskReadOnly, permission: "waf_rules.read", timeout: 20, maxResults: 1,
		schema: obj(map[string]interface{}{
			"rule_id": sch("integer", "规则ID"), "start_time": sch("string", "起始时间"),
			"end_time": sch("string", "结束时间"),
		})}}, db: db})
	r.Register(&exceptionSearch{baseTool: baseTool{meta: toolMeta{
		code: "exception.search", name: "例外策略查询", version: "1.0",
		description: "按范围/状态查询例外策略",
		risk:        RiskReadOnly, permission: "exceptions.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"status": sch("string", "状态（可选）"), "scope_type": sch("string", "范围（可选）"),
			"page": sch("integer", "页码"),
		})}}, db: db})
	r.Register(&exceptionGet{baseTool: baseTool{meta: toolMeta{
		code: "exception.get", name: "例外策略详情", version: "1.0",
		description: "按ID获取例外策略详情",
		risk:        RiskReadOnly, permission: "exceptions.read", timeout: 10, maxResults: 1,
		schema: obj(map[string]interface{}{"exception_id": sch("string", "例外ID")})}}, db: db})
}

type appSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *appSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	page := IntField(m, "page", 1)
	if page < 1 {
		page = 1
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	idx := 1
	if v := StrField(m, "keyword", 64); v != "" {
		where += fmt.Sprintf(" AND (code ILIKE $%d OR name ILIKE $%d)", idx, idx)
		args = append(args, "%"+v+"%")
		idx++
	}
	if v := StrField(m, "status", 20); v != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, v)
		idx++
	}
	var total int64
	if err := t.db.QueryRow(ctx, `SELECT count(*) FROM applications WHERE `+where, args...).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := t.db.Query(ctx, `
SELECT id, code, name, status, protection_mode, created_at FROM applications
WHERE `+where+` ORDER BY created_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, code, name, status, mode string
		var at time.Time
		if err := rows.Scan(&id, &code, &name, &status, &mode, &at); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"application_id": id, "code": code, "name": name, "status": status,
			"protection_mode": mode, "created_at": at,
		})
	}
	return map[string]interface{}{"total": total, "page": page, "items": items}, rows.Err()
}

type appGet struct {
	baseTool
	db *pgxpool.Pool
}

func (t *appGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id := StrField(m, "application_id", 64)
	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("%w: invalid application_id", ErrInvalidInput)
	}
	var code, name, status, mode string
	err := t.db.QueryRow(ctx, `
SELECT code, name, status, protection_mode FROM applications WHERE id = $1 AND deleted_at IS NULL`, id).Scan(&code, &name, &status, &mode)
	if err != nil {
		return nil, fmt.Errorf("application not found")
	}
	dRows, err := t.db.Query(ctx, `
SELECT normalized_hostname, http_enabled, https_enabled FROM application_domains
WHERE application_id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	defer dRows.Close()
	var domains []interface{}
	for dRows.Next() {
		var h string
		var he, hs bool
		if err := dRows.Scan(&h, &he, &hs); err != nil {
			return nil, err
		}
		domains = append(domains, map[string]interface{}{"hostname": h, "http": he, "https": hs})
	}
	uRows, err := t.db.Query(ctx, `
SELECT name, host, port, scheme, status FROM upstreams
WHERE application_id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	defer uRows.Close()
	var upstreams []interface{}
	for uRows.Next() {
		var n, h, sc, st string
		var p int
		if err := uRows.Scan(&n, &h, &p, &sc, &st); err != nil {
			return nil, err
		}
		upstreams = append(upstreams, map[string]interface{}{
			"name": n, "host": h, "port": p, "scheme": sc, "status": st,
		})
	}
	return map[string]interface{}{
		"application_id": id, "code": code, "name": name, "status": status,
		"protection_mode": mode, "domains": domains, "upstreams": upstreams,
	}, nil
}

type domainGet struct {
	baseTool
	db *pgxpool.Pool
}

func (t *domainGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if v := StrField(m, "hostname", 255); v != "" {
		where += fmt.Sprintf(" AND d.normalized_hostname = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "application_id", 64); v != "" {
		if _, err := uuid.Parse(v); err != nil {
			return nil, fmt.Errorf("%w: invalid application_id", ErrInvalidInput)
		}
		where += fmt.Sprintf(" AND d.application_id = $%d", idx)
		args = append(args, v)
		idx++
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("%w: hostname or application_id required", ErrInvalidInput)
	}
	rows, err := t.db.Query(ctx, `
SELECT d.id, d.application_id, a.code, d.normalized_hostname, d.http_enabled, d.https_enabled,
  COALESCE(d.http_port, 80), COALESCE(d.https_port, 443)
FROM application_domains d JOIN applications a ON a.id = d.application_id AND a.deleted_at IS NULL
WHERE `+where+` ORDER BY d.normalized_hostname LIMIT 50`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, appID, code, host string
		var he, hs bool
		var httpPort, httpsPort int
		if err := rows.Scan(&id, &appID, &code, &host, &he, &hs, &httpPort, &httpsPort); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"domain_id": id, "application_id": appID, "application_code": code,
			"hostname": host, "http_enabled": he, "https_enabled": hs,
			"http_port": httpPort, "https_port": httpsPort,
		})
	}
	return map[string]interface{}{"items": items}, rows.Err()
}

type upstreamGet struct {
	baseTool
	db *pgxpool.Pool
}

func (t *upstreamGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	appID := StrField(m, "application_id", 64)
	if _, err := uuid.Parse(appID); err != nil {
		return nil, fmt.Errorf("%w: invalid application_id", ErrInvalidInput)
	}
	rows, err := t.db.Query(ctx, `
SELECT id, name, host, port, scheme, weight, status FROM upstreams
WHERE application_id = $1 AND deleted_at IS NULL ORDER BY name`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, name, host, scheme, st string
		var port, weight int
		if err := rows.Scan(&id, &name, &host, &port, &scheme, &weight, &st); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"upstream_id": id, "name": name, "host": host, "port": port,
			"scheme": scheme, "weight": weight, "status": st,
		})
	}
	return map[string]interface{}{"application_id": appID, "items": items}, rows.Err()
}

type certMeta struct {
	baseTool
	db *pgxpool.Pool
}

func (t *certMeta) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	if v := StrField(m, "certificate_id", 64); v != "" {
		where += " AND id = $1"
		args = append(args, v)
	}
	if d := IntField(m, "expiring_days", 0); d > 0 {
		where += fmt.Sprintf(" AND not_after <= now() + interval '%d days'", d)
	}
	rows, err := t.db.Query(ctx, `
SELECT id, name, common_name, issuer, not_before, not_after, status
FROM certificates WHERE `+where+` ORDER BY not_after LIMIT 50`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, name, cn, issuer, status string
		var nb, na *time.Time
		if err := rows.Scan(&id, &name, &cn, &issuer, &nb, &na, &status); err != nil {
			return nil, err
		}
		var daysLeft *int
		if na != nil {
			d := int(time.Until(*na).Hours() / 24)
			daysLeft = &d
		}
		items = append(items, map[string]interface{}{
			"certificate_id": id, "name": name, "common_name": cn, "issuer": issuer,
			"not_before": nb, "not_after": na, "days_remaining": daysLeft, "status": status,
		})
	}
	return map[string]interface{}{"items": items}, rows.Err()
}

type gatewayStatus struct {
	baseTool
	db *pgxpool.Pool
}

func (t *gatewayStatus) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var version, hash, result string
	var publishedAt *time.Time
	err := t.db.QueryRow(ctx, `
SELECT version_number, configuration_hash, publish_result, published_at
FROM gateway_config_versions WHERE is_current = TRUE LIMIT 1`).Scan(&version, &hash, &result, &publishedAt)
	if err != nil {
		return map[string]interface{}{"online": false, "message": "无已发布配置"}, nil
	}
	var apps, domains, ups int64
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM applications WHERE deleted_at IS NULL AND status='ACTIVE'`).Scan(&apps)
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM application_domains WHERE deleted_at IS NULL`).Scan(&domains)
	_ = t.db.QueryRow(ctx, `SELECT count(*) FROM upstreams WHERE deleted_at IS NULL AND status='ACTIVE'`).Scan(&ups)
	return map[string]interface{}{
		"online": true, "current_version": version, "config_hash": hash,
		"publish_result": result, "published_at": publishedAt,
		"applications": apps, "domains": domains, "upstreams": ups,
	}, nil
}

type policyGet struct {
	baseTool
	db *pgxpool.Pool
}

func (t *policyGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	where := "deleted_at IS NULL AND status = 'ACTIVE'"
	args := []interface{}{}
	idx := 1
	if v := StrField(m, "policy_id", 64); v != "" {
		where += fmt.Sprintf(" AND id = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "keyword", 64); v != "" {
		where += fmt.Sprintf(" AND (code ILIKE $%d OR name ILIKE $%d)", idx, idx)
		args = append(args, "%"+v+"%")
		idx++
	}
	rows, err := t.db.Query(ctx, `
SELECT id, code, name, protection_mode, paranoia_level, inbound_anomaly_threshold, outbound_anomaly_threshold, is_builtin
FROM protection_policies WHERE `+where+` ORDER BY is_builtin DESC, code LIMIT 50`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, code, name, mode string
		var pl, in, out int
		var builtin bool
		if err := rows.Scan(&id, &code, &name, &mode, &pl, &in, &out, &builtin); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"policy_id": id, "code": code, "name": name, "protection_mode": mode,
			"paranoia_level": pl, "inbound_threshold": in, "outbound_threshold": out, "is_builtin": builtin,
		})
	}
	return map[string]interface{}{"items": items}, rows.Err()
}

type policyVersion struct {
	baseTool
	db *pgxpool.Pool
}

func (t *policyVersion) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	vn := StrField(m, "version_number", 64)
	if vn != "" {
		var id, version, hash, result string
		var publishedAt *time.Time
		var isCurrent bool
		err := t.db.QueryRow(ctx, `
SELECT id::text, version_number, configuration_hash, COALESCE(publish_result,''), published_at, is_current
FROM gateway_config_versions WHERE version_number = $1`, vn).
			Scan(&id, &version, &hash, &result, &publishedAt, &isCurrent)
		if err != nil {
			return nil, fmt.Errorf("version not found")
		}
		return map[string]interface{}{
			"version_id": id, "version_number": version, "config_hash": hash,
			"publish_result": result, "published_at": publishedAt, "is_current": isCurrent,
		}, nil
	}
	rows, err := t.db.Query(ctx, `
SELECT id::text, version_number, configuration_hash, COALESCE(publish_result,''), published_at, is_current
FROM gateway_config_versions ORDER BY published_at DESC NULLS LAST LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, version, hash, result string
		var publishedAt *time.Time
		var isCurrent bool
		if err := rows.Scan(&id, &version, &hash, &result, &publishedAt, &isCurrent); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"version_id": id, "version_number": version, "config_hash": hash,
			"publish_result": result, "published_at": publishedAt, "is_current": isCurrent,
		})
	}
	return map[string]interface{}{"items": items}, rows.Err()
}

type policyDiff struct {
	baseTool
	db *pgxpool.Pool
}

func (t *policyDiff) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	fromV := StrField(m, "from_version", 64)
	toV := StrField(m, "to_version", 64)
	if fromV == "" || toV == "" {
		return nil, fmt.Errorf("%w: from_version and to_version required", ErrInvalidInput)
	}
	type meta struct {
		Version string
		Hash    string
		Result  string
		At      *time.Time
	}
	load := func(vn string) (*meta, error) {
		var x meta
		err := t.db.QueryRow(ctx, `
SELECT version_number, configuration_hash, COALESCE(publish_result,''), published_at
FROM gateway_config_versions WHERE version_number = $1`, vn).
			Scan(&x.Version, &x.Hash, &x.Result, &x.At)
		if err != nil {
			return nil, fmt.Errorf("version %s not found", vn)
		}
		return &x, nil
	}
	a, err := load(fromV)
	if err != nil {
		return nil, err
	}
	b, err := load(toV)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"from":         map[string]interface{}{"version": a.Version, "config_hash": a.Hash, "publish_result": a.Result, "published_at": a.At},
		"to":           map[string]interface{}{"version": b.Version, "config_hash": b.Hash, "publish_result": b.Result, "published_at": b.At},
		"hash_changed": a.Hash != b.Hash,
		"note":         "仅返回元数据差异，不含完整配置内容",
	}, nil
}

type ruleSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *ruleSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	where := "1=1"
	args := []interface{}{}
	idx := 1
	if v := IntField(m, "rule_id", 0); v > 0 {
		where += fmt.Sprintf(" AND rule_id = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "keyword", 64); v != "" {
		where += fmt.Sprintf(" AND (name ILIKE $%d OR message ILIKE $%d)", idx, idx)
		args = append(args, "%"+v+"%")
		idx++
	}
	if v := StrField(m, "attack_type", 40); v != "" {
		where += fmt.Sprintf(" AND attack_type = $%d", idx)
		args = append(args, v)
		idx++
	}
	page := IntField(m, "page", 1)
	if page < 1 {
		page = 1
	}
	rows, err := t.db.Query(ctx, `
SELECT rule_id, name, severity, attack_type, rule_source, file_name FROM waf_rules
WHERE `+where+` ORDER BY rule_id LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var rid int
		var name, sev, at, src, file string
		if err := rows.Scan(&rid, &name, &sev, &at, &src, &file); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"rule_id": rid, "name": name, "severity": sev, "attack_type": at, "rule_source": src, "file": file,
		})
	}
	return map[string]interface{}{"page": page, "items": items}, rows.Err()
}

type ruleGet struct {
	baseTool
	db *pgxpool.Pool
}

func (t *ruleGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	rid := IntField(m, "rule_id", 0)
	if rid <= 0 {
		return nil, fmt.Errorf("%w: rule_id required", ErrInvalidInput)
	}
	var name, sev, at, src, file, msg string
	var phase int
	err := t.db.QueryRow(ctx, `
SELECT name, severity, attack_type, rule_source, file_name, COALESCE(message,''), COALESCE(phase, 0)
FROM waf_rules WHERE rule_id = $1`, rid).Scan(&name, &sev, &at, &src, &file, &msg, &phase)
	if err != nil {
		return nil, fmt.Errorf("rule not found")
	}
	var hits int64
	_ = t.db.QueryRow(ctx, `
SELECT count(*) FROM security_event_matches WHERE rule_id = $1`, rid).Scan(&hits)
	var fp int64
	_ = t.db.QueryRow(ctx, `
SELECT count(*) FROM security_events e JOIN security_event_matches m ON m.event_id = e.id
WHERE m.rule_id = $1 AND e.disposition_status = 'CONFIRMED_FALSE_POSITIVE'`, rid).Scan(&fp)
	return map[string]interface{}{
		"rule_id": rid, "name": name, "severity": sev, "attack_type": at, "rule_source": src,
		"file": file, "message": msg, "phase": phase,
		"hit_count": hits, "false_positive_count": fp,
	}, nil
}

type ruleHitStats struct {
	baseTool
	db *pgxpool.Pool
}

func (t *ruleHitStats) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	rid := IntField(m, "rule_id", 0)
	if rid <= 0 {
		return nil, fmt.Errorf("%w: rule_id required", ErrInvalidInput)
	}
	start, end, err := parseTimeRange(m)
	if err != nil {
		return nil, err
	}
	var hits, blocks, fps int64
	err = t.db.QueryRow(ctx, `
SELECT count(*),
  count(*) FILTER (WHERE e.action='BLOCK'),
  count(*) FILTER (WHERE e.disposition_status='CONFIRMED_FALSE_POSITIVE')
FROM security_event_matches m
JOIN security_events e ON e.id = m.event_id AND e.occurred_at >= $2 AND e.occurred_at < $3
WHERE m.rule_id = $1`, rid, start, end).Scan(&hits, &blocks, &fps)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"rule_id": rid, "hits": hits, "blocks": blocks, "false_positives": fps,
		"range": map[string]string{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)},
	}, nil
}

type exceptionSearch struct {
	baseTool
	db *pgxpool.Pool
}

func (t *exceptionSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	where := "deleted_at IS NULL"
	args := []interface{}{}
	idx := 1
	if v := StrField(m, "status", 20); v != "" {
		where += fmt.Sprintf(" AND status = $%d", idx)
		args = append(args, v)
		idx++
	}
	if v := StrField(m, "scope_type", 20); v != "" {
		where += fmt.Sprintf(" AND scope_type = $%d", idx)
		args = append(args, v)
		idx++
	}
	page := IntField(m, "page", 1)
	if page < 1 {
		page = 1
	}
	rows, err := t.db.Query(ctx, `
SELECT id, name, scope_type, exception_action, status, effective_until, created_at
FROM exception_policies WHERE `+where+` ORDER BY created_at DESC LIMIT $`+fmt.Sprint(idx)+` OFFSET $`+fmt.Sprint(idx+1),
		append(args, 20, (page-1)*20)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, name, scope, act, st string
		var until *time.Time
		var at time.Time
		if err := rows.Scan(&id, &name, &scope, &act, &st, &until, &at); err != nil {
			return nil, err
		}
		items = append(items, map[string]interface{}{
			"exception_id": id, "name": name, "scope_type": scope, "action": act,
			"status": st, "effective_until": until, "created_at": at,
		})
	}
	return map[string]interface{}{"page": page, "items": items}, rows.Err()
}

type exceptionGet struct {
	baseTool
	db *pgxpool.Pool
}

func (t *exceptionGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	id := StrField(m, "exception_id", 64)
	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("%w: invalid exception_id", ErrInvalidInput)
	}
	var name, scope, act, st, reason string
	var until *time.Time
	var isTemp bool
	err := t.db.QueryRow(ctx, `
SELECT name, scope_type, exception_action, status, is_temporary, effective_until, COALESCE(reason,'')
FROM exception_policies WHERE id = $1 AND deleted_at IS NULL`, id).
		Scan(&name, &scope, &act, &st, &isTemp, &until, &reason)
	if err != nil {
		return nil, fmt.Errorf("exception not found")
	}
	return map[string]interface{}{
		"exception_id": id, "name": name, "scope_type": scope, "action": act,
		"status": st, "is_temporary": isTemp, "effective_until": until, "reason": reason,
	}, nil
}
