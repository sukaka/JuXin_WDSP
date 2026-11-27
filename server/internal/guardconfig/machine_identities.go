// machine_identities.go 机器身份登记册与绑定下发（NG-ID g1 批次 B1，设计
// docs/nextgen/NG-ID-g1-machine-identity.md §1.12）：
// api_machine_identities 段 = machine_identities ENABLED 行 + machine_identity_keys
// 全状态键行（ACTIVE/RETIRED/REVOKED 均下发——键状态机 enforcement 在网关侧）；
// api_machine_identity_bindings 段 = machine_identity_bindings 全行稳定序；
// api_machine_identity_meta 段 = 撤销水位（单行 seq）+ 登记册版本（推导见
// GuardMachineIdentityMeta 注释——设计未冻结推导规则，本实现取身份+键两表
// max(updated_at) Unix 毫秒，溯源用途不参与 fail-closed 比较）。
// 身份 identity_name+键 kid+绑定（应用,path）稳定排序——同内容恒得同序列化。
// 表缺失/查询失败 Warn 跳过（与 MCPCatalogStore 同一模式；三段皆空=不下发
// （omitempty），NG-T-C01 零行为）。
package guardconfig

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// MachineIdentityLister 机器身份登记册读取接口（包内单测可 fake 错误路径）。
type MachineIdentityLister interface {
	ListEnabledMachineIdentities(ctx context.Context) ([]gatewayconfig.GuardMachineIdentity, error)
}

// MachineIdentityBindingLister 机器身份绑定读取接口（包内单测可 fake 错误路径）。
type MachineIdentityBindingLister interface {
	ListAllMachineIdentityBindings(ctx context.Context) ([]gatewayconfig.GuardMachineIdentityBinding, error)
}

// MachineIdentityMetaLister 机器身份元数据（撤销水位+登记册版本）读取接口。
type MachineIdentityMetaLister interface {
	LoadMachineIdentityMeta(ctx context.Context) (*gatewayconfig.GuardMachineIdentityMeta, error)
}

// MachineIdentityStore machine_identities/machine_identity_keys/machine_identity_bindings/
// machine_identity_revocation_watermark 读取（表由迁移 000183/000184 建立；按冻结列名读取）。
type MachineIdentityStore struct {
	db *pgxpool.Pool
}

// NewMachineIdentityStore 创建。
func NewMachineIdentityStore(db *pgxpool.Pool) *MachineIdentityStore {
	return &MachineIdentityStore{db: db}
}

var _ MachineIdentityLister = (*MachineIdentityStore)(nil)
var _ MachineIdentityBindingLister = (*MachineIdentityStore)(nil)
var _ MachineIdentityMetaLister = (*MachineIdentityStore)(nil)

func rfc3339Ptr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.UTC().Format(time.RFC3339)
	return &s
}

// ListEnabledMachineIdentities 读取 ENABLED 身份+全状态键行（identity_name/kid 稳定序——
// 同内容恒得同序列化，版本戳确定；DISABLED 身份及其键不出现——发布面安全语义）。
func (s *MachineIdentityStore) ListEnabledMachineIdentities(ctx context.Context) ([]gatewayconfig.GuardMachineIdentity, error) {
	idRows, err := s.db.Query(ctx, `SELECT id, identity_name, tenant_id, principal_binding, status, bot_challenge_exempt
		FROM machine_identities WHERE status='ENABLED' ORDER BY identity_name`)
	if err != nil {
		return nil, err
	}
	defer idRows.Close()
	type idRow struct {
		idx int
		id  string
	}
	out := []gatewayconfig.GuardMachineIdentity{}
	var order []idRow
	for idRows.Next() {
		var m gatewayconfig.GuardMachineIdentity
		var id string
		if err := idRows.Scan(&id, &m.IdentityName, &m.TenantID, &m.PrincipalBinding, &m.Status, &m.BotChallengeExempt); err != nil {
			return nil, err
		}
		order = append(order, idRow{idx: len(out), id: id})
		m.Keys = []gatewayconfig.GuardMachineIdentityKey{}
		out = append(out, m)
	}
	if err := idRows.Err(); err != nil {
		return nil, err
	}
	for _, r := range order {
		keys, err := s.listKeysOf(ctx, r.id)
		if err != nil {
			return nil, err
		}
		out[r.idx].Keys = keys
	}
	return out, nil
}

// listKeysOf 单身份全状态键行（kid 稳定序；revoked_seq/窗口/生效域随行下发——
// 键状态机 enforcement 在网关装配/验证侧）。
func (s *MachineIdentityStore) listKeysOf(ctx context.Context, identityID string) ([]gatewayconfig.GuardMachineIdentityKey, error) {
	rows, err := s.db.Query(ctx, `SELECT kid, alg, public_key_pem, status, not_before, not_after, retire_overlap_until, revoked_seq
		FROM machine_identity_keys WHERE identity_id=$1 ORDER BY kid`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardMachineIdentityKey{}
	for rows.Next() {
		var k gatewayconfig.GuardMachineIdentityKey
		var nb, na, overlap *time.Time
		if err := rows.Scan(&k.Kid, &k.Alg, &k.PublicKeyPEM, &k.Status, &nb, &na, &overlap, &k.RevokedSeq); err != nil {
			return nil, err
		}
		k.NotBefore = rfc3339Ptr(nb)
		k.NotAfter = rfc3339Ptr(na)
		k.RetireOverlapUntil = rfc3339Ptr(overlap)
		out = append(out, k)
	}
	return out, rows.Err()
}

// ListAllMachineIdentityBindings 读取全部绑定（应用+路径稳定序）。
func (s *MachineIdentityStore) ListAllMachineIdentityBindings(ctx context.Context) ([]gatewayconfig.GuardMachineIdentityBinding, error) {
	rows, err := s.db.Query(ctx, `SELECT application_id, COALESCE(path_exact,''), COALESCE(path_prefix,''), mode, proof_required
		FROM machine_identity_bindings ORDER BY application_id, COALESCE(path_exact, path_prefix)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardMachineIdentityBinding{}
	for rows.Next() {
		var b gatewayconfig.GuardMachineIdentityBinding
		if err := rows.Scan(&b.ApplicationID, &b.PathExact, &b.PathPrefix, &b.Mode, &b.ProofRequired); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// LoadMachineIdentityMeta 读取撤销水位+登记册版本（单行种子 seq=0（迁移 000184）；
// registry_version=身份+键两表 max(updated_at) Unix 毫秒（空登记册=0）——确定性
// （同内容恒同值）、随变更墙钟递增、溯源用途（设计未冻结推导规则，见
// GuardMachineIdentityMeta 注释））。
func (s *MachineIdentityStore) LoadMachineIdentityMeta(ctx context.Context) (*gatewayconfig.GuardMachineIdentityMeta, error) {
	var m gatewayconfig.GuardMachineIdentityMeta
	if err := s.db.QueryRow(ctx, `SELECT seq FROM machine_identity_revocation_watermark WHERE id=1`).Scan(&m.RevocationWatermark); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(ctx, `SELECT COALESCE((
		SELECT max(ms) FROM (
			SELECT (extract(epoch from updated_at)*1000)::bigint AS ms FROM machine_identities
			UNION ALL
			SELECT (extract(epoch from updated_at)*1000)::bigint FROM machine_identity_keys
		) t), 0)`).Scan(&m.RegistryVersion); err != nil {
		return nil, err
	}
	return &m, nil
}

// SetMachineIdentityLister 注入机器身份登记册读取（nil 时不下发 api_machine_identities 段）。
func (p *Provider) SetMachineIdentityLister(l MachineIdentityLister) { p.machineIdentities = l }

// machineIDPrincipalBindingDomain  principal_binding 网关比对域分隔前缀（跨轨逐字冻结——
// 与 gateway/dynamic_security/detectors/machineid/registry.go principalFingerprint
// 同源同文，不得改名：S7 批次 C 裁决 3 跨轨对齐修复，S6 偏差 1 先例）。
const machineIDPrincipalBindingDomain = "jwt-principal:"

// machineIDPrincipalBindingDefaultSalt 与网关 principalFingerprint 空盐兜底逐字一致
// （identity_salt 未配置时两端同域成立的前提）。
const machineIDPrincipalBindingDefaultSalt = "jiuzhang-wdsp-fp-default\x00"

// machineIDPrincipalBindingFP 发布域换算：管理面录入的是 JWT 事件可观测的
// VerifiedPrincipalID 指纹值（第一层），网关运行期比对的是
// HMAC-SHA256(key=identity_salt, "jwt-principal:"+VerifiedPrincipalID) 截前 16 字节
// hex（第二层）——发布边界统一把录入值换算到网关比对域；DB 保留运营录入值（读回
// 一致），盐与换算值同快照随行（盐轮换后下次发布自动重对齐；回滚快照携带换算后
// 值，盐未轮换时一致——盐轮换本身即全局身份指纹重置，与 apiauthz 主体指纹同纪律）。
func machineIDPrincipalBindingFP(identitySalt, entered string) string {
	if identitySalt == "" {
		identitySalt = machineIDPrincipalBindingDefaultSalt
	}
	m := hmac.New(sha256.New, []byte(identitySalt))
	_, _ = m.Write([]byte(machineIDPrincipalBindingDomain))
	_, _ = m.Write([]byte(entered))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// applyMachineIDPrincipalBindingFP 对装配完成的 GuardConfig 执行 principal_binding
// 发布域换算（BuildGuardConfig 内 applyGatewayRuntime 之后调用——同一快照的
// identity_salt 为换算盐；nil/空录入不动）。
func applyMachineIDPrincipalBindingFP(cfg *gatewayconfig.GuardConfig) {
	if cfg == nil {
		return
	}
	for i := range cfg.APIMachineIdentities {
		pb := cfg.APIMachineIdentities[i].PrincipalBinding
		if pb == nil {
			continue
		}
		if v := strings.TrimSpace(*pb); v != "" {
			fp := machineIDPrincipalBindingFP(cfg.IdentitySalt, v)
			cfg.APIMachineIdentities[i].PrincipalBinding = &fp
		}
	}
}

// SetMachineIdentityBindingLister 注入机器身份绑定读取（nil 时不下发 api_machine_identity_bindings 段）。
func (p *Provider) SetMachineIdentityBindingLister(l MachineIdentityBindingLister) {
	p.machineIDBindings = l
}

// SetMachineIdentityMetaLister 注入机器身份元数据读取（nil 时不下发 api_machine_identity_meta 段）。
func (p *Provider) SetMachineIdentityMetaLister(l MachineIdentityMetaLister) { p.machineIDMeta = l }

// loadAPIMachineIdentities 读取 ENABLED 机器身份+全状态键行（兼容旧调用方；BuildGuardConfig 走 Strict）。
func (p *Provider) loadAPIMachineIdentities(ctx context.Context) []gatewayconfig.GuardMachineIdentity {
	identities, err := p.loadAPIMachineIdentitiesStrict(ctx)
	if err != nil {
		slog.Warn("api_machine_identities load failed, skipping section", "error", err)
	}
	return identities
}

func (p *Provider) loadAPIMachineIdentitiesStrict(ctx context.Context) ([]gatewayconfig.GuardMachineIdentity, error) {
	if p.machineIdentities == nil {
		return nil, nil
	}
	identities, err := p.machineIdentities.ListEnabledMachineIdentities(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "machine_identities") ||
			isMissingLegacyTableError(err, "machine_identity_keys") {
			slog.Warn("optional legacy table machine_identities is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("machine_identities", err)
	}
	return identities, nil
}

// loadAPIMachineIdentityBindings 读取全部机器身份绑定（兼容旧调用方；BuildGuardConfig 走 Strict）。
func (p *Provider) loadAPIMachineIdentityBindings(ctx context.Context) []gatewayconfig.GuardMachineIdentityBinding {
	bindings, err := p.loadAPIMachineIdentityBindingsStrict(ctx)
	if err != nil {
		slog.Warn("api_machine_identity_bindings load failed, skipping section", "error", err)
	}
	return bindings
}

func (p *Provider) loadAPIMachineIdentityBindingsStrict(ctx context.Context) ([]gatewayconfig.GuardMachineIdentityBinding, error) {
	if p.machineIDBindings == nil {
		return nil, nil
	}
	bindings, err := p.machineIDBindings.ListAllMachineIdentityBindings(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "machine_identity_bindings") {
			slog.Warn("optional legacy table machine_identity_bindings is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("machine_identity_bindings", err)
	}
	return bindings, nil
}

// loadAPIMachineIdentitySections 读取机器身份三段（兼容旧调用方；BuildGuardConfig 走 Strict）。
func (p *Provider) loadAPIMachineIdentitySections(ctx context.Context) ([]gatewayconfig.GuardMachineIdentity, []gatewayconfig.GuardMachineIdentityBinding, *gatewayconfig.GuardMachineIdentityMeta) {
	identities, bindings, meta, err := p.loadAPIMachineIdentitySectionsStrict(ctx)
	if err != nil {
		slog.Warn("api_machine_identity sections load failed, dropping all machine identity sections", "error", err)
		return nil, nil, nil
	}
	return identities, bindings, meta
}

// loadAPIMachineIdentitySectionsStrict 仅容忍旧库未建表（42P01）；任一真实数据库错误中止候选发布（fail-hard），
// 防止已启用的机器身份 PROTECT 策略在瞬时 DB 故障时被静默清零下发。
func (p *Provider) loadAPIMachineIdentitySectionsStrict(ctx context.Context) ([]gatewayconfig.GuardMachineIdentity, []gatewayconfig.GuardMachineIdentityBinding, *gatewayconfig.GuardMachineIdentityMeta, error) {
	identities, err := p.loadAPIMachineIdentitiesStrict(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	bindings, err := p.loadAPIMachineIdentityBindingsStrict(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(identities) == 0 && len(bindings) == 0 {
		return identities, bindings, nil, nil
	}
	if p.machineIDMeta == nil {
		return identities, bindings, nil, nil
	}
	meta, err := p.machineIDMeta.LoadMachineIdentityMeta(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "machine_identity_revocation_watermark") ||
			isMissingLegacyTableError(err, "machine_identities") ||
			isMissingLegacyTableError(err, "machine_identity_keys") {
			slog.Warn("optional legacy table machine_identity_revocation_watermark is unavailable, dropping machine identity sections", "error", err)
			return nil, nil, nil, nil
		}
		return nil, nil, nil, wrapLegacyLoaderError("machine_identity_revocation_watermark", err)
	}
	return identities, bindings, meta, nil
}
