// revoked_credentials.go 已吊销凭据清单下发（阶段8 §35「已吊销凭据使用」数据源）：
// api_revoked_credentials 表当前生效窗口内的行 → api_revoked_credentials 段。
// 表由迁移 000156 建立；缺失/查询失败 Warn 跳过，与 FlowBaselineStore 同一模式。
// 指纹级清单（credential_type + 32 位 hex 指纹），无凭据明文；网关检测器按
// credential_type + ":" + fingerprint 与请求身份指纹（CredentialKey 口径）比对。
package guardconfig

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// RevokedCredentialLister 已吊销凭据读取接口（api_revoked_credentials 表；包内单测可 fake 错误路径）。
type RevokedCredentialLister interface {
	ListActiveRevokedCredentials(ctx context.Context) ([]gatewayconfig.GuardRevokedCredential, error)
}

// RevokedCredentialStore api_revoked_credentials 读取（表由迁移 000156 建立；按冻结列名
// 读取；仅取当前生效窗口内的行，按 credential_type/fingerprint 稳定排序——同内容恒得
// 同序列化，版本戳确定）。
type RevokedCredentialStore struct {
	db *pgxpool.Pool
}

// NewRevokedCredentialStore 创建已吊销凭据读取仓储。
func NewRevokedCredentialStore(db *pgxpool.Pool) *RevokedCredentialStore {
	return &RevokedCredentialStore{db: db}
}

var _ RevokedCredentialLister = (*RevokedCredentialStore)(nil)

// ListActiveRevokedCredentials 读取当前生效的吊销记录（未生效/已到期行不下发；
// 到期时间随载荷下发，供网关在发布间隙按时间自行失效）。
func (s *RevokedCredentialStore) ListActiveRevokedCredentials(ctx context.Context) ([]gatewayconfig.GuardRevokedCredential, error) {
	rows, err := s.db.Query(ctx, `
SELECT credential_type, fingerprint, effective_until
FROM api_revoked_credentials
WHERE effective_from <= now() AND (effective_until IS NULL OR effective_until > now())
ORDER BY credential_type, fingerprint`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardRevokedCredential{}
	for rows.Next() {
		var r gatewayconfig.GuardRevokedCredential
		var until *time.Time
		if err := rows.Scan(&r.CredentialType, &r.Fingerprint, &until); err != nil {
			return nil, err
		}
		if until != nil {
			r.ExpiresAt = until.UTC().Format(time.RFC3339)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetRevokedCredentialLister 注入已吊销凭据读取（nil 时不下发 api_revoked_credentials 段）。
func (p *Provider) SetRevokedCredentialLister(l RevokedCredentialLister) { p.revokedCredentials = l }

// loadAPIRevokedCredentialsStrict 读取当前生效吊销清单；未注入或空清单不下发；
// 缺表容忍 Warn 跳过，真实查询错误 fail-hard（纪律同 loadAPIRoleBaselinesStrict：
// 增量能力，缺失时保持发布通道既有行为，网关无清单下发时吊销检测零行为）。
func (p *Provider) loadAPIRevokedCredentialsStrict(ctx context.Context) ([]gatewayconfig.GuardRevokedCredential, error) {
	if p.revokedCredentials == nil {
		return nil, nil
	}
	items, err := p.revokedCredentials.ListActiveRevokedCredentials(ctx)
	if err != nil {
		if isMissingLegacyTableError(err, "api_revoked_credentials") {
			slog.Warn("optional legacy table api_revoked_credentials is unavailable", "error", err)
			return nil, nil
		}
		return nil, wrapLegacyLoaderError("api_revoked_credentials", err)
	}
	if len(items) == 0 {
		return nil, nil
	}
	return items, nil
}
