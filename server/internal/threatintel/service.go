package threatintel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
)

// 默认参数
const (
	DefaultFeed    = "feodo"
	DefaultTTLDays = 30
	MaxTTLDays     = 3650
)

// ErrInvalidInput 导入参数非法（HTTP 层映射 400）。
var ErrInvalidInput = errors.New("invalid threat intel import input")

// feedPattern 限定 feed 名字符集（小写字母/数字开头，可含 _ -，1-32）——
// feed 进入 reason 前缀与 LIKE 模式，必须防止通配符/注入。
var feedPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ReasonPrefix 返回本功能历史导入集合的 reason 统一前缀。
// 对账只认 source_type=IMPORT 且 reason 以该前缀开头的 GLOBAL DENY 行。
func ReasonPrefix(feed string) string { return "威胁情报 " + feed }

// matchPrefix 返回对账匹配的完整 LIKE 前缀（含「 批次」边界词）——
// 防止 feed 互为前缀时误匹配（如 feodo 匹配到 feodo_eu 的规则）。
func matchPrefix(feed string) string { return ReasonPrefix(feed) + " 批次" }

// ProtectedLister 一次性加载启用中的保护地址清单（由 *protectedaddresses.Store 注入；
// 逐条 IsProtected 会每次全表 List，批量导入改为一次加载内存匹配）。可为 nil 表示不检查。
type ProtectedLister interface {
	List(ctx context.Context, addressType string) ([]protectedaddresses.ProtectedAddress, error)
}

// Service 是威胁情报对账导入服务。
type Service struct {
	db        *pgxpool.Pool
	protected ProtectedLister
}

// NewService 创建服务。
func NewService(db *pgxpool.Pool, protected ProtectedLister) *Service {
	return &Service{db: db, protected: protected}
}

// ImportInput 是一次对账导入的输入。
type ImportInput struct {
	Feed     string    // 情报源名（缺省 feodo；字符集受限）
	TTLDays  int       // 有效期天数（缺省 30；0=PERMANENT 永久；上限 3650）
	Entries  []Entry   // 解析后的 IP(+family) 集合（允许空集=对账清空历史导入）
	Operator uuid.UUID // 操作人（created_by/updated_by）
}

// ConflictItem 是一条跳过明细（冲突/人工停用/保护地址）。
type ConflictItem struct {
	Address string `json:"address"`
	Reason  string `json:"reason"`
}

// Result 是对账导入结果（计数 + 批次号 + 前 50 条跳过明细）。
type Result struct {
	BatchID         string
	Feed            string
	TTLDays         int
	Added           int
	Refreshed       int
	Expired         int
	SkippedConflict int
	Conflicts       []ConflictItem
}

// existingRule 是本功能历史导入集合中的一行（对账参与者）。
type existingRule struct {
	ID           uuid.UUID
	Address      string
	Status       string
	ValidityType string
}

// ValidateInput 校验并归一化导入参数（feed 小写、TTL 默认与上下限）。
func ValidateInput(in *ImportInput) error {
	in.Feed = strings.ToLower(strings.TrimSpace(in.Feed))
	if in.Feed == "" {
		in.Feed = DefaultFeed
	}
	if !feedPattern.MatchString(in.Feed) {
		return fmt.Errorf("%w: feed 名仅允许小写字母/数字开头加 _ -（1-32 字符）: %q", ErrInvalidInput, in.Feed)
	}
	if in.TTLDays < 0 {
		return fmt.Errorf("%w: ttl_days 不能为负数（0=永久）", ErrInvalidInput)
	}
	if in.TTLDays > MaxTTLDays {
		return fmt.Errorf("%w: ttl_days 超过上限 %d", ErrInvalidInput, MaxTTLDays)
	}
	return nil
}

// Import 执行集合对账（单事务）：
//   - 新 IP → 新建 GLOBAL DENY ACTIVE（TTL>0 时 TEMPORARY + effective_until=now+TTL，
//     TTL=0 时 PERMANENT），reason=「威胁情报 <feed> 批次<批次号>（<family 或 c2>）」；
//   - 仍在册（本功能历史集合 ACTIVE/EXPIRED）→ 刷新有效期与 reason 批次号，EXPIRED 复活为 ACTIVE；
//   - 本批次消失 → status=EXPIRED（保留历史，不物理删除）；
//   - 与本功能历史集合以外的任何非删除 GLOBAL DENY 行同址 → 跳过新建（冲突清单）；
//   - 历史集合中被人工置 DISABLED 的行不改动、不复活（人工处置优先），在册 DISABLED 地址
//     计入 skipped_conflict；命中保护地址同样跳过。
func (s *Service) Import(ctx context.Context, in ImportInput) (*Result, error) {
	if err := ValidateInput(&in); err != nil {
		return nil, err
	}
	now := time.Now()
	batchID := newBatchID(now)
	res := &Result{BatchID: batchID, Feed: in.Feed, TTLDays: in.TTLDays, Conflicts: []ConflictItem{}}

	// 保护地址清单一次加载（内存匹配，避免逐条全表扫描）
	var protected []protectedaddresses.ProtectedAddress
	if s.protected != nil {
		list, err := s.protected.List(ctx, "")
		if err != nil {
			return nil, fmt.Errorf("加载保护地址清单失败: %w", err)
		}
		protected = list
	}

	var until *time.Time
	validity := accessrules.ValidityPermanent
	if in.TTLDays > 0 {
		t := now.Add(time.Duration(in.TTLDays) * 24 * time.Hour)
		until = &t
		validity = accessrules.ValidityTemporary
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 本功能历史导入集合（行锁防并发对账交错）
	existing, err := loadFeedRules(ctx, tx, in.Feed)
	if err != nil {
		return nil, err
	}
	inBatch := make(map[string]bool, len(in.Entries))
	var refreshList []existingRule
	var toInsert []Entry

	for _, e := range in.Entries {
		inBatch[e.IP] = true
		if cur, ok := existing[e.IP]; ok {
			if cur.Status == accessrules.StatusDisabled {
				// 人工停用：不复活不刷新，保留人工处置
				res.SkippedConflict++
				res.addConflict(e.IP, "本功能历史规则已被人工停用，保留人工处置")
				continue
			}
			refreshList = append(refreshList, cur)
			continue
		}
		// 保护地址：跳过新建
		if hit, name := protectedaddresses.MatchProtected(protected, e.IP); hit {
			res.SkippedConflict++
			res.addConflict(e.IP, "命中保护地址「"+name+"」，禁止加入黑名单")
			continue
		}
		toInsert = append(toInsert, e)
	}

	// 冲突预检：待新建地址与本功能集合以外的任何非删除 GLOBAL DENY 行同址 → 跳过
	if len(toInsert) > 0 {
		conflicts, err := findForeignDeny(ctx, tx, in.Feed, entryIPs(toInsert))
		if err != nil {
			return nil, err
		}
		kept := toInsert[:0]
		for _, e := range toInsert {
			if src, ok := conflicts[e.IP]; ok {
				res.SkippedConflict++
				res.addConflict(e.IP, "已存在 "+src+" 来源的全局黑名单规则，未覆盖")
				continue
			}
			kept = append(kept, e)
		}
		toInsert = kept
	}

	// 新建
	for _, e := range toInsert {
		if err := insertFeedRule(ctx, tx, e, in.Feed, batchID, validity, until, in.Operator); err != nil {
			return nil, err
		}
		res.Added++
	}

	// 刷新在册：有效期按本批 TTL 重算（TTL>0 → TEMPORARY+新失效时间；TTL=0 → 转 PERMANENT），
	// reason 更新为最近批次号与 family（决策：记最近批次而非累加全量批次，reason 列 500 字符有界）。
	if len(refreshList) > 0 {
		familyByIP := map[string]string{}
		for _, e := range in.Entries {
			familyByIP[e.IP] = e.Family
		}
		for _, cur := range refreshList {
			if err := refreshFeedRule(ctx, tx, cur.ID, in.Feed, batchID, familyByIP[cur.Address], validity, until, in.Operator); err != nil {
				return nil, err
			}
			res.Refreshed++
		}
	}

	// 本批次消失的历史在册 ACTIVE 行 → EXPIRED（DISABLED 不动）
	var expireIDs []uuid.UUID
	for addr, cur := range existing {
		if cur.Status == accessrules.StatusActive && !inBatch[addr] {
			expireIDs = append(expireIDs, cur.ID)
		}
	}
	if len(expireIDs) > 0 {
		n, err := expireFeedRules(ctx, tx, expireIDs, in.Operator)
		if err != nil {
			return nil, err
		}
		res.Expired = n
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// addConflict 追加跳过明细（最多前 50 条，计数在调用点完成）。
func (r *Result) addConflict(address, reason string) {
	if len(r.Conflicts) < MaxRowErrors {
		r.Conflicts = append(r.Conflicts, ConflictItem{Address: address, Reason: reason})
	}
}

// loadFeedRules 加载本功能历史导入集合：source_type=IMPORT、GLOBAL DENY、
// reason 以统一前缀开头的全部非删除行（含 ACTIVE/DISABLED/EXPIRED），FOR UPDATE 锁定。
func loadFeedRules(ctx context.Context, tx pgx.Tx, feed string) (map[string]existingRule, error) {
	rows, err := tx.Query(ctx, `
SELECT id, address, status, validity_type FROM ip_access_rules
WHERE deleted_at IS NULL AND rule_type = $1 AND scope_type = $2 AND source_type = $3
  AND reason LIKE $4 ESCAPE '\'
FOR UPDATE`,
		accessrules.RuleTypeDeny, accessrules.ScopeGlobal, accessrules.SourceImport,
		likePrefixEscape(matchPrefix(feed))+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]existingRule{}
	for rows.Next() {
		var r existingRule
		if err := rows.Scan(&r.ID, &r.Address, &r.Status, &r.ValidityType); err != nil {
			return nil, err
		}
		out[r.Address] = r
	}
	return out, rows.Err()
}

// findForeignDeny 查询候选地址中已被本功能集合以外的非删除 GLOBAL DENY 行占用的地址。
// 返回 address → 占用行描述（source_type/status）。
func findForeignDeny(ctx context.Context, tx pgx.Tx, feed string, addrs []string) (map[string]string, error) {
	rows, err := tx.Query(ctx, `
SELECT address, source_type, status FROM ip_access_rules
WHERE deleted_at IS NULL AND rule_type = $1 AND scope_type = $2 AND address = ANY($3)
  AND NOT (source_type = $4 AND reason LIKE $5 ESCAPE '\')`,
		accessrules.RuleTypeDeny, accessrules.ScopeGlobal, addrs,
		accessrules.SourceImport, likePrefixEscape(matchPrefix(feed))+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var addr, src, status string
		if err := rows.Scan(&addr, &src, &status); err != nil {
			return nil, err
		}
		out[addr] = fmt.Sprintf("%s（%s）", src, status)
	}
	return out, rows.Err()
}

// insertFeedRule 新建一条情报黑名单规则（ACTIVE GLOBAL DENY，source_type=IMPORT）。
func insertFeedRule(ctx context.Context, tx pgx.Tx, e Entry, feed, batchID, validity string,
	until *time.Time, operator uuid.UUID) error {
	_, err := tx.Exec(ctx, `
INSERT INTO ip_access_rules (name, rule_type, scope_type, application_id, address, ip_version,
  priority, status, validity_type, effective_until, reason, source_type, created_by, updated_by)
VALUES ($1,$2,$3,NULL,$4,$5,100,$6,$7,$8,$9,$10,$11,$11)`,
		e.IP, accessrules.RuleTypeDeny, accessrules.ScopeGlobal, e.IP, accessrules.IPVersion4,
		accessrules.StatusActive, validity, until,
		batchReason(feed, batchID, e.Family), accessrules.SourceImport, operator)
	return err
}

// refreshFeedRule 刷新在册规则：有效期按本批 TTL 重算、reason 记最近批次、
// EXPIRED 复活为 ACTIVE（DISABLED 已在分类阶段剔除，不会走到这里）。
func refreshFeedRule(ctx context.Context, tx pgx.Tx, id uuid.UUID, feed, batchID, family, validity string,
	until *time.Time, operator uuid.UUID) error {
	res, err := tx.Exec(ctx, `
UPDATE ip_access_rules SET status=$2, validity_type=$3, effective_until=$4, reason=$5,
  updated_by=$6, updated_at=now(), version=version+1
WHERE id=$1 AND deleted_at IS NULL AND status <> $7`,
		id, accessrules.StatusActive, validity, until,
		batchReason(feed, batchID, family), operator, accessrules.StatusDisabled)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return fmt.Errorf("刷新规则 %s 失败：规则已被删除或人工停用", id)
	}
	return nil
}

// expireFeedRules 将本批次消失的历史在册 ACTIVE 行标记 EXPIRED（保留历史）。
func expireFeedRules(ctx context.Context, tx pgx.Tx, ids []uuid.UUID, operator uuid.UUID) (int, error) {
	res, err := tx.Exec(ctx, `
UPDATE ip_access_rules SET status=$2, updated_by=$3, updated_at=now(), version=version+1
WHERE id = ANY($1) AND deleted_at IS NULL AND status = $4`,
		ids, accessrules.StatusExpired, operator, accessrules.StatusActive)
	if err != nil {
		return 0, err
	}
	return int(res.RowsAffected()), nil
}

// batchReason 生成规则 reason：威胁情报 <feed> 批次<批次号>（<family 或 c2>）。
// reason 列上限 500 字符，family 超长时截断（固定段必然在界内）。
func batchReason(feed, batchID, family string) string {
	f := strings.TrimSpace(family)
	if f == "" {
		f = "c2"
	}
	budget := 500 - utf8.RuneCountInString(ReasonPrefix(feed)) - len([]rune(" 批次（）")) - utf8.RuneCountInString(batchID)
	runes := []rune(f)
	if len(runes) > budget && budget > 0 {
		runes = runes[:budget]
	}
	return ReasonPrefix(feed) + " 批次" + batchID + "（" + string(runes) + "）"
}

// newBatchID 生成批次号：UTC 秒级时间戳 + 6 位随机十六进制（同秒重复导入也可区分）。
func newBatchID(now time.Time) string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:])
}

// likePrefixEscape 转义 LIKE 模式中的 % _ \（feed 字符集含 _，必须转义）。
func likePrefixEscape(prefix string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(prefix)
}

// entryIPs 提取条目地址列表。
func entryIPs(entries []Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.IP)
	}
	return out
}
