// Package regression 安全回归证据登记与发布门禁（WDSP P1-04 R3；任务书
// docs/tasks/wdsp-p1/P1-04_RULE_MODEL_REGRESSION.md §6.2/§7）。
//
// 信任边界：回归报告由仓库外的受控验证服务以 Ed25519 对「版本化 manifest 的
// 确定编码字节」签名；本包只做服务端核验——固定 schema 与确定字节编码（UTF-8、
// 键按字典序、无冗余空白，等价于 encoding/json 对 UseNumber 解码结果的再编码），
// 拒绝重复 JSON 键、未知签名算法与未登记/已撤销 key_id。签名只证明来源与完整性，
// 不证明测试结论正确：服务端仍独立核验全部必需对象哈希、执行数量、用例唯一性
// 与结果一致性，declared_status 仅登记不采信。
//
// 限额（S0 契约 #5 按语料规模冻结的 R3 数值）：
//   - 导入请求 ≤ 1 MiB；manifest 对象 ≤ 4 MiB；
//   - 用例结果分块对象：单块 ≤ 4 MiB、每次运行 ≤ 64 块；
//   - 报告对象 ≤ 16 MiB；性能原始分布对象 ≤ 256 MiB（流式存储不全量读入内存）；
//   - 单次运行全部对象合计 ≤ 512 MiB；
//   - 证据默认有效期 7 天（策略可调 1~30 天），相关内容变化立即失效（按候选
//     配置指纹绑定，不等待到期）。
package regression

import "errors"

// 对象类别（受控登记与限额按类别区分）。
const (
	KindManifest   = "MANIFEST"
	KindCasesChunk = "CASES_CHUNK"
	KindReport     = "REPORT"
	KindPerf       = "PERF"
	KindLog        = "LOG"
)

// 对象登记状态。
const (
	ObjectRegistered = "REGISTERED"
	ObjectConsumed   = "CONSUMED"
)

// 运行级别。
const (
	LevelSmoke   = "SMOKE"
	LevelFull    = "FULL"
	LevelRelease = "RELEASE"
)

// 状态词表（与 p0bench/p1reg 词表一致）。
const (
	StatusPass    = "PASS"
	StatusFail    = "FAIL"
	StatusSkip    = "SKIP"
	StatusBlocked = "BLOCKED"
	StatusNotRun  = "NOT_RUN"
)

// 服务端核验结论。
const (
	VerifyPending = "PENDING"
	VerifyPassed  = "PASSED"
	VerifyFailed  = "FAILED"
)

// 门禁模式。
const (
	ModeOff     = "OFF"
	ModeObserve = "OBSERVE"
	ModeEnforce = "ENFORCE"
)

// 门禁判定。
const (
	DecisionAllow  = "ALLOW"
	DecisionBlock  = "BLOCK"
	DecisionRecord = "RECORD"
)

// 签名算法词表（只接受 Ed25519，未知算法一律拒绝；不自行设计加密算法）。
const (
	SignatureAlgorithmEd25519 = "ed25519"
)

// 限额（S0 契约 #5，R3 冻结值）。
const (
	MaxImportRequestBytes = 1 << 20        // 导入请求 1 MiB
	MaxManifestBytes      = 4 << 20        // manifest 4 MiB
	MaxChunkBytes         = 4 << 20        // 用例分块单块 4 MiB
	MaxChunksPerRun       = 64             // 每次运行最多 64 块
	MaxReportBytes        = 16 << 20       // 生成报告 16 MiB
	MaxPerfBytes          = 256 << 20      // 性能原始分布 256 MiB（流式）
	MaxLogBytes           = 64 << 20       // 日志关联摘要 64 MiB
	MaxTotalBytesPerRun   = 512 << 20      // 单次运行合计 512 MiB
	DefaultEvidenceMaxAge = 7 * 24 * 3600  // 证据默认有效期 7 天（秒）
	MinEvidenceMaxAge     = 24 * 3600      // 最短 1 天
	MaxEvidenceMaxAge     = 30 * 24 * 3600 // 最长 30 天
	MaxCasesPerRun        = 100000         // 用例索引条数硬上限
	maxRunIDLen           = 128
	maxKeyIDLen           = 128
)

// 候选配置指纹版本前缀：cfgfpv1 = 发布候选规范化配置哈希（configuration_hash）
// 的确定拼接「cfgfpv1:<hex>」。规范化方式随前缀版本化，禁止为命中旧证据
// 任意删除字段（S0 契约 #6）。configuration_hash 覆盖规则包/模型产物/有效配置
// 的完整生成 JSON；构建 digest 与编译器版本随 manifest 登记留痕。
const FingerprintPrefixV1 = "cfgfpv1:"

// 受信验签公钥登记（管理配置 system_settings，组/键固定）。
const (
	TrustedKeysSettingsGroup = "security_regression"
	TrustedKeysSettingsKey   = "trusted_verify_keys"
)

// 错误哨兵（门禁依赖不可用必须明确失败，不静默放行）。
var (
	ErrNotFound           = errors.New("regression: not found")
	ErrConflict           = errors.New("regression: conflict")
	ErrDuplicateKeys      = errors.New("regression: duplicate JSON keys")
	ErrNonCanonical       = errors.New("regression: manifest is not in canonical byte encoding")
	ErrUnknownAlgorithm   = errors.New("regression: unknown signature algorithm")
	ErrUnknownKeyID       = errors.New("regression: unregistered signature key_id")
	ErrRevokedKey         = errors.New("regression: signature key revoked")
	ErrBadSignature       = errors.New("regression: signature verification failed")
	ErrInvalidManifest    = errors.New("regression: invalid manifest")
	ErrHashMismatch       = errors.New("regression: evidence object hash mismatch")
	ErrObjectLimit        = errors.New("regression: evidence object exceeds size limit")
	ErrGateRejected       = errors.New("regression: publish blocked by regression gate")
	ErrGateUnavailable    = errors.New("regression: gate dependency unavailable")
	ErrVerificationFailed = errors.New("regression: evidence verification failed")
)
