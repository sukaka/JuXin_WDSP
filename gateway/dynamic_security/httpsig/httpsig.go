// Package httpsig HTTP Message Signatures（RFC 9421）+ Content-Digest
// （RFC 9530）+ 结构化字段（RFC 8941 子集）验证纯库（NG-ID G1 批次 A，
// docs/nextgen/NG-ID-g1-machine-identity.md §5 批次 A 线契约逐字冻结——
// B2 直接消费，签名不得改名改形）。
//
// 范围（§1.4 十步固定序中的纯函数部分）：
//   - 步 1：头形态解析（RFC 8941 SF 子集；恰好一个签名标签——多标签拒收；
//     签名参数 created/expires/nonce/keyid/alg 齐全性）；
//   - 步 6：覆盖成分充分性（必含 @method/@authority/@path；有 query 必含
//     @query；有 body 必含 content-digest；权限关键头（authorization/
//     proxy-authorization/x-api-key/cookie——认证检测器消费面同源）存在必被
//     覆盖——未签名的权限关键头不得进入可信上下文，§12.2-3 原文）；
//   - 步 7：目标绑定（@authority=可信代理处理后的 Host 原文、@path raw
//     不归一、@query 原文——§1.1 规范化口径逐字执行；RFC 9421 §2.2.3 的
//     小写归一以设计冻结文本为准不执行（登记偏差——RFC 向量主机名本已
//     小写，两者不冲突））；
//   - 步 8：content-digest 重算比对（sha-256/sha-512 双算法，常量时间比较）；
//   - 步 9：签名基线重构（参数序与未知参数按 Signature-Input 原文忠实重现——
//     Params 冻结形状不携带参数序，重构经请求头重读同一解析引擎完成）+
//     密码学验签（stdlib crypto：ed25519/ecdsa-p256-sha256（R||S 64 字节拼接，
//     非 ASN.1）/rsa-pss-sha512（盐长 64=哈希长）；失败不区分「签名错/基线错」
//     防探测——事件细分属 B2 词表，本层 ErrVerify 只承载错误分类）。
//
// 步 2/3/4/5/10（登记册查找/键状态机/时效判定/重放链位）属 B2——Params 只承载
// 解析产出；重放存储（ReplayStore）本批交付 Store 与脚本，链位与缺席处置在 B2。
// 全部计算在调用方 goroutine（无后台任务，ctx 取消由调用方承担）。
package httpsig

import (
	"errors"
	"fmt"
	"strings"
)

// Budgets 资源预算（§1.9 冻结常量首批；各字段 ≤0 时按 DefaultBudgets 兜底）。
type Budgets struct {
	MaxHeaderBytes        int // Signature-Input+Signature 头合计（头解析内存上界）
	MaxComponents         int // 覆盖成分数/签名标签
	MaxComponentNameLen   int // 成分名长度
	MaxParamsPerComponent int // 参数个数/成分
	MaxBodyBytes          int // content-digest 体预算（体保全同源上限）
}

// DefaultBudgets §1.9 冻结常量。
func DefaultBudgets() Budgets {
	return Budgets{
		MaxHeaderBytes:        8 << 10,
		MaxComponents:         32,
		MaxComponentNameLen:   128,
		MaxParamsPerComponent: 8,
		MaxBodyBytes:          4 << 20,
	}
}

func (b Budgets) withDefaults() Budgets {
	d := DefaultBudgets()
	if b.MaxHeaderBytes <= 0 {
		b.MaxHeaderBytes = d.MaxHeaderBytes
	}
	if b.MaxComponents <= 0 {
		b.MaxComponents = d.MaxComponents
	}
	if b.MaxComponentNameLen <= 0 {
		b.MaxComponentNameLen = d.MaxComponentNameLen
	}
	if b.MaxParamsPerComponent <= 0 {
		b.MaxParamsPerComponent = d.MaxParamsPerComponent
	}
	if b.MaxBodyBytes <= 0 {
		b.MaxBodyBytes = d.MaxBodyBytes
	}
	return b
}

// Key 登记册行编译产物（公钥 PEM；alg 为登记算法——与签名参数 alg 一致性
// 双重核对（§1.4 步 3 语义的纯函数侧承载））。
type Key struct {
	Kid          string
	Alg          string
	PublicKeyPEM []byte
}

// Params 签名参数解析产出（线契约逐字冻结形状；只承载解析产出——
// 时效/状态机/登记册语义属 B2）。
type Params struct {
	KeyID             string
	Alg               string
	Nonce             string
	Created           int64
	Expires           int64
	CoveredComponents []string
}

// 错误三分类（线契约冻结；ErrVerify 只承载错误分类——事件/reason 词表
// （MID-*）属 B2，本层不越界定义）。
var (
	ErrMalformed = errors.New("httpsig: malformed signature headers")
	ErrBudget    = errors.New("httpsig: budget exceeded")
	ErrVerify    = errors.New("httpsig: signature verification failed")
)

// BudgetError 预算触顶明细（rule 为本层内部明细词表——非 B2 冻结事件词表）。
type BudgetError struct {
	Rule   string
	Limit  int
	Actual int
}

func (e *BudgetError) Error() string {
	return fmt.Sprintf("httpsig: budget exceeded %s (limit %d, actual %d)", e.Rule, e.Limit, e.Actual)
}

func (e *BudgetError) Unwrap() error { return ErrBudget }

// malformed/verifyErr 错误构造（ErrMalformed/ErrVerify 哨兵链 + 明细文本）。
func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

func verifyErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrVerify, fmt.Sprintf(format, args...))
}

// ParseHeaders 头形态解析（线契约逐字冻结签名，§1.4 步 1）：
// Signature-Input（Dictionary，恰好一个签名标签，值=覆盖成分 Inner List +
// 签名参数）+ Signature（Dictionary，恰好一个同形标签，值=签名 Byte Sequence）。
// 签名参数齐全性（created/expires 整数必填；nonce/keyid/alg 字符串/令牌必填——
// 长度与时效判定属 B2 步 5）与成分预算在本层执行；多签名标签 G1 拒收。
func ParseHeaders(signatureInput, signature string, b Budgets) (*Params, error) {
	b = b.withDefaults()
	if len(signatureInput)+len(signature) > b.MaxHeaderBytes {
		return nil, &BudgetError{Rule: "header_bytes_exceeded", Limit: b.MaxHeaderBytes, Actual: len(signatureInput) + len(signature)}
	}
	if strings.TrimSpace(signatureInput) == "" || strings.TrimSpace(signature) == "" {
		return nil, malformed("Signature-Input/Signature 缺一")
	}
	inputMembers, err := parseSFDictionary(signatureInput)
	if err != nil {
		return nil, malformed("Signature-Input: %v", err)
	}
	if len(inputMembers) != 1 {
		return nil, malformed("Signature-Input: 恰好一个签名标签（多标签 G1 拒收），实际 %d", len(inputMembers))
	}
	m := inputMembers[0]
	if !m.IsList {
		return nil, malformed("Signature-Input: 标签值必须为 Inner List")
	}
	// 成分预算与形态
	if len(m.Items) > b.MaxComponents {
		return nil, &BudgetError{Rule: "component_count_exceeded", Limit: b.MaxComponents, Actual: len(m.Items)}
	}
	p := &Params{}
	for _, item := range m.Items {
		var name string
		switch item.Value.Kind {
		case sfValueString, sfValueToken:
			name = item.Value.Str
		default:
			return nil, malformed("覆盖成分必须为字符串/令牌形态（kind=%d）", item.Value.Kind)
		}
		if len(name) > b.MaxComponentNameLen {
			return nil, &BudgetError{Rule: "component_name_len_exceeded", Limit: b.MaxComponentNameLen, Actual: len(name)}
		}
		if len(item.Params) > b.MaxParamsPerComponent {
			return nil, &BudgetError{Rule: "component_params_exceeded", Limit: b.MaxParamsPerComponent, Actual: len(item.Params)}
		}
		if !validComponentName(name) {
			return nil, malformed("覆盖成分名非法: %q", name)
		}
		p.CoveredComponents = append(p.CoveredComponents, name)
	}
	// 签名参数齐全性（§1.4 步 1：created/expires/nonce/keyid/alg 五参数齐全）
	for _, pr := range m.ListParams {
		switch pr.Name {
		case "created":
			if pr.Value.Kind != sfValueInteger {
				return nil, malformed("created 必须为整数")
			}
			p.Created = pr.Value.Int
		case "expires":
			if pr.Value.Kind != sfValueInteger {
				return nil, malformed("expires 必须为整数")
			}
			p.Expires = pr.Value.Int
		case "nonce":
			if pr.Value.Kind != sfValueString && pr.Value.Kind != sfValueToken {
				return nil, malformed("nonce 必须为字符串/令牌")
			}
			p.Nonce = pr.Value.Str
		case "keyid":
			if pr.Value.Kind != sfValueString && pr.Value.Kind != sfValueToken {
				return nil, malformed("keyid 必须为字符串/令牌")
			}
			p.KeyID = pr.Value.Str
		case "alg":
			if pr.Value.Kind != sfValueString && pr.Value.Kind != sfValueToken {
				return nil, malformed("alg 必须为字符串/令牌")
			}
			p.Alg = pr.Value.Str
		default:
			// 未知参数（如应用级 tag）：容忍保序（基线重构经原文重读重现——
			// RFC 9421 附录 B.2.2 先例；不冒充理解语义）
		}
	}
	if p.KeyID == "" || p.Alg == "" || p.Nonce == "" || p.Created == 0 || p.Expires == 0 {
		return nil, malformed("签名参数 created/expires/nonce/keyid/alg 须齐全")
	}
	// Signature 头：恰好一个标签 + Byte Sequence 值（标签一致性在验签层
	// 经原文重读交叉核对——Params 冻结形状不携带标签）
	sigMembers, err := parseSFDictionary(signature)
	if err != nil {
		return nil, malformed("Signature: %v", err)
	}
	if len(sigMembers) != 1 {
		return nil, malformed("Signature: 恰好一个签名标签，实际 %d", len(sigMembers))
	}
	if sigMembers[0].IsList || sigMembers[0].Item.Value.Kind != sfValueBytes {
		return nil, malformed("Signature: 标签值必须为 Byte Sequence（:base64:）")
	}
	return p, nil
}

// validComponentName 覆盖成分名字符集（小写 header 名形或 @派生名形——
// 词汇合法性（哪个 @名受支持）属验签层；本层只锁字符集防乱码）。
func validComponentName(name string) bool {
	if name == "" {
		return false
	}
	if name[0] == '@' {
		if len(name) == 1 {
			return false
		}
		for i := 1; i < len(name); i++ {
			c := name[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
		return true
	}
	// header 字段名：RFC 9110 token 的小写形（大写拒收——RFC 9421 成分名小写纪律）
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '!' || c == '#' ||
			c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
			c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~') {
			return false
		}
	}
	return true
}
