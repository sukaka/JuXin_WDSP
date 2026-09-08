package botchallenge

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// PoW 题目构造（任务书 §5.2，B2 冻结）：
//
//	digest = SHA-256( "wdsp-bot-pow-v1" ‖ lp(challenge_id) ‖ lp(nonce) ‖ lp(app_id)
//	                  ‖ lp(host) ‖ lp(solution) )
//	通过 ⟺ digest 前 difficulty 个比特为 0。
//	- lp(x) = 4 字节大端长度前缀 ‖ x：固定编码 + 无歧义长度前缀，杜绝字段边界歧义拼接；
//	- 标准 SHA-256（标准库），禁止自创加密算法；
//	- 应用/Host 参与哈希：一题一解绑定单上下文，跨应用/Host 不可移植；
//	  会话绑定在状态层（挑战记录存会话摘要，verify 强制 Cookie 摘要一致）——
//	  会话 ID 不出现在题目输入中（会话 Cookie 为 HttpOnly，页面 JS 本就不可取）。
//	- difficulty 由服务端状态决定（verify 请求无难度字段——客户端无从降难度）；
//	- solution 为有界长度十进制 uint64（1..20 位数字）。
const powDomain = "wdsp-bot-pow-v1"

// randRead crypto/rand 读取包装（随机源故障如实上报——fail-closed，绝不降级为弱随机）。
func randRead(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// lp 写长度前缀帧（与 counters.HashParts 同一帧纪律，输出完整 256 bit 摘要）。
func lp(h hash.Hash, b []byte) {
	var lb [4]byte
	n := len(b)
	lb[0] = byte(n >> 24)
	lb[1] = byte(n >> 16)
	lb[2] = byte(n >> 8)
	lb[3] = byte(n)
	h.Write(lb[:])
	h.Write(b)
}

// powDigest 计算题目摘要（challengeID/nonce 为 hex 串；solution 为十进制串）。
func powDigest(challengeID, nonce, appID, host, solution string) ([32]byte, error) {
	cid, err := hex.DecodeString(challengeID)
	if err != nil || len(cid) != challengeIDBytes {
		return [32]byte{}, fmt.Errorf("challenge_id 非法")
	}
	nn, err := hex.DecodeString(nonce)
	if err != nil || len(nn) != nonceBytes {
		return [32]byte{}, fmt.Errorf("nonce 非法")
	}
	if !validSolution(solution) {
		return [32]byte{}, fmt.Errorf("solution 非法")
	}
	h := sha256.New()
	h.Write([]byte(powDomain))
	lp(h, cid)
	lp(h, nn)
	lp(h, []byte(appID))
	lp(h, []byte(normalizeHost(host)))
	lp(h, []byte(solution))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// leadingZeroBits 摘要前导零比特数。
func leadingZeroBits(digest [32]byte) int {
	n := 0
	for _, b := range digest {
		if b == 0 {
			n += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				return n
			}
			n++
		}
	}
	return n
}

// CheckSolution PoW 判定（服务端权威校验；difficulty 来自服务端状态）。
func CheckSolution(challengeID, nonce, appID, host, solution string, difficulty int) (bool, error) {
	d, err := powDigest(challengeID, nonce, appID, host, solution)
	if err != nil {
		return false, err
	}
	return leadingZeroBits(d) >= difficulty, nil
}

// validSolution solution 词形：1..20 位十进制数字（uint64 有界）。
func validSolution(s string) bool {
	if len(s) == 0 || len(s) > maxSolutionLen {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	if _, err := strconv.ParseUint(s, 10, 64); err != nil {
		return false
	}
	return true
}

// Solve 服务端测试/自检用求解器（浏览器 JS 求解的同构实现；有界迭代）。
func Solve(challengeID, nonce, appID, host string, difficulty int, maxIter uint64) (string, bool) {
	for i := uint64(0); i < maxIter; i++ {
		cand := strconv.FormatUint(i, 10)
		ok, err := CheckSolution(challengeID, nonce, appID, host, cand, difficulty)
		if err == nil && ok {
			return cand, true
		}
	}
	return "", false
}

// normalizeHost Host 规范化（小写； binding 比较与摘要在规范化后进行——
// Host 头大小写不敏感，端口保留原样参与精确匹配）。
func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// flowID 脱敏关联指纹：SHA-256(domain ‖ challenge_id 字节) 截断 16 hex——
// 单向（挑战 ID 为 128bit 随机，哈希不可逆推）、确定性（签发/验证/通行三阶段可关联），
// 不含任何可回放材料。
func flowID(challengeID string) string {
	raw, err := hex.DecodeString(challengeID)
	if err != nil {
		raw = []byte(challengeID)
	}
	h := sha256.New()
	h.Write([]byte("wdsp-bot-flow-v1"))
	lp(h, raw)
	return hex.EncodeToString(h.Sum(nil))[:16]
}
