// crawler-ua 规则生成器：把 monperrus/crawler-user-agents 的爬虫 UA 正则
// JSON 转换为 CUSTOM_PACK 约定的 SecLang 标记规则（OBSERVE：pass+log，不阻断、
// 不累加异常评分）。纯标准库，确定性输出（排序后按序分配规则 ID）。
//
// 输入与输出路径相对于本源文件目录解析，与执行时的工作目录无关：
//
//	go run ./tools/rulegen/crawler-ua            # 在本目录（含 go.mod）内等效为 go run .
//	go run tools/rulegen/crawler-ua/main.go      # 仓库根（无 go.mod）可用文件模式
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const (
	baseID     = 1002001 // 规则 ID 起点（1000300-1000599 段已被 cloud-abuse/api-abuse/sensitive-exposure 占用，依设计文档 §4.1 顺延至 1,002,xxx 起）
	inputFile  = "crawler-user-agents.json"
	outputFile = "../../../gateway/rules/contrib/CUSTOM_PACK/scanner-fingerprints-ext.conf"
)

// entry 对应上游 JSON 数组元素；仅需 pattern 字段，其余字段忽略。
type entry struct {
	Pattern string `json:"pattern"`
}

func selfDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "无法定位源文件路径")
		os.Exit(1)
	}
	return filepath.Dir(file)
}

// escapeOperator 转义双引号包裹的 SecLang operator 参数：仅需处理双引号
// （反斜杠为正则转义，Coraza UnescapeQuotedString 只折叠 \"，其余原样保留）。
func escapeOperator(p string) string {
	return strings.ReplaceAll(p, `"`, `\"`)
}

// escapeMsg 转义单引号包裹的 msg 值：先反斜杠再单引号
// （Coraza parseActions 以 \' 判定转义，避免提前终止引号区间）。
func escapeMsg(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

// annotate 生成 msg 用的 pattern 简注：还原正则转义斜杠便于阅读，按 rune 截断。
func annotate(pattern string) string {
	a := strings.ReplaceAll(pattern, `\/`, `/`)
	r := []rune(a)
	if len(r) > 48 {
		r = append(r[:45], '.', '.', '.')
	}
	return string(r)
}

func main() {
	dir := selfDir()
	raw, err := os.ReadFile(filepath.Join(dir, inputFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取 %s 失败: %v\n", inputFile, err)
		os.Exit(1)
	}
	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		fmt.Fprintf(os.Stderr, "解析 %s 失败: %v\n", inputFile, err)
		os.Exit(1)
	}

	seen := map[string]struct{}{}
	var patterns []string
	skippedInvalid := 0
	for _, e := range entries {
		p := e.Pattern
		if p == "" {
			skippedInvalid++
			continue
		}
		// 控制字符会破坏 SecLang 单行结构，视为非法。
		if strings.ContainsAny(p, "\r\n\t") {
			skippedInvalid++
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			fmt.Fprintf(os.Stderr, "跳过非法 pattern（编译失败）: %q: %v\n", p, err)
			skippedInvalid++
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		patterns = append(patterns, p)
	}
	sort.Strings(patterns) // 确定性：字节序排序后按序分配 ID

	var b strings.Builder
	b.WriteString(`# =============================================================================
# 九章自建规则包（CUSTOM_PACK）— 爬虫 UA 指纹扩充（scanner-fingerprints-ext）
#
# 来源：monperrus/crawler-user-agents（MIT License），PINNED 锁定见
#       tools/rulegen/crawler-ua/PINNED.txt（commit 9345a7ad9c49cd0fbd880eb5a84ed1f358fc6a97）。
#
# 本文件由 tools/rulegen/crawler-ua 生成，勿手改。
# 重新生成命令：go run ./tools/rulegen/crawler-ua
#   （在 tools/rulegen/crawler-ua 目录内等效执行 go run .；
#     仓库根目录无 go.mod 时用 go run tools/rulegen/crawler-ua/main.go）
#
# 规则 ID 段：1002001 起（任务建议的 1000300-1000599 段经全库查重已被
#   cloud-abuse/api-abuse/sensitive-exposure 占用，依 docs/WAF_RULE_ENRICHMENT_DESIGN.md
#   §4.1「新增自建规则顺延 1,002,xxx 起」重新分配，分配表见该次投递报告）。
#
# 处置策略（重要）：本文件全部为"只标记"规则 —— pass + log，
#   不使用 block、不累加异常评分（OBSERVE 轨道），严重度仅 WARNING。
#   爬虫 UA 特征对正常流量有误标可能（如开发调试 UA），只记录不处置。
# =============================================================================

`)
	id := baseID
	for _, p := range patterns {
		fmt.Fprintf(&b, "SecRule REQUEST_HEADERS:User-Agent \"@rx %s\" \\\n", escapeOperator(p))
		b.WriteString("    \"id:")
		fmt.Fprintf(&b, "%d", id)
		b.WriteString(`,\
    phase:1,\
    pass,\
    log,\
    capture,\
    t:none,\
`)
		fmt.Fprintf(&b, "    msg:'Scanner fingerprint: crawler UA (%s)',\\\n", escapeMsg(annotate(p)))
		b.WriteString(`    tag:'attack-scanner',\
    tag:'crawler-ua',\
    tag:'CUSTOM_PACK',\
    ver:'CUSTOM_PACK/1.0.0',\
    severity:'WARNING'"

`)
		id++
	}
	fmt.Fprintf(&b, "# 生成统计：上游条目 %d，去重后 %d，跳过非法 %d，规则 ID %d-%d。\n",
		len(entries), len(patterns), skippedInvalid, baseID, id-1)

	out := filepath.Join(dir, filepath.FromSlash(outputFile))
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写出 %s 失败: %v\n", out, err)
		os.Exit(1)
	}
	fmt.Printf("上游条目=%d 去重后=%d 跳过非法=%d 生成规则=%d ID段=%d-%d 输出=%s\n",
		len(entries), len(patterns), skippedInvalid, len(patterns), baseID, id-1, out)
}
