// ai-crawler 规则生成器：把 ai-robots-txt/ai.robots.txt 的 AI 爬虫 UA 清单
// （robots.txt 的 User-agent 行）转换为 CUSTOM_PACK 约定的 SecLang 标记规则
// （OBSERVE：pass+log，不阻断、不累加异常评分）。纯标准库，确定性输出
// （排序去重后按序分配规则 ID）。
//
// 输入与输出路径相对于本源文件目录解析，与执行时的工作目录无关：
//
//	go run ./tools/rulegen/ai-crawler            # 在本目录（含 go.mod）内等效为 go run .
//	go run tools/rulegen/ai-crawler/main.go      # 仓库根（无 go.mod）可用文件模式
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	baseID     = 1010001 // 规则 ID 起点（与 crawler-ua 生成器 1002001-1003501 段不重叠）
	inputFile  = "robots.txt"
	outputFile = "../../../gateway/rules/contrib/CUSTOM_PACK/ai-crawler-control.conf"
)

func selfDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "无法定位源文件路径")
		os.Exit(1)
	}
	return filepath.Dir(file)
}

// escapeOperator 转义双引号包裹的 SecLang operator 参数：@contains 为字面
// 子串匹配，反斜杠需原样呈现，故反斜杠与双引号都转义。
func escapeOperator(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// escapeMsg 转义单引号包裹的 msg 值：先反斜杠再单引号
// （Coraza parseActions 以 \' 判定转义，避免提前终止引号区间）。
func escapeMsg(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	return s
}

func main() {
	dir := selfDir()
	raw, err := os.ReadFile(filepath.Join(dir, inputFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取 %s 失败: %v\n", inputFile, err)
		os.Exit(1)
	}

	seen := map[string]struct{}{}
	var names []string
	skipped := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(key), "User-agent") {
			continue // Disallow 等其他指令不生成规则
		}
		name := strings.TrimSpace(val)
		if name == "" || name == "*" || strings.ContainsAny(name, "\r\t") {
			skipped++
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names) // 确定性：字节序排序后按序分配 ID

	var b strings.Builder
	b.WriteString(`# =============================================================================
# 九章自建规则包（CUSTOM_PACK）— AI 爬虫 UA 识别（ai-crawler-control）
#
# 来源：ai-robots-txt/ai.robots.txt（MIT License），PINNED 锁定见
#       tools/rulegen/ai-crawler/PINNED.txt（commit 987266f3c581bc6bb71aa075051731188ab2a075）。
#
# 本文件由 tools/rulegen/ai-crawler 生成，勿手改。
# 重新生成命令：go run ./tools/rulegen/ai-crawler
#   （在 tools/rulegen/ai-crawler 目录内等效执行 go run .；
#     仓库根目录无 go.mod 时用 go run tools/rulegen/ai-crawler/main.go）
#
# 规则 ID 段：1010001 起。
#
# 处置策略（重要）：本文件全部为"只标记"规则 —— pass + log，
#   不使用 block、不累加异常评分（OBSERVE 轨道），严重度仅 WARNING。
#   AI 爬虫 UA 命中仅用于观测与报表，是否处置由前台策略另行决定。
# =============================================================================

`)
	id := baseID
	for _, n := range names {
		fmt.Fprintf(&b, "SecRule REQUEST_HEADERS:User-Agent \"@contains %s\" \\\n", escapeOperator(n))
		b.WriteString("    \"id:")
		fmt.Fprintf(&b, "%d", id)
		b.WriteString(`,\
    phase:1,\
    pass,\
    log,\
    capture,\
    t:none,\
`)
		fmt.Fprintf(&b, "    msg:'AI crawler UA: %s',\\\n", escapeMsg(n))
		b.WriteString(`    tag:'attack-scanner',\
    tag:'ai-crawler',\
    tag:'CUSTOM_PACK',\
    ver:'CUSTOM_PACK/1.0.0',\
    severity:'WARNING'"

`)
		id++
	}
	fmt.Fprintf(&b, "# 生成统计：User-agent 条目 %d（跳过 %d），规则 ID %d-%d。\n",
		len(names), skipped, baseID, id-1)

	out := filepath.Join(dir, filepath.FromSlash(outputFile))
	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写出 %s 失败: %v\n", out, err)
		os.Exit(1)
	}
	fmt.Printf("User-agent条目=%d 跳过=%d 生成规则=%d ID段=%d-%d 输出=%s\n",
		len(names), skipped, len(names), baseID, id-1, out)
}
