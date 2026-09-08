// eventparser 是九章事件采集器 POC：
// 跟踪 Coraza JSON 审计日志，解析为九章标准安全事件并脱敏输出。
//
// 用法：
//
//	eventparser -audit /var/log/caddy/coraza-audit.log \
//	            -events /var/log/jiuzhang/events.jsonl \
//	            -errors /var/log/jiuzhang/parse-errors.jsonl \
//	            [-once] [-node gateway-poc-01]
//
// -once 模式处理完当前文件内容后退出（用于测试与批处理）；
// 默认模式持续跟踪文件增长（用于常驻采集）。
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/jiuzhang-waf/gateway/internal/eventparser"
)

// errorRecord 解析失败记录：不保留原始审计行（可能含 Authorization/Cookie/口令明文），
// 只留结构化摘要——tx_id（尽力提取）+ 行长度 + 行内容哈希（与原始审计日志对照检索用，
// 原始行仍在 0600 审计日志文件中可供排查）。
type errorRecord struct {
	OccurredAt string `json:"occurred_at"`
	Reason     string `json:"reason"`
	TxID       string `json:"tx_id,omitempty"`
	LineBytes  int    `json:"line_bytes"`
	LineSHA256 string `json:"line_sha256"`
}

// summarizeLine 生成失败行的结构化摘要（不含原始内容，杜绝敏感数据落错误文件）。
func summarizeLine(line []byte, reason string) errorRecord {
	rec := errorRecord{
		OccurredAt: time.Now().UTC().Format(time.RFC3339),
		Reason:     reason,
		LineBytes:  len(line),
	}
	sum := sha256.Sum256(line)
	rec.LineSHA256 = hex.EncodeToString(sum[:])
	var entry eventparser.AuditEntry
	if err := json.Unmarshal(line, &entry); err == nil {
		rec.TxID = entry.Transaction.ID
	}
	return rec
}

func main() {
	auditPath := flag.String("audit", "/var/log/caddy/coraza-audit.log", "Coraza JSON 审计日志路径")
	eventsPath := flag.String("events", "events.jsonl", "标准事件输出路径")
	errorsPath := flag.String("errors", "parse-errors.jsonl", "解析失败输出路径")
	node := flag.String("node", "gateway-poc-01", "网关节点标识")
	appID := flag.String("app-id", "poc-app", "应用标识")
	appName := flag.String("app-name", "测试应用", "应用名称")
	appDomain := flag.String("app-domain", "waf.test", "应用域名")
	once := flag.Bool("once", false, "处理完当前文件后退出")
	poll := flag.Duration("poll", 500*time.Millisecond, "跟踪模式的轮询间隔")
	flag.Parse()

	app := eventparser.ApplicationRef{ID: *appID, Name: *appName, Domain: *appDomain}
	if err := run(*auditPath, *eventsPath, *errorsPath, *node, app, *once, *poll); err != nil {
		log.Fatalf("eventparser error: %v", err)
	}
}

func run(auditPath, eventsPath, errorsPath, node string, app eventparser.ApplicationRef, once bool, poll time.Duration) error {
	eventsFile, err := os.OpenFile(eventsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open events output: %w", err)
	}
	defer eventsFile.Close()

	errorsFile, err := os.OpenFile(errorsPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open errors output: %w", err)
	}
	defer errorsFile.Close()

	var offset int64
	for {
		n, follow, err := processNewLines(auditPath, &offset, eventsFile, errorsFile, node, app)
		if err != nil {
			return err
		}
		if n > 0 {
			log.Printf("parsed %d audit entr(ies), offset=%d", n, offset)
		}
		if once {
			return nil
		}
		if !follow {
			time.Sleep(poll)
		}
	}
}

// processNewLines 从 offset 起读取新增完整行并逐行解析。
// 返回值 n 为处理行数，follow 表示文件可能仍有新内容（供调用方决定是否立即重读）。
func processNewLines(auditPath string, offset *int64, eventsFile, errorsFile *os.File, node string, app eventparser.ApplicationRef) (int, bool, error) {
	f, err := os.Open(auditPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil // 审计日志尚未生成（无攻击事件时正常）
		}
		return 0, false, fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return 0, false, fmt.Errorf("stat audit log: %w", err)
	}
	// 文件被截断（如日志轮转）时从头读取
	if info.Size() < *offset {
		*offset = 0
	}
	if info.Size() == *offset {
		return 0, false, nil
	}

	if _, err := f.Seek(*offset, io.SeekStart); err != nil {
		return 0, false, fmt.Errorf("seek audit log: %w", err)
	}

	reader := bufio.NewReader(f)
	n := 0
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			// 只处理完整行（以换行结尾）；不完整行等待下次读取
			if line[len(line)-1] == '\n' {
				n++
				processLine(line, eventsFile, errorsFile, node, app)
				pos, _ := f.Seek(0, io.SeekCurrent)
				*offset = pos - int64(reader.Buffered())
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, false, fmt.Errorf("read audit log: %w", err)
		}
	}
	return n, true, nil
}

func processLine(line []byte, eventsFile, errorsFile *os.File, node string, app eventparser.ApplicationRef) {
	evt, err := eventparser.ParseLine(line, node, app)
	if err != nil {
		// 解析失败不静默丢弃：写入错误文件（结构化摘要，不落原始行——含敏感头/口令明文风险）
		rec := summarizeLine(line, err.Error())
		b, _ := json.Marshal(rec)
		_, _ = errorsFile.Write(append(b, '\n'))
		return
	}
	b, err := json.Marshal(evt)
	if err != nil {
		rec := summarizeLine(line, fmt.Sprintf("marshal event: %v", err))
		eb, _ := json.Marshal(rec)
		_, _ = errorsFile.Write(append(eb, '\n'))
		return
	}
	_, _ = eventsFile.Write(append(b, '\n'))
}
