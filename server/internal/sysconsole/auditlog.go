// auditlog.go 控制台审计：登录与每条命令记录（时间/账号/动作/结果）。
// 优先经 logger(1) 写 syslog/journal——控制台以普通用户运行，syslog 由 root 守护进程落盘，
// 使用控制台的客户无权篡改；logger 不可用时降级追加本地文件（交付镜像均有 logger）。
package sysconsole

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// AuditEntry 一条审计记录。
type AuditEntry struct {
	Time    string `json:"ts"`
	User    string `json:"user"`
	Action  string `json:"action"`  // login / command
	Detail  string `json:"detail"`  // 命令原文或登录结果说明
	Success bool   `json:"success"` // 执行结果
}

// AuditLogger 审计输出器。sysTag 非空时优先 syslog（`logger -t <sysTag>`），
// 失败再追加 fallbackPath；两者都不可用时 stderr 提示，不静默丢弃。
type AuditLogger struct {
	sysTag       string
	fallbackPath string
}

// NewAuditLogger 创建（fallbackPath 为本地文件兜底；传空串表示仅 syslog）。
func NewAuditLogger(sysTag, fallbackPath string) *AuditLogger {
	return &AuditLogger{sysTag: sysTag, fallbackPath: fallbackPath}
}

// Log 记录一条审计。
func (l *AuditLogger) Log(user, action, detail string, success bool) {
	e := AuditEntry{
		Time:    time.Now().Format(time.RFC3339),
		User:    user,
		Action:  action,
		Detail:  detail,
		Success: success,
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	if l.sysTag != "" {
		if err := exec.Command("logger", "-t", l.sysTag, "--", string(raw)).Run(); err == nil {
			return
		}
	}
	if l.fallbackPath != "" {
		if f, err := os.OpenFile(l.fallbackPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err == nil {
			defer f.Close()
			_, _ = f.Write(append(raw, '\n'))
			return
		}
	}
	fmt.Fprintf(os.Stderr, "[audit] 无法落审计（syslog/文件均不可用）：%s %s\n", action, detail)
}
