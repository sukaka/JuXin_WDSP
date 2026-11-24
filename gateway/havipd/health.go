// 容器与运维探针健康检查（--healthcheck）：校验状态文件存在、近期已刷新且 JSON 合法。
package havipd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// DefaultHealthMaxAge 状态文件最大允许陈旧时间（havipd 默认每秒刷新一次状态）。
const DefaultHealthMaxAge = 30 * time.Second

// CheckHealth 校验 havipd 状态文件存在、mtime 未超过 maxAge 且为合法 Status JSON。
func CheckHealth(statusPath string, maxAge time.Duration) error {
	return checkHealthAt(statusPath, maxAge, time.Now())
}

func checkHealthAt(statusPath string, maxAge time.Duration, now time.Time) error {
	if statusPath == "" {
		return fmt.Errorf("状态文件路径为空")
	}
	if maxAge <= 0 {
		maxAge = DefaultHealthMaxAge
	}
	fi, err := os.Stat(statusPath)
	if err != nil {
		return fmt.Errorf("读取状态文件失败: %w", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("状态路径是目录而非文件: %s", statusPath)
	}
	if age := now.Sub(fi.ModTime()); age > maxAge {
		return fmt.Errorf("状态文件已过期（上次刷新距今 %s，上限 %s）", age.Round(time.Second), maxAge)
	}
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return fmt.Errorf("读取状态文件内容失败: %w", err)
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return fmt.Errorf("状态文件 JSON 非法: %w", err)
	}
	switch st.State {
	case StateMaster, StateBackup, StateFault, StateDisabled, StateStopped:
		return nil
	default:
		return fmt.Errorf("状态文件 state 取值非法: %q", st.State)
	}
}
