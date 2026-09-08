// 外部命令与进程信号抽象：生产为带超时的 exec 实现；单测注入桩。
// 零新增依赖（os/exec 标准库）。
package havipd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Runner 外部命令抽象（只读查询与变更动作同构；keepalived 启动后自行
// daemonize，命令返回即完成启动发起，存活由 PID 轮询判定）。
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// CmdError 命令失败详情（非零退出或超时），Stderr 供状态信息摘录。
type CmdError struct {
	Name   string
	Args   []string
	Stderr string
	Err    error
}

func (e *CmdError) Error() string {
	cmd := e.Name + " " + strings.Join(e.Args, " ")
	if s := strings.TrimSpace(e.Stderr); s != "" {
		return fmt.Sprintf("%s: %v: %s", cmd, e.Err, s)
	}
	return fmt.Sprintf("%s: %v", cmd, e.Err)
}

// Unwrap 暴露底层错误。
func (e *CmdError) Unwrap() error { return e.Err }

// ExecRunner 生产执行器：exec 参数数组（不经 shell），单动作超时。
type ExecRunner struct {
	// Timeout 单动作超时（<=0 取 DefaultCmdTimeout）。
	Timeout time.Duration
}

func (r ExecRunner) timeout() time.Duration {
	if r.Timeout <= 0 {
		return DefaultCmdTimeout
	}
	return r.Timeout
}

// Run 实现 Runner。
func (r ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, r.timeout())
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if cctx.Err() == context.DeadlineExceeded {
		return out, &CmdError{Name: name, Args: args, Stderr: stderr.String(),
			Err: fmt.Errorf("超时（%s）", r.timeout())}
	}
	if err != nil {
		return out, &CmdError{Name: name, Args: args, Stderr: stderr.String(), Err: err}
	}
	return out, nil
}

// Process 进程信号/存活抽象（测试注入桩；生产为 syscall 实现）。
type Process interface {
	// Alive PID 是否存活（kill(pid, 0) 语义）。
	Alive(pid int) bool
	// Signal 向 PID 发信号（SIGTERM 停止 / SIGHUP 重载 keepalived）。
	Signal(pid int, sig os.Signal) error
}

// SyscallProcess 生产进程操作。
type SyscallProcess struct{}

// Alive 实现 Process：kill(pid, 0) + /proc 僵尸态排除——容器 PID1 不回收
// 子进程时，已退出的进程以 zombie 残留，kill(pid,0) 对 zombie 仍返回成功，
// 会把 stale pidfile 误判为「运行中」而错走重载路径（lab 实测暴露）。
func (SyscallProcess) Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if p.Signal(syscall.Signal(0)) != nil {
		return false
	}
	return !isZombie(pid)
}

// isZombie 读 /proc/<pid>/stat 判定僵尸态（Linux 专属，与本组件部署形态一致；
// 读失败按非僵尸处理——保持 kill(0) 语义，不放大误判面）。
func isZombie(pid int) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false
	}
	// stat 格式：pid (comm) state ...——comm 可含空格/括号，取最后一个 ')' 后的字段。
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return false
	}
	return s[idx+2] == 'Z'
}

// Signal 实现 Process。
func (SyscallProcess) Signal(pid int, sig os.Signal) error {
	if pid <= 0 {
		return fmt.Errorf("非法 PID: %d", pid)
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(sig)
}
