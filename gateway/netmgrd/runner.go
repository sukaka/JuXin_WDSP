// ip/sysctl 命令执行抽象：生产为带超时的 exec 实现；--dry-run 为只打印不执行；
// 单测注入脚本化桩。零新增依赖（os/exec 标准库）。
package netmgrd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
)

// Runner 命令执行抽象。Query 为只读查询（`ip -j ... show`；--dry-run 下真实
// 执行以产出准确计划）；Exec 为变更动作（--dry-run 下只打印不执行）。
type Runner interface {
	// Query 执行只读命令并返回标准输出。
	Query(ctx context.Context, name string, args ...string) ([]byte, error)
	// Exec 执行变更命令；失败返回 *CmdError（含 stderr 摘要）。
	Exec(ctx context.Context, name string, args ...string) error
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

// Unwrap 暴露底层错误（exit code / 超时判别）。
func (e *CmdError) Unwrap() error { return e.Err }

// ExecRunner 生产执行器：exec 参数数组（不经 shell），每个动作独立超时。
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

// Query 实现 Runner。
func (r ExecRunner) Query(ctx context.Context, name string, args ...string) ([]byte, error) {
	return r.run(ctx, name, args)
}

// Exec 实现 Runner（丢弃标准输出，仅判成败）。
func (r ExecRunner) Exec(ctx context.Context, name string, args ...string) error {
	_, err := r.run(ctx, name, args)
	return err
}

func (r ExecRunner) run(ctx context.Context, name string, args []string) ([]byte, error) {
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

// DryRunner --dry-run 执行器：Query 委托真实执行器（只读，安全）以产出准确
// 计划；Exec 只打印/记录不执行。
type DryRunner struct {
	// Real 只读查询委托（生产为 ExecRunner）。
	Real Runner
	// Out 变更命令打印目标（main 传 os.Stdout；nil 则只记录）。
	Out io.Writer
	// Commands 已记录（未执行）的变更命令，供测试/运维断言。
	Commands []string
}

// Query 实现 Runner（真实执行只读查询）。
func (d *DryRunner) Query(ctx context.Context, name string, args ...string) ([]byte, error) {
	return d.Real.Query(ctx, name, args...)
}

// Exec 实现 Runner（只打印不执行，永远返回成功）。
func (d *DryRunner) Exec(_ context.Context, name string, args ...string) error {
	cmd := name + " " + strings.Join(args, " ")
	d.Commands = append(d.Commands, cmd)
	if d.Out != nil {
		fmt.Fprintf(d.Out, "+ %s\n", cmd)
	}
	return nil
}
