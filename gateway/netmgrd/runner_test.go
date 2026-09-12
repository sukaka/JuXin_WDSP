package netmgrd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerSuccess(t *testing.T) {
	r := ExecRunner{Timeout: 2 * time.Second}
	out, err := r.Query(context.Background(), "sh", "-c", "echo hello")
	if err != nil {
		t.Fatalf("应成功: %v", err)
	}
	if !strings.Contains(string(out), "hello") {
		t.Fatalf("应捕获标准输出: %q", out)
	}
}

func TestExecRunnerCapturesStderr(t *testing.T) {
	r := ExecRunner{Timeout: 2 * time.Second}
	err := r.Exec(context.Background(), "sh", "-c", "echo boom 1>&2; exit 3")
	var ce *CmdError
	if !errors.As(err, &ce) {
		t.Fatalf("失败应返回 *CmdError: %T %v", err, err)
	}
	if !strings.Contains(ce.Stderr, "boom") {
		t.Fatalf("应捕获 stderr 供状态信息摘录: %q", ce.Stderr)
	}
	if !strings.Contains(ce.Error(), "boom") {
		t.Fatalf("Error() 应含 stderr 摘要: %s", ce.Error())
	}
}

func TestExecRunnerTimeout(t *testing.T) {
	r := ExecRunner{Timeout: 100 * time.Millisecond}
	start := time.Now()
	err := r.Exec(context.Background(), "sh", "-c", "sleep 5")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("超时应报错")
	}
	if !strings.Contains(err.Error(), "超时") {
		t.Fatalf("应标明超时: %v", err)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("超时应及时终止命令（耗时 %s）", elapsed)
	}
}

func TestDryRunner(t *testing.T) {
	real := &fakeRunner{dump: []byte(`[]`)}
	var buf bytes.Buffer
	d := &DryRunner{Real: real, Out: &buf}

	// Query 委托真实执行器（只读查询真实执行以产出准确计划）
	out, err := d.Query(context.Background(), "ip", "-j", "-d", "addr", "show")
	if err != nil || string(out) != "[]" {
		t.Fatalf("Query 应委托真实执行器: out=%q err=%v", out, err)
	}
	// Exec 只打印/记录不执行，永远成功
	if err := d.Exec(context.Background(), "ip", "link", "add", "br0", "type", "bridge"); err != nil {
		t.Fatalf("dry-run Exec 不应失败: %v", err)
	}
	if len(d.Commands) != 1 || d.Commands[0] != "ip link add br0 type bridge" {
		t.Fatalf("应记录未执行命令: %v", d.Commands)
	}
	if !strings.Contains(buf.String(), "+ ip link add br0 type bridge") {
		t.Fatalf("应打印计划命令: %q", buf.String())
	}
	// dry-run 下真实执行器不得收到任何 Exec
	if len(real.execLog()) != 0 {
		t.Fatalf("dry-run 不得执行变更: %v", real.execLog())
	}
}
