// hastatus 清扫器测试：状态文件缺失/解析失败/异常/恢复全路径。
package hastatus

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/systemalerts"
)

// fakeAlerter 记录 Raise/AutoRecover 调用。
type fakeAlerter struct {
	raises   []string
	recovers []string
}

func (f *fakeAlerter) NotifyFailure(_ context.Context, alertType, component, title, message string) (*systemalerts.Alert, error) {
	f.raises = append(f.raises, alertType+"|"+component+"|"+title+"|"+message)
	return nil, nil
}

func (f *fakeAlerter) AutoRecover(_ context.Context, component string, alertTypes ...string) (int, error) {
	f.recovers = append(f.recovers, component+"|"+strings.Join(alertTypes, ","))
	return len(alertTypes), nil
}

func (f *fakeAlerter) hasRaise(sub string) bool {
	for _, r := range f.raises {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func (f *fakeAlerter) hasRecover(sub string) bool {
	for _, r := range f.recovers {
		if strings.Contains(r, sub) {
			return true
		}
	}
	return false
}

func newTestSweeper(t *testing.T) (*Sweeper, *fakeAlerter, string) {
	t.Helper()
	dir := t.TempDir()
	fa := &fakeAlerter{}
	sv := NewSweeper(dir).SetAlerter(fa)
	return sv, fa, dir
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNoFilesNoAlert(t *testing.T) {
	sv, fa, _ := newTestSweeper(t)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fa.raises) != 0 {
		t.Fatalf("无状态文件不应告警: %v", fa.raises)
	}
	// 缺失 = 收回：对既有告警发恢复
	if !fa.hasRecover(ComponentNetwork) || !fa.hasRecover(ComponentHAVIP) {
		t.Fatalf("应有恢复调用: %v", fa.recovers)
	}
}

func TestNetworkApplyFailed(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, networkStatusFile, `{"ok":false,"message":"部分失败: bridge/br0: 成员口 eth9 不存在"}`)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fa.hasRaise(TypeNetworkApplyFailed + "|" + ComponentNetwork) {
		t.Fatalf("应产网络执行失败告警: %v", fa.raises)
	}
	if !fa.hasRaise("成员口 eth9 不存在") {
		t.Fatalf("告警应带失败明细: %v", fa.raises)
	}
}

func TestNetworkRecoversWhenOK(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, networkStatusFile, `{"ok":true,"message":"applied","link_pairs":[{"bridge":"br0","state":"BOTH_UP"}]}`)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fa.raises) != 0 {
		t.Fatalf("正常不应告警: %v", fa.raises)
	}
	if !fa.hasRecover(ComponentNetwork + "|" + TypeNetworkApplyFailed) {
		t.Fatalf("应恢复网络告警: %v", fa.recovers)
	}
}

func TestLinkPairDownAndSuppressed(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, networkStatusFile, `{"ok":true,"link_pairs":[
	  {"bridge":"br0","state":"PROPAGATED_DOWN","down_port":"eth2","propagated_port":"eth3"},
	  {"bridge":"br1","state":"SUPPRESSED"}]}`)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fa.hasRaise(TypeLinkPairDown + "|" + ComponentLinkPair) {
		t.Fatalf("应产联动告警: %v", fa.raises)
	}
	if !fa.hasRaise(TypeLinkPairSuppressed + "|" + ComponentLinkPair) {
		t.Fatalf("应产抑制告警: %v", fa.raises)
	}
	if !fa.hasRaise("br0（故障口 eth2）") {
		t.Fatalf("告警应带桥与故障口: %v", fa.raises)
	}
}

func TestNetworkStatusParseFailure(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, networkStatusFile, `{broken`)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fa.hasRaise(TypeNetworkApplyFailed + "|" + ComponentNetwork + "|网络执行状态文件解析失败") {
		t.Fatalf("应产解析失败告警: %v", fa.raises)
	}
}

func TestHAVIPFaultStates(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, haVipConfigFile, `{"group":"ha-main"}`)
	writeFile(t, dir, haVipStatusFile, `{"group":"ha-main","node":"gw-a","state":"FAULT","keepalived_running":false,"message":"keepalived 启动失败"}`)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fa.hasRaise(TypeHAVIPFault + "|" + ComponentHAVIP) {
		t.Fatalf("FAULT 应告警: %v", fa.raises)
	}
}

func TestHAVIPMasterNoAlert(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, haVipConfigFile, `{"group":"ha-main"}`)
	writeFile(t, dir, haVipStatusFile, `{"group":"ha-main","node":"gw-a","state":"MASTER","keepalived_running":true}`)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fa.raises) != 0 {
		t.Fatalf("MASTER 不应告警: %v", fa.raises)
	}
	if !fa.hasRecover(ComponentHAVIP + "|" + TypeHAVIPFault) {
		t.Fatalf("应恢复: %v", fa.recovers)
	}
}

func TestHAVIPConfigWithoutStatus(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, haVipConfigFile, `{"group":"ha-main"}`)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fa.hasRaise("主备配置已下发但 havipd 未上报状态") {
		t.Fatalf("配置存在状态缺失应告警: %v", fa.raises)
	}
}

func TestHAVIPStaleStatus(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, haVipConfigFile, `{"group":"ha-main"}`)
	writeFile(t, dir, haVipStatusFile, `{"group":"ha-main","node":"gw-a","state":"MASTER","keepalived_running":true}`)
	// 把状态文件 mtime 调到 1 分钟前（havipd 每秒应刷新，过期 = 疑似停止）
	stale := time.Now().Add(-time.Minute)
	if err := os.Chtimes(filepath.Join(dir, haVipStatusFile), stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fa.hasRaise("havipd 疑似停止") {
		t.Fatalf("状态过期应告警: %v", fa.raises)
	}
}

func TestHAVIPDisabledNoAlert(t *testing.T) {
	sv, fa, dir := newTestSweeper(t)
	writeFile(t, dir, haVipConfigFile, `{"group":"ha-main"}`)
	writeFile(t, dir, haVipStatusFile, `{"group":"ha-main","node":"gw-a","state":"DISABLED","keepalived_running":false}`)
	if err := sv.SweepOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fa.raises) != 0 {
		t.Fatalf("DISABLED 为运维意图不应告警: %v", fa.raises)
	}
}
