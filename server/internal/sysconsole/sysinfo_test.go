// sysinfo_test.go 系统信息解析纯逻辑单测。
package sysconsole

import (
	"strings"
	"testing"
)

func TestParseCPUModel(t *testing.T) {
	cpuinfo := "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Core(TM) i7\n\nprocessor\t: 1\n"
	if got := parseCPUModel(cpuinfo); got != "Intel(R) Core(TM) i7" {
		t.Errorf("parseCPUModel = %q", got)
	}
	if got := parseCPUModel("nothing: here\n"); got != "" {
		t.Errorf("无 model name 应返回空，got %q", got)
	}
}

func TestParseMemInfo(t *testing.T) {
	meminfo := "MemTotal:       16384000 kB\nMemFree:         8192000 kB\nMemAvailable:   12288000 kB\n"
	total, avail := parseMemInfo(meminfo)
	if total != 16384000*1024 || avail != 12288000*1024 {
		t.Errorf("parseMemInfo = %d/%d", total, avail)
	}
	if total, _ := parseMemInfo("garbage"); total != 0 {
		t.Errorf("垃圾输入应返回 0")
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[uint64]string{
		512:                    "512 B",
		2048:                   "2.0 KB",
		5 * 1024 * 1024:        "5.0 MB",
		3 * 1024 * 1024 * 1024: "3.0 GB",
	}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestSysInfoDegrades(t *testing.T) {
	// 任何平台上都不应 panic，且包含三个小节标题
	out := SysInfo()
	for _, sec := range []string{"== CPU ==", "== 内存 ==", "== 磁盘 =="} {
		if !strings.Contains(out, sec) {
			t.Errorf("SysInfo 缺少小节 %s", sec)
		}
	}
}
