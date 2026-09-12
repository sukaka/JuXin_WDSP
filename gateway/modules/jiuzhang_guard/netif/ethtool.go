package netif

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// defaultEthtoolTimeout 单次 ethtool 调用超时（尽力而为探测不得拖慢采集周期）。
const defaultEthtoolTimeout = 2 * time.Second

// EthtoolProber 基于 ethtool 二进制的 Prober（容器内常不可用，调用方须容忍 nil）。
type EthtoolProber struct {
	path    string
	timeout time.Duration
}

// NewEthtoolProber 定位 ethtool 二进制；不可用返回 nil（采集降级为 media_type=UNKNOWN）。
func NewEthtoolProber() *EthtoolProber {
	p, err := exec.LookPath("ethtool")
	if err != nil {
		return nil
	}
	return &EthtoolProber{path: p, timeout: defaultEthtoolTimeout}
}

// ifnameRe 接口名白名单（sysfs 枚举来源可信，此处纵深防御：杜绝异常字符进入 exec 参数）。
var ifnameRe = regexp.MustCompile(`^[A-Za-z0-9_.:@-]+$`)

func (p *EthtoolProber) run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, p.path, args...).Output()
	if err != nil {
		return "", fmt.Errorf("exec ethtool %s: %w", strings.Join(args, " "), err)
	}
	return string(out), nil
}

// DriverAndBus 解析 `ethtool -i <if>` 的 driver 与 bus-info。
func (p *EthtoolProber) DriverAndBus(ifname string) (string, string, error) {
	if !ifnameRe.MatchString(ifname) {
		return "", "", fmt.Errorf("invalid ifname %q", ifname)
	}
	out, err := p.run("-i", ifname)
	if err != nil {
		return "", "", err
	}
	driver, busInfo := parseEthtoolInfo(out)
	return driver, busInfo, nil
}

// Media 解析 `ethtool <if>` 的 Supported ports（TP→电口 / FIBRE→光口）。
func (p *EthtoolProber) Media(ifname string) (string, error) {
	if !ifnameRe.MatchString(ifname) {
		return "", fmt.Errorf("invalid ifname %q", ifname)
	}
	out, err := p.run(ifname)
	if err != nil {
		return "", err
	}
	m := parseSupportedPorts(out)
	if m == "" {
		return "", fmt.Errorf("no recognizable supported ports")
	}
	return m, nil
}

// parseEthtoolInfo 解析 `ethtool -i` 输出的 driver / bus-info 键值行。
func parseEthtoolInfo(out string) (driver, busInfo string) {
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "driver":
			driver = strings.TrimSpace(v)
		case "bus-info":
			busInfo = strings.TrimSpace(v)
		}
	}
	return driver, busInfo
}

// parseSupportedPorts 解析 "Supported ports: [ TP ]" 行；
// combo 口（[ TP FIBRE ]）按出现顺序取首个可识别介质；无可识别项返回空。
func parseSupportedPorts(out string) string {
	const marker = "Supported ports:"
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, marker)
		if idx < 0 {
			continue
		}
		rest := line[idx+len(marker):]
		l := strings.Index(rest, "[")
		r := strings.Index(rest, "]")
		if l < 0 || r <= l {
			return ""
		}
		for _, tok := range strings.Fields(rest[l+1 : r]) {
			switch tok {
			case MediaTP:
				return MediaTP
			case MediaFibre:
				return MediaFibre
			}
		}
		return ""
	}
	return ""
}
