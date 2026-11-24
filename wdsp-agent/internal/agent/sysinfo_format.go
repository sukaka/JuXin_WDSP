package agent

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// parseDarwinSystemVersionPlist 解析 macOS /System/Library/CoreServices/SystemVersion.plist。
func parseDarwinSystemVersionPlist(data []byte) string {
	dec := xml.NewDecoder(bytes.NewReader(data))
	kv := make(map[string]string, 4)
	var currentKey string
	for {
		tok, err := dec.Token()
		if err != nil {
			if err == io.EOF {
				break
			}
			return ""
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "key":
			var k string
			if err := dec.DecodeElement(&k, &se); err == nil {
				currentKey = strings.TrimSpace(k)
			}
		case "string":
			var v string
			if err := dec.DecodeElement(&v, &se); err == nil && currentKey != "" {
				kv[currentKey] = strings.TrimSpace(v)
				currentKey = ""
			}
		default:
			currentKey = ""
		}
	}
	name := kv["ProductName"]
	ver := kv["ProductVersion"]
	build := kv["ProductBuildVersion"]
	if name == "" && ver == "" {
		return ""
	}
	if name == "" {
		name = "macOS"
	}
	if ver == "" {
		return name
	}
	if build != "" {
		return fmt.Sprintf("%s %s (%s)", name, ver, build)
	}
	return fmt.Sprintf("%s %s", name, ver)
}

// formatWindowsOSRelease 归一化 Windows 版本展示字符串。
// Windows 11 的注册表 ProductName 历史遗留仍可能含 "Windows 10"（非 Server），
// 当 CurrentBuildNumber >= 22000 时修正为 "Windows 11"。
func formatWindowsOSRelease(productName, displayVersion, currentBuild string, major, minor, buildNum uint32) string {
	name := strings.TrimSpace(productName)
	disp := strings.TrimSpace(displayVersion)
	buildStr := strings.TrimSpace(currentBuild)
	effBuild := buildNum
	if effBuild == 0 && buildStr != "" {
		if n, err := strconv.ParseUint(buildStr, 10, 32); err == nil {
			effBuild = uint32(n)
		}
	}
	if effBuild >= 22000 && strings.Contains(name, "Windows 10") && !strings.Contains(name, "Server") {
		name = strings.Replace(name, "Windows 10", "Windows 11", 1)
	}
	if name == "" {
		if major > 0 {
			name = fmt.Sprintf("Windows %d.%d", major, minor)
		} else {
			name = "Windows"
		}
	}
	if disp != "" && !strings.Contains(name, disp) {
		name = fmt.Sprintf("%s %s", name, disp)
	}
	if effBuild > 0 {
		return fmt.Sprintf("%s (Build %d)", name, effBuild)
	}
	return name
}
