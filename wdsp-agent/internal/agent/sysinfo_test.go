package agent

import (
	"runtime"
	"strings"
	"testing"
)

func TestParseDarwinSystemVersionPlist(t *testing.T) {
	sample := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>ProductBuildVersion</key>
	<string>24C101</string>
	<key>ProductName</key>
	<string>macOS</string>
	<key>ProductVersion</key>
	<string>15.2</string>
</dict>
</plist>`)
	got := parseDarwinSystemVersionPlist(sample)
	if got != "macOS 15.2 (24C101)" {
		t.Fatalf("got %q, want %q", got, "macOS 15.2 (24C101)")
	}
	if empty := parseDarwinSystemVersionPlist([]byte("not xml")); empty != "" {
		t.Fatalf("invalid plist should return empty, got %q", empty)
	}
}

func TestFormatWindowsOSRelease(t *testing.T) {
	tests := []struct {
		name        string
		product     string
		display     string
		buildStr    string
		maj, min, b uint32
		want        string
	}{
		{
			name:    "windows 11 fixup from windows 10 product name",
			product: "Windows 10 Pro", display: "24H2", buildStr: "26100",
			maj: 10, min: 0, b: 26100,
			want: "Windows 11 Pro 24H2 (Build 26100)",
		},
		{
			name:    "windows server keeps server name",
			product: "Windows Server 2022 Datacenter", display: "21H2", buildStr: "20348",
			maj: 10, min: 0, b: 20348,
			want: "Windows Server 2022 Datacenter 21H2 (Build 20348)",
		},
		{
			name:    "windows 10 stays windows 10 below 22000",
			product: "Windows 10 Enterprise", display: "22H2", buildStr: "19045",
			maj: 10, min: 0, b: 19045,
			want: "Windows 10 Enterprise 22H2 (Build 19045)",
		},
		{
			name: "fallback without registry",
			maj:  10, min: 0, b: 17763,
			want: "Windows 10.0 (Build 17763)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatWindowsOSRelease(tc.product, tc.display, tc.buildStr, tc.maj, tc.min, tc.b)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHostSysinfoLive(t *testing.T) {
	osRel := OSRelease()
	if strings.TrimSpace(osRel) == "" {
		t.Fatal("OSRelease should not be empty")
	}
	if Arch() != runtime.GOARCH {
		t.Fatalf("Arch=%q want %q", Arch(), runtime.GOARCH)
	}
	if runtime.GOOS == "darwin" {
		if !strings.HasPrefix(osRel, "macOS") {
			t.Fatalf("macOS OSRelease=%q should start with macOS", osRel)
		}
		if Kernel() == "" || Kernel() == "unknown" {
			t.Fatalf("macOS Kernel=%q should be populated", Kernel())
		}
	}
}
