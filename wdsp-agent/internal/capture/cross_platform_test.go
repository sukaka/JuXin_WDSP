package capture

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

func buildBPFRecord(sec, usec int32, dataLen uint32, payload []byte, align int) []byte {
	hdrLen := uint16(18)
	total := bpfWordAlign(int(hdrLen)+len(payload), align)
	buf := make([]byte, total)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(sec))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(usec))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(payload)))
	binary.LittleEndian.PutUint32(buf[12:16], dataLen)
	binary.LittleEndian.PutUint16(buf[16:18], hdrLen)
	copy(buf[hdrLen:], payload)
	return buf
}

func TestParseBPFBufferMultiFrameAndTruncation(t *testing.T) {
	rec1 := buildBPFRecord(1700000001, 250000, 5, []byte("hello"), 4)
	rec2 := buildBPFRecord(1700000002, 500000, 1500, []byte("truncated"), 4)
	combined := append(rec1, rec2...)

	var frames []BPFFrame
	n := ParseBPFBuffer(combined, 4, func(f BPFFrame) {
		frames = append(frames, f)
	})
	if n != 2 || len(frames) != 2 {
		t.Fatalf("parsed frames=%d len=%d, want 2", n, len(frames))
	}
	if string(frames[0].Data) != "hello" || frames[0].CapLen != 5 || frames[0].OrigLen != 5 {
		t.Fatalf("frame[0]=%+v", frames[0])
	}
	if frames[0].Timestamp.Unix() != 1700000001 || frames[0].Timestamp.Nanosecond() != 250_000_000 {
		t.Fatalf("frame[0] ts=%v", frames[0].Timestamp)
	}
	if string(frames[1].Data) != "truncated" || frames[1].CapLen != 9 || frames[1].OrigLen != 1500 {
		t.Fatalf("frame[1]=%+v", frames[1])
	}

	// 畸形短头防死循环
	bad := make([]byte, 32)
	binary.LittleEndian.PutUint16(bad[16:18], 4) // < minBPFHdrLen
	if got := ParseBPFBuffer(bad, 4, nil); got != 0 {
		t.Fatalf("invalid hdrlen should stop immediately, got %d", got)
	}
}

func TestCounterDeltaAndWrapAround(t *testing.T) {
	var c CounterDelta
	r, d := c.Diff(100, 2)
	if r != 100 || d != 2 {
		t.Fatalf("first diff=(%d,%d)", r, d)
	}
	r, d = c.Diff(150, 5)
	if r != 50 || d != 3 {
		t.Fatalf("second diff=(%d,%d)", r, d)
	}
	// uint32 wrap-around
	c.lastRecv = ^uint32(0) - 5
	r, _ = c.Diff(4, 5)
	if r != 10 {
		t.Fatalf("wrap-around diff=%d want 10", r)
	}
}

func TestWindowsNpcapHelpers(t *testing.T) {
	paths := BuildNpcapDLLPaths(`D:\Windows\`)
	if len(paths) != 1 || paths[0] != `D:\Windows\System32\Npcap\wpcap.dll` {
		t.Fatalf("unexpected paths: %v", paths)
	}
	if !sanitizeNpcapPath(paths[0]) {
		t.Fatalf("valid path rejected: %s", paths[0])
	}
	if sanitizeNpcapPath(`.\wpcap.dll`) || sanitizeNpcapPath(`C:\Windows\..\evil.dll`) {
		t.Fatal("unsafe relative/traversal path must be rejected")
	}

	adapters := []WindowsAdapterInfo{
		{FriendlyName: "Ethernet0", AdapterGUID: "{AAA-111}", IPv4s: []string{"10.0.1.10"}},
		{FriendlyName: "Wi-Fi", AdapterGUID: "{BBB-222}", IPv4s: []string{"192.168.1.20"}},
	}
	if m, ok := MatchWindowsAdapter("ethernet0", adapters); !ok || m.AdapterGUID != "{AAA-111}" {
		t.Fatalf("friendly name match failed: ok=%v m=%+v", ok, m)
	}
	if m, ok := MatchWindowsAdapter(`\Device\NPF_{BBB-222}`, adapters); !ok || m.FriendlyName != "Wi-Fi" {
		t.Fatalf("device path match failed: ok=%v m=%+v", ok, m)
	}
	if m, ok := MatchWindowsAdapter("10.0.1.10", adapters); !ok || m.FriendlyName != "Ethernet0" {
		t.Fatalf("ip match failed: ok=%v m=%+v", ok, m)
	}
	if got := FormatNpcapDeviceName("{AAA-111}"); got != `\Device\NPF_{AAA-111}` {
		t.Fatalf("FormatNpcapDeviceName=%q", got)
	}
	if got := FormatNpcapDeviceName(`\Device\NPF_{AAA-111}`); got != `\Device\NPF_{AAA-111}` {
		t.Fatalf("FormatNpcapDeviceName idempotent=%q", got)
	}
}

func TestDecodeRawIPv4Frame(t *testing.T) {
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP:    net.ParseIP("10.20.0.1").To4(),
		DstIP:    net.ParseIP("10.20.0.2").To4(),
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort: 54321, DstPort: 8080, Seq: 42, PSH: true, ACK: true, Window: 65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}
	payload := []byte("GET /health HTTP/1.1\r\nHost: win-svc\r\n\r\n")
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true},
		ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}

	f := filter.New([]uint16{8080}, filter.Both)
	st := &Stats{}
	p, ok := DecodeRawIPv4Frame(buf.Bytes(), time.Unix(1788256800, 0), f, st)
	if !ok {
		t.Fatal("raw IPv4 TCP packet on port 8080 should pass filter")
	}
	if !p.NonEthernet {
		t.Fatal("raw IPv4 packet must set NonEthernet=true")
	}
	if p.SrcIP != "10.20.0.1" || p.DstIP != "10.20.0.2" || p.SrcPort != 54321 || p.DstPort != 8080 {
		t.Fatalf("unexpected 5-tuple: %+v", p)
	}
	if string(p.Payload) != string(payload) {
		t.Fatalf("payload=%q", p.Payload)
	}
}

func TestStartBackendDarwinAndWindowsChains(t *testing.T) {
	oldOS := platformOS
	oldBPF, oldNpcap, oldRaw := bpfFactory, npcapFactory, rawSocketFactory
	t.Cleanup(func() {
		platformOS = oldOS
		bpfFactory, npcapFactory, rawSocketFactory = oldBPF, oldNpcap, oldRaw
	})

	// 1. Darwin: auto -> bpf；显式指定 ebpf（不适用于 macOS）时 Fail-Open 回退 bpf
	platformOS = "darwin"
	bpfMock := &fakeBackend{}
	bpfFactory = func(BackendConfig) (Backend, error) { return bpfMock, nil }

	sel, err := StartBackend(BackendAuto, testCfg())
	if err != nil || sel.Name != BackendBPF || sel.Fallback {
		t.Fatalf("darwin auto failed: sel=%+v err=%v", sel, err)
	}
	sel, err = StartBackend(BackendEBPF, testCfg())
	if err != nil || sel.Name != BackendBPF || !sel.Fallback || !strings.Contains(sel.Reason, "macOS") {
		t.Fatalf("darwin cross-platform fallback failed: sel=%+v err=%v", sel, err)
	}

	// 2. Windows: npcap 优先；npcap 不可用自动回退 rawsocket；两者都失败报错
	platformOS = "windows"
	npcapMock := &fakeBackend{}
	rawMock := &fakeBackend{}
	npcapFactory = func(BackendConfig) (Backend, error) { return npcapMock, nil }
	rawSocketFactory = func(BackendConfig) (Backend, error) { return rawMock, nil }

	sel, err = StartBackend(BackendAuto, testCfg())
	if err != nil || sel.Name != BackendNpcap || sel.Fallback {
		t.Fatalf("windows auto should pick npcap first: sel=%+v err=%v", sel, err)
	}

	npcapFactory = func(BackendConfig) (Backend, error) { return nil, ErrNpcapUnavailable }
	sel, err = StartBackend(BackendAuto, testCfg())
	if err != nil || sel.Name != BackendRawSocket || !sel.Fallback || sel.Reason == "" {
		t.Fatalf("windows should fallback to rawsocket when npcap missing: sel=%+v err=%v", sel, err)
	}

	rawSocketFactory = func(BackendConfig) (Backend, error) { return nil, errors.New("admin required") }
	if _, err := StartBackend(BackendAuto, testCfg()); err == nil {
		t.Fatal("windows should return error when both npcap and rawsocket fail")
	}
}
