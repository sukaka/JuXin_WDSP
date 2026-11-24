//go:build linux

package mirrorcap

import (
	"testing"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
)

func TestParseOOBClampsOversizedControllen(t *testing.T) {
	hdrLen := unix.CmsgLen(0)
	ts := unix.Timespec{Sec: 1700000000, Nsec: 123456789}
	tsSize := int(unsafe.Sizeof(ts))
	oobLen := unix.CmsgSpace(tsSize)

	h := &ethHandle{oob: make([]byte, oobLen)}
	hdr := (*unix.Cmsghdr)(unsafe.Pointer(&h.oob[0]))
	hdr.Level = unix.SOL_SOCKET
	hdr.Type = unix.SO_TIMESTAMPNS
	hdr.SetLen(hdrLen + tsSize)
	*(*unix.Timespec)(unsafe.Pointer(&h.oob[hdrLen])) = ts

	for _, ctrlLen := range []uint64{uint64(oobLen + 128), ^uint64(0)} {
		var ci gopacket.CaptureInfo
		h.parseOOB(ctrlLen, &ci)
		want := time.Unix(ts.Sec, ts.Nsec)
		if !ci.Timestamp.Equal(want) {
			t.Fatalf("controllen=%d: timestamp=%v, want %v", ctrlLen, ci.Timestamp, want)
		}
	}
}

func TestShouldSkipOutgoingPacketType(t *testing.T) {
	if !shouldSkipPacketType(unix.PACKET_OUTGOING) {
		t.Fatal("PACKET_OUTGOING 必须跳过以防透明网桥双口重复计入")
	}
	for _, pt := range []uint8{
		unix.PACKET_HOST,
		unix.PACKET_BROADCAST,
		unix.PACKET_MULTICAST,
		unix.PACKET_OTHERHOST,
	} {
		if shouldSkipPacketType(pt) {
			t.Fatalf("入向帧类型 %d 不应被跳过", pt)
		}
	}
}
