//go:build linux

package pcapevidence

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
)

var errCaptureReadTimeout = errors.New("capture read timeout")

// packetSource 的Stats遵循Linux PACKET_STATISTICS：返回距上次读取的增量。
type packetSource interface {
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Stats() (packets, drops uint32, err error)
	Close()
}

type pollPacketSource struct {
	fd      atomic.Int32
	ifindex int
	buffer  []byte
}

func newPollPacketSource(iface string, promiscuous bool) (packetSource, error) {
	info, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("capture interface %q is unavailable: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, htonsPort(unix.ETH_P_ALL))
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET capture: %w", err)
	}
	source := &pollPacketSource{ifindex: info.Index, buffer: make([]byte, 65535)}
	source.fd.Store(int32(fd))
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: uint16(htonsPort(unix.ETH_P_ALL)), Ifindex: info.Index}); err != nil {
		source.Close()
		return nil, fmt.Errorf("bind capture interface: %w", err)
	}
	if promiscuous {
		mreq := &unix.PacketMreq{Ifindex: int32(info.Index), Type: unix.PACKET_MR_PROMISC}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
			source.Close()
			return nil, fmt.Errorf("enable requested promiscuous capture: %w", err)
		}
	}
	return source, nil
}

func (s *pollPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		fd := int(s.fd.Load())
		if fd < 0 {
			return nil, gopacket.CaptureInfo{}, net.ErrClosed
		}
		ready, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 100)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		if ready == 0 {
			return nil, gopacket.CaptureInfo{}, errCaptureReadTimeout
		}
		n, _, _, _, err := unix.Recvmsg(fd, s.buffer, nil, 0)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, gopacket.CaptureInfo{}, err
		}
		if n <= 0 {
			continue
		}
		return s.buffer[:n], gopacket.CaptureInfo{
			Timestamp: time.Now().UTC(), CaptureLength: n, Length: n, InterfaceIndex: s.ifindex,
		}, nil
	}
}

func (s *pollPacketSource) Stats() (uint32, uint32, error) {
	fd := int(s.fd.Load())
	if fd < 0 {
		return 0, 0, net.ErrClosed
	}
	stats, err := unix.GetsockoptTpacketStats(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return 0, 0, err
	}
	return stats.Packets, stats.Drops, nil
}

func (s *pollPacketSource) Close() {
	fd := int(s.fd.Swap(-1))
	if fd >= 0 {
		_ = unix.Close(fd)
	}
}

func htonsPort(value int) int {
	return value<<8 | value>>8
}
