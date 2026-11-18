//go:build !linux

package pcapevidence

import "fmt"

type Capture struct{}

func NewCapture(CaptureConfig) (*Capture, error) {
	return nil, fmt.Errorf("request PCAP capture requires Linux AF_PACKET")
}

func (c *Capture) Run() error          { return fmt.Errorf("request PCAP capture requires Linux AF_PACKET") }
func (c *Capture) Close() error        { return nil }
func (c *Capture) Stats() CaptureStats { return CaptureStats{} }
