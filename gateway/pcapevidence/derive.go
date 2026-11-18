package pcapevidence

import (
	"encoding/binary"
	"fmt"
	"io"
)

// ExportPCAPRange 从已完成完整性验证的经典PCAP流派生指定包范围，不写临时明文文件。
func ExportPCAPRange(input io.Reader, output io.Writer, first, last uint64) (uint64, error) {
	if input == nil || output == nil || first == 0 || last < first {
		return 0, fmt.Errorf("invalid PCAP derivative range")
	}
	header := make([]byte, 24)
	if _, err := io.ReadFull(input, header); err != nil {
		return 0, fmt.Errorf("read PCAP header: %w", err)
	}
	var order binary.ByteOrder
	switch binary.BigEndian.Uint32(header[:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	default:
		return 0, fmt.Errorf("unsupported PCAP byte order")
	}
	if order.Uint32(header[20:24]) != 1 {
		return 0, fmt.Errorf("only Ethernet PCAP derivatives are supported")
	}
	if err := writeAll(output, header); err != nil {
		return 0, err
	}
	var packetNumber, selected uint64
	for {
		record := make([]byte, 16)
		_, err := io.ReadFull(input, record)
		if err == io.EOF {
			break
		}
		if err != nil {
			return selected, fmt.Errorf("truncated PCAP record header: %w", err)
		}
		length := order.Uint32(record[8:12])
		if length == 0 || length > 16<<20 {
			return selected, fmt.Errorf("invalid PCAP packet length")
		}
		packetNumber++
		payload := make([]byte, int(length))
		if _, err := io.ReadFull(input, payload); err != nil {
			return selected, fmt.Errorf("truncated PCAP packet: %w", err)
		}
		if uint64(packetNumber) < first || uint64(packetNumber) > last {
			continue
		}
		if err := writeAll(output, record); err != nil {
			return selected, err
		}
		if err := writeAll(output, payload); err != nil {
			return selected, err
		}
		selected++
	}
	if selected == 0 || last > packetNumber {
		return selected, fmt.Errorf("requested PCAP range is outside the source evidence")
	}
	return selected, nil
}
