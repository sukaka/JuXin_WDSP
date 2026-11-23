// xdb.go 只读 ip2region XDB 归属地查询器：按 ip2region 公开二进制格式实现的
// 自研零外部依赖解析器（并发安全、常驻内存、查询零 I/O、全程边界检查，损坏文件返回错误而非 panic）。
//
// 兼容范围：
//   - XDB v2（IPv4，14 字节索引项；数据列 country|region|province|city|isp）
//   - XDB v3（IPv4 14 字节索引项 & IPv6 38 字节索引项；数据列 country|province|city|isp|iso_code）
//
// 二进制格式要点（ip2region spec）：
//   - 文件头 256 字节（小端序）：version(u16)、index_policy(u16)、created_at(u32)、
//     start_index_ptr(u32)、end_index_ptr(u32)；v3 额外含 ip_version(u16, 4/6)、runtime_ptr_bytes(u16, 4)。
//   - 向量索引区位于偏移 256，大小 256*256*8 = 524288 字节；按 IP 前两字节 (b0, b1) 定位
//     该段二分索引的起止文件偏移 [sPtr, ePtr]。
//   - 二分索引段：
//     - IPv4：14 字节 = sip(u32le) + eip(u32le) + dataLen(u16le) + dataPtr(u32le)
//     - IPv6：38 字节 = sip([16]byte big-endian) + eip([16]byte big-endian) + dataLen(u16le) + dataPtr(u32le)
package apigeo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

const (
	xdbHeaderSize      = 256
	xdbVectorRows      = 256
	xdbVectorCols      = 256
	xdbVectorEntrySize = 8
	xdbVectorIndexSize = xdbVectorRows * xdbVectorCols * xdbVectorEntrySize
	xdbMinFileSize     = xdbHeaderSize + xdbVectorIndexSize

	xdbIndexPolicyVector = 1
	xdbSegSizeV4         = 14 // 4 + 4 + 2 + 4
	xdbSegSizeV6         = 38 // 16 + 16 + 2 + 4
)

// XDBRecord 从 ip2region XDB 单条记录解析出的归属地信息。
type XDBRecord struct {
	CountryCode string // ISO 3166-1 alpha-2（港澳台已按标准细分为 HK/MO/TW）
	Country     string
	Province    string
	City        string
	ISP         string
	Raw         string
}

// XDB 只读常驻内存查询器（并发安全）。
type XDB struct {
	buf       []byte
	version   uint16
	ipVersion uint16 // 4 或 6
	segSize   int
}

// OpenXDB 从磁盘加载并解析 ip2region XDB 文件。
func OpenXDB(path string) (*XDB, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read xdb %q: %w", path, err)
	}
	return ParseXDB(buf)
}

// ParseXDB 校验并解析 XDB 字节流。
func ParseXDB(buf []byte) (*XDB, error) {
	if len(buf) < xdbMinFileSize {
		return nil, fmt.Errorf("xdb too small (%d bytes, min %d)", len(buf), xdbMinFileSize)
	}
	version := binary.LittleEndian.Uint16(buf[0:2])
	if version != 2 && version != 3 {
		return nil, fmt.Errorf("xdb unsupported version %d", version)
	}
	policy := binary.LittleEndian.Uint16(buf[2:4])
	if policy != xdbIndexPolicyVector {
		return nil, fmt.Errorf("xdb unsupported index policy %d", policy)
	}
	startIdx := binary.LittleEndian.Uint32(buf[8:12])
	endIdx := binary.LittleEndian.Uint32(buf[12:16])
	if startIdx < xdbMinFileSize || endIdx < startIdx || uint64(endIdx) >= uint64(len(buf)) {
		return nil, fmt.Errorf("xdb invalid index range [%d, %d] (file size %d)", startIdx, endIdx, len(buf))
	}

	var ipVersion uint16 = 4
	var ptrBytes uint16 = 4
	if version >= 3 {
		ipVersion = binary.LittleEndian.Uint16(buf[16:18])
		if ipVersion == 0 {
			ipVersion = 4
		}
		ptrBytes = binary.LittleEndian.Uint16(buf[18:20])
		if ptrBytes == 0 {
			ptrBytes = 4
		}
	}
	if ptrBytes != 4 {
		return nil, fmt.Errorf("xdb unsupported runtime_ptr_bytes %d", ptrBytes)
	}

	var segSize int
	switch ipVersion {
	case 4:
		segSize = xdbSegSizeV4
	case 6:
		segSize = xdbSegSizeV6
	default:
		return nil, fmt.Errorf("xdb unsupported ip_version %d", ipVersion)
	}
	if uint64(endIdx)+uint64(segSize) > uint64(len(buf)) {
		return nil, fmt.Errorf("xdb end index out of file bounds")
	}

	return &XDB{
		buf:       buf,
		version:   version,
		ipVersion: ipVersion,
		segSize:   segSize,
	}, nil
}

// IPVersion 返回该 XDB 支持的 IP 版本（4 或 6）。
func (x *XDB) IPVersion() int {
	if x == nil {
		return 0
	}
	return int(x.ipVersion)
}

// Lookup 查询单个 IP 的归属地记录。
// IP 版本与当前库不匹配或未收录返回 (nil, nil)；底层数据损坏返回错误。
func (x *XDB) Lookup(ip netip.Addr) (*XDBRecord, error) {
	if x == nil || !ip.IsValid() {
		return nil, nil
	}
	ip = ip.Unmap()
	if x.ipVersion == 4 {
		if !ip.Is4() {
			return nil, nil
		}
		return x.lookupV4(ip.As4())
	}
	if !ip.Is6() {
		return nil, nil
	}
	return x.lookupV6(ip.As16())
}

// LookupCountry 实现 CountryLookup 接口，返回 ISO 3166-1 alpha-2 国家码。
func (x *XDB) LookupCountry(ip netip.Addr) (string, error) {
	rec, err := x.Lookup(ip)
	if err != nil || rec == nil {
		return "", err
	}
	return rec.CountryCode, nil
}

func (x *XDB) vectorRange(b0, b1 byte) (sPtr, ePtr uint32, ok bool, err error) {
	vOff := xdbHeaderSize + (int(b0)*xdbVectorCols+int(b1))*xdbVectorEntrySize
	sPtr = binary.LittleEndian.Uint32(x.buf[vOff : vOff+4])
	ePtr = binary.LittleEndian.Uint32(x.buf[vOff+4 : vOff+8])
	if sPtr == 0 && ePtr == 0 {
		return 0, 0, false, nil
	}
	if sPtr < xdbMinFileSize || ePtr < sPtr {
		return 0, 0, false, fmt.Errorf("xdb corrupt vector entry [%d, %d]", sPtr, ePtr)
	}
	if uint64(ePtr)+uint64(x.segSize) > uint64(len(x.buf)) {
		return 0, 0, false, fmt.Errorf("xdb vector range out of bounds [%d, %d]", sPtr, ePtr)
	}
	if (ePtr-sPtr)%uint32(x.segSize) != 0 {
		return 0, 0, false, fmt.Errorf("xdb unaligned segment range [%d, %d]", sPtr, ePtr)
	}
	return sPtr, ePtr, true, nil
}

func (x *XDB) lookupV4(b [4]byte) (*XDBRecord, error) {
	sPtr, ePtr, ok, err := x.vectorRange(b[0], b[1])
	if err != nil || !ok {
		return nil, err
	}
	target := binary.BigEndian.Uint32(b[:])
	l := 0
	h := int((ePtr - sPtr) / xdbSegSizeV4)
	for l <= h {
		m := (l + h) >> 1
		p := int(sPtr) + m*xdbSegSizeV4
		sip := binary.LittleEndian.Uint32(x.buf[p : p+4])
		if target < sip {
			h = m - 1
			continue
		}
		eip := binary.LittleEndian.Uint32(x.buf[p+4 : p+8])
		if target > eip {
			l = m + 1
			continue
		}
		dataLen := binary.LittleEndian.Uint16(x.buf[p+8 : p+10])
		dataPtr := binary.LittleEndian.Uint32(x.buf[p+10 : p+14])
		return x.readRegion(dataPtr, dataLen)
	}
	return nil, nil
}

func (x *XDB) lookupV6(b [16]byte) (*XDBRecord, error) {
	sPtr, ePtr, ok, err := x.vectorRange(b[0], b[1])
	if err != nil || !ok {
		return nil, err
	}
	target := b[:]
	l := 0
	h := int((ePtr - sPtr) / xdbSegSizeV6)
	for l <= h {
		m := (l + h) >> 1
		p := int(sPtr) + m*xdbSegSizeV6
		sip := x.buf[p : p+16]
		if bytes.Compare(target, sip) < 0 {
			h = m - 1
			continue
		}
		eip := x.buf[p+16 : p+32]
		if bytes.Compare(target, eip) > 0 {
			l = m + 1
			continue
		}
		dataLen := binary.LittleEndian.Uint16(x.buf[p+32 : p+34])
		dataPtr := binary.LittleEndian.Uint32(x.buf[p+34 : p+38])
		return x.readRegion(dataPtr, dataLen)
	}
	return nil, nil
}

func (x *XDB) readRegion(dataPtr uint32, dataLen uint16) (*XDBRecord, error) {
	if dataLen == 0 {
		return nil, nil
	}
	end := uint64(dataPtr) + uint64(dataLen)
	if end > uint64(len(x.buf)) {
		return nil, fmt.Errorf("xdb data range [%d, %d) out of bounds (%d)", dataPtr, end, len(x.buf))
	}
	raw := string(x.buf[dataPtr:end])
	return parseXDBRegion(raw, x.version), nil
}

// parseXDBRegion 解析 ip2region 文本记录：
//   - v3：country|province|city|isp|iso_code（如：中国|广东省|广州市|电信|CN）
//   - v2：country|region|province|city|isp（如：中国|0|广东省|广州市|电信）
func parseXDBRegion(raw string, version uint16) *XDBRecord {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, "|")
	rec := &XDBRecord{Raw: raw}
	if len(parts) >= 5 {
		iso5 := normalizeISO2(parts[4])
		if version >= 3 || iso5 != "" {
			rec.Country = cleanXDBField(parts[0])
			rec.Province = cleanXDBField(parts[1])
			rec.City = cleanXDBField(parts[2])
			rec.ISP = cleanXDBField(parts[3])
			rec.CountryCode = iso5
		} else {
			rec.Country = cleanXDBField(parts[0])
			rec.Province = cleanXDBField(parts[2])
			rec.City = cleanXDBField(parts[3])
			rec.ISP = cleanXDBField(parts[4])
		}
	} else {
		if len(parts) > 0 {
			rec.Country = cleanXDBField(parts[0])
		}
		if len(parts) > 1 {
			rec.Province = cleanXDBField(parts[1])
		}
		if len(parts) > 2 {
			rec.City = cleanXDBField(parts[2])
		}
		if len(parts) > 3 {
			rec.ISP = cleanXDBField(parts[3])
		}
	}

	if rec.CountryCode == "" && rec.Country != "" {
		rec.CountryCode = countryNameToISO2(rec.Country)
	}
	// ISO 3166-1 alpha-2 标准细分：港澳台独立编码（兼顾出境判定与大屏质心定位）
	if rec.CountryCode == "CN" || rec.Country == "中国" {
		switch {
		case strings.Contains(rec.Province, "香港") || strings.Contains(rec.City, "香港"):
			rec.CountryCode = "HK"
		case strings.Contains(rec.Province, "澳门") || strings.Contains(rec.City, "澳门"):
			rec.CountryCode = "MO"
		case strings.Contains(rec.Province, "台湾") || strings.Contains(rec.City, "台湾"):
			rec.CountryCode = "TW"
		}
	}

	if rec.CountryCode == "" && rec.Country == "" && rec.Province == "" && rec.City == "" && rec.ISP == "" {
		return nil
	}
	return rec
}

func cleanXDBField(s string) string {
	s = strings.TrimSpace(s)
	switch strings.ToLower(s) {
	case "", "0", "reserved", "unknown", "null", "none", "未知", "内网ip", "局域网":
		return ""
	default:
		return s
	}
}
