// mmdb.go 只读 MaxMind DB（mmdb）归属地查询器：按 MaxMind DB 公开二进制格式
// 实现的自研最小解析器（仓库禁止新增第三方依赖，无法引入 maxminddb-golang；
// 格式细节与 web/node_modules/mmdb-lib 实现交叉验证）。
//
// 覆盖能力：元数据解析、二叉查找树遍历（24/28/32 位记录）、数据段解码
// （指针/UTF-8 串/Map/各整型/数组/布尔/浮点），兼容两套常见记录结构：
//   - sapics/ip-location-db 扁平结构（country_code/state1/city/latitude/longitude）
//   - DB-IP 官方 / MaxMind GeoIP2 嵌套结构（country.iso_code/subdivisions/city/location）
// 全程边界与递归深度检查：文件损坏返回错误而非 panic。
//
// 格式要点（MaxMind DB spec）：
//   - 文件 = 查找树（node_count 个节点，每节点左右两条 record_size 位记录）
//   - 16 字节分隔符 + 数据段 + 元数据（以 "\xab\xcd\xefMaxMind.com" 标记定位）；
//   - 树记录值：< node_count 为下一节点；== node_count 表示未收录；
//     > node_count 为数据段指针，文件偏移 = 值 - node_count + 树字节数；
//   - 数据段内指针以（树字节数 + 16）为基址；
//   - IPv6 树中 IPv4 地址从「沿左分支走 96 位」得到的起始节点进入（::/96 前缀）。
package apigeo

import (
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// maxDecodeDepth MMDB 数据段解码最大嵌套/指针跳转深度（防止损坏文件的循环指针导致栈溢出）。
const maxDecodeDepth = 32

// metadataMarker 元数据段起始标记（从文件尾部反向搜索）。
var metadataMarker = []byte("\xab\xcd\xefMaxMind.com")

// dataSectionSeparatorSize 查找树与数据段之间的分隔符长度。
const dataSectionSeparatorSize = 16

// mmdb 数据段控制字节类型编号（高 3 位；0 为扩展类型，类型号 = 下一字节 + 7）。
const (
	dtPointer = 1
	dtUTF8    = 2
	dtDouble  = 3
	dtBytes   = 4
	dtUint16  = 5
	dtUint32  = 6
	dtMap     = 7
	dtInt32   = 8
	dtUint64  = 9
	dtUint128 = 10
	dtArray   = 11
	dtBoolean = 14
	dtFloat   = 15
)

// pointerValueOffset 指针对应的固定偏移加成（索引为指针尺寸 0..3）。
var pointerValueOffset = []int{0, 2048, 526336, 0}

// mmdbMetadata 元数据（仅保留本包所需字段）。
type mmdbMetadata struct {
	nodeCount      int
	recordSize     int // 每条树记录位数：24 / 28 / 32
	ipVersion      int // 4 或 6
	nodeByteSize   int // 每节点字节数 = recordSize / 4
	searchTreeSize int // 树总字节数 = nodeCount * nodeByteSize
}

// MMDB 解析后的只读查询器（buf 常驻内存，查询无 I/O，并发安全——只读共享）。
type MMDB struct {
	buf       []byte
	meta      mmdbMetadata
	decoder   decoder // 数据段解码器（指针基址 = 树字节数 + 16）
	ipv4Start int     // IPv4 在 IPv6 树中的起始节点（IPv4 树为 0）
}

// OpenMMDB 从文件加载并解析 mmdb 库（文件不存在/损坏如实返回错误，由调用方决定降级）。
func OpenMMDB(path string) (*MMDB, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mmdb %q: %w", path, err)
	}
	return ParseMMDB(buf)
}

// ParseMMDB 解析 mmdb 字节流（元数据校验 + IPv4 起始节点预计算）。
func ParseMMDB(buf []byte) (*MMDB, error) {
	if len(buf) < len(metadataMarker)+64 {
		return nil, fmt.Errorf("mmdb too small (%d bytes)", len(buf))
	}
	markerAt := lastIndex(buf, metadataMarker)
	if markerAt < 0 {
		return nil, fmt.Errorf("mmdb metadata marker not found")
	}
	// 元数据自身按数据段格式编码（实践中不含指针，基址仅作防御）
	md := decoder{buf: buf, baseOffset: markerAt + len(metadataMarker)}
	v, _, err := md.decode(markerAt + len(metadataMarker))
	if err != nil {
		return nil, fmt.Errorf("mmdb metadata decode: %w", err)
	}
	metaMap, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("mmdb metadata is not a map")
	}
	var meta mmdbMetadata
	if meta.nodeCount, ok = metaInt(metaMap, "node_count"); !ok || meta.nodeCount <= 0 {
		return nil, fmt.Errorf("mmdb metadata missing/invalid node_count")
	}
	if meta.recordSize, ok = metaInt(metaMap, "record_size"); !ok {
		return nil, fmt.Errorf("mmdb metadata missing record_size")
	}
	if meta.recordSize != 24 && meta.recordSize != 28 && meta.recordSize != 32 {
		return nil, fmt.Errorf("mmdb unsupported record_size %d", meta.recordSize)
	}
	if major, ok := metaInt(metaMap, "binary_format_major_version"); !ok || major != 2 {
		return nil, fmt.Errorf("mmdb unsupported binary_format_major_version")
	}
	meta.ipVersion, _ = metaInt(metaMap, "ip_version") // 缺省按 4 处理（防御）
	meta.nodeByteSize = meta.recordSize / 4
	meta.searchTreeSize = meta.nodeCount * meta.nodeByteSize
	if meta.searchTreeSize+dataSectionSeparatorSize >= len(buf) {
		return nil, fmt.Errorf("mmdb search tree exceeds file size")
	}
	m := &MMDB{
		buf:  buf,
		meta: meta,
		decoder: decoder{
			buf:        buf,
			baseOffset: meta.searchTreeSize + dataSectionSeparatorSize,
		},
	}
	// IPv6 树中 IPv4 起始节点：从根沿左分支（全 0 位）走 96 位
	if meta.ipVersion == 6 {
		node := 0
		for i := 0; i < 96 && node < meta.nodeCount; i++ {
			node, err = m.readRecord(node, 0)
			if err != nil {
				return nil, fmt.Errorf("mmdb ipv4 start walk: %w", err)
			}
		}
		m.ipv4Start = node
	}
	return m, nil
}

// MMDBLocation 从 MMDB 记录提取的标准化归属地信息（同时兼容 sapics 扁平结构与 DB-IP/MaxMind 嵌套结构）。
type MMDBLocation struct {
	CountryCode string
	Country     string
	Province    string
	City        string
	Latitude    float64
	Longitude   float64
	HasCoord    bool
}

// LookupRecord 查询 IP 对应的原始 MMDB map 记录。
// 未收录/版本不匹配/记录非 map 返回 (nil, nil)；数据损坏返回错误（调用方不静默吞错）。
func (m *MMDB) LookupRecord(ip netip.Addr) (map[string]any, error) {
	if m == nil {
		return nil, nil
	}
	ip = ip.Unmap() // ::ffff:x.y 归一为 IPv4
	var raw []byte
	node := 0
	if ip.Is4() {
		if m.meta.ipVersion == 6 {
			node = m.ipv4Start
		}
		b := ip.As4()
		raw = b[:]
	} else {
		if m.meta.ipVersion != 6 {
			return nil, nil // IPv4 库不收录 IPv6
		}
		b := ip.As16()
		raw = b[:]
	}
	// 自最高位逐位下行：记录值 < nodeCount 继续；== nodeCount 未收录；> 则为数据指针
	for depth := 0; depth < len(raw)*8 && node < m.meta.nodeCount; depth++ {
		bit := int(raw[depth/8]>>(7-uint(depth%8))) & 1
		next, err := m.readRecord(node, bit)
		if err != nil {
			return nil, err
		}
		node = next
	}
	if node <= m.meta.nodeCount {
		return nil, nil // 未收录（==）或树提前耗尽（<，防御）
	}
	off := node - m.meta.nodeCount + m.meta.searchTreeSize
	v, _, err := m.decoder.decode(off)
	if err != nil {
		return nil, fmt.Errorf("mmdb decode record for %s: %w", ip, err)
	}
	rec, ok := v.(map[string]any)
	if !ok {
		return nil, nil // 记录非 map，按未收录处理
	}
	return rec, nil
}

// LookupLocation 查询 IP 的归属地明细（国家码、国家、省/州、城市、经纬度）。
// 未收录返回 (nil, nil)；底层数据损坏返回错误。
func (m *MMDB) LookupLocation(ip netip.Addr) (*MMDBLocation, error) {
	rec, err := m.LookupRecord(ip)
	if err != nil || rec == nil {
		return nil, err
	}
	return extractMMDBLocation(rec), nil
}

// LookupCountry 查询 IP 的 ISO 3166-1 alpha-2 国家码。
// 未收录/版本不匹配返回 ("", nil)；数据损坏返回错误（调用方不静默吞错）。
func (m *MMDB) LookupCountry(ip netip.Addr) (string, error) {
	loc, err := m.LookupLocation(ip)
	if err != nil || loc == nil {
		return "", err
	}
	return loc.CountryCode, nil
}

// extractMMDBLocation 兼容提取两套 MMDB 记录结构：
//  1. sapics/ip-location-db 扁平结构：country_code / state1 / city / latitude / longitude
//  2. DB-IP 官方 / MaxMind GeoIP2 嵌套结构：country.{iso_code,names} / subdivisions[0].names /
//     city.names / location.{latitude,longitude}（国家缺失时回退 registered_country）
func extractMMDBLocation(rec map[string]any) *MMDBLocation {
	if len(rec) == 0 {
		return nil
	}
	var loc MMDBLocation

	// 1. 国家码与国家名
	if code, ok := rec["country_code"].(string); ok && strings.TrimSpace(code) != "" {
		loc.CountryCode = normalizeISO2(code)
	}
	if countryMap, ok := rec["country"].(map[string]any); ok {
		if loc.CountryCode == "" {
			if code, ok := countryMap["iso_code"].(string); ok {
				loc.CountryCode = normalizeISO2(code)
			}
		}
		if name := extractLocalizedName(countryMap["names"]); name != "" {
			loc.Country = name
		}
	}
	if loc.CountryCode == "" {
		if regMap, ok := rec["registered_country"].(map[string]any); ok {
			if code, ok := regMap["iso_code"].(string); ok {
				loc.CountryCode = normalizeISO2(code)
			}
			if loc.Country == "" {
				loc.Country = extractLocalizedName(regMap["names"])
			}
		}
	}

	// 2. 省/州：优先嵌套 subdivisions[0]，回退扁平 state1
	if subs, ok := rec["subdivisions"].([]any); ok && len(subs) > 0 {
		if first, ok := subs[0].(map[string]any); ok {
			loc.Province = extractLocalizedName(first["names"])
		}
	}
	if loc.Province == "" {
		if s, ok := rec["state1"].(string); ok {
			loc.Province = strings.TrimSpace(s)
		}
	}

	// 3. 城市：同时支持嵌套 city.names 与扁平 city 字符串
	switch cityVal := rec["city"].(type) {
	case map[string]any:
		loc.City = extractLocalizedName(cityVal["names"])
	case string:
		loc.City = strings.TrimSpace(cityVal)
	}

	// 4. 经纬度：优先嵌套 location.{latitude,longitude}，回退顶层扁平字段
	var lat, lon float64
	var okLat, okLon bool
	if locMap, ok := rec["location"].(map[string]any); ok {
		lat, okLat = toFloat64(locMap["latitude"])
		lon, okLon = toFloat64(locMap["longitude"])
	}
	if !okLat || !okLon {
		lat, okLat = toFloat64(rec["latitude"])
		lon, okLon = toFloat64(rec["longitude"])
	}
	if okLat && okLon && !math.IsNaN(lat) && !math.IsNaN(lon) && !(lat == 0 && lon == 0) &&
		lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 {
		loc.Latitude = lat
		loc.Longitude = lon
		loc.HasCoord = true
	}

	if loc.CountryCode == "" && loc.Country == "" && loc.Province == "" && loc.City == "" && !loc.HasCoord {
		return nil
	}
	return &loc
}

// extractLocalizedName 从 GeoIP2 names map 提取展示名（优先简体中文，回退英文，最后任意非空值）。
func extractLocalizedName(v any) string {
	names, ok := v.(map[string]any)
	if !ok || len(names) == 0 {
		return ""
	}
	for _, lang := range []string{"zh-CN", "zh_CN", "zh", "en"} {
		if s, ok := names[lang].(string); ok {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}

// normalizeISO2 归一两位 ISO 3166-1 alpha-2 国家码；非法返回空串。
func normalizeISO2(raw string) string {
	s := strings.ToUpper(strings.TrimSpace(raw))
	if len(s) != 2 || s[0] < 'A' || s[0] > 'Z' || s[1] < 'A' || s[1] > 'Z' {
		return ""
	}
	return s
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

// readRecord 读取节点 node 的左（bit=0）/右（bit=1）记录值（全程边界检查）。
func (m *MMDB) readRecord(node, bit int) (int, error) {
	off := node * m.meta.nodeByteSize
	if node < 0 || off+m.meta.nodeByteSize > m.meta.searchTreeSize {
		return 0, fmt.Errorf("mmdb node %d out of tree bounds", node)
	}
	b := m.buf
	switch m.meta.recordSize {
	case 24:
		if bit == 0 {
			return u24be(b, off), nil
		}
		return u24be(b, off+3), nil
	case 28:
		if bit == 0 {
			return int(b[off+3]&0xf0)<<20 | u24be(b, off), nil
		}
		return int(b[off+3]&0x0f)<<24 | u24be(b, off+4), nil
	default: // 32
		if bit == 0 {
			return int(u32be(b, off)), nil
		}
		return int(u32be(b, off+4)), nil
	}
}

// decoder mmdb 数据段解码器；baseOffset 为指针解析基址（数据段起点）。
type decoder struct {
	buf        []byte
	baseOffset int
}

// decode 解码 off 处的值，返回（值, 本值结束偏移）；指针透明跟随（值为指向处解码结果，
// 结束偏移仍为指针自身末尾）。全程边界与深度检查，损坏数据返回错误。
func (d *decoder) decode(off int) (any, int, error) {
	return d.decodeAt(off, 0)
}

func (d *decoder) decodeAt(off, depth int) (any, int, error) {
	if depth > maxDecodeDepth {
		return nil, 0, fmt.Errorf("mmdb decode depth exceeded (%d)", maxDecodeDepth)
	}
	if off < 0 || off >= len(d.buf) {
		return nil, 0, fmt.Errorf("mmdb decode offset %d out of bounds", off)
	}
	ctrl := d.buf[off]
	off++
	typ := int(ctrl >> 5)
	if typ == dtPointer {
		target, end, err := d.decodePointer(ctrl, off)
		if err != nil {
			return nil, 0, err
		}
		v, _, err := d.decodeAt(target, depth+1)
		if err != nil {
			return nil, 0, err
		}
		return v, end, nil
	}
	if typ == 0 { // 扩展类型：真实类型 = 下一字节 + 7
		if off >= len(d.buf) {
			return nil, 0, fmt.Errorf("mmdb extended type truncated")
		}
		typ = int(d.buf[off]) + 7
		off++
		if typ < 8 {
			return nil, 0, fmt.Errorf("mmdb invalid extended type %d", typ)
		}
	}
	size, off, err := d.sizeFromCtrl(ctrl, off)
	if err != nil {
		return nil, 0, err
	}
	return d.decodeByType(typ, off, size, depth)
}

// decodePointer 解析指针值（控制字节 001SSVVV；SS 为尺寸档，VVV 参与值计算）。
func (d *decoder) decodePointer(ctrl byte, off int) (target, end int, err error) {
	size := int(ctrl>>3) & 3
	partial := int(ctrl & 0x07)
	switch size {
	case 0:
		if off+1 > len(d.buf) {
			return 0, 0, fmt.Errorf("mmdb pointer truncated")
		}
		return d.baseOffset + (partial << 8) + int(d.buf[off]), off + 1, nil
	case 1:
		if off+2 > len(d.buf) {
			return 0, 0, fmt.Errorf("mmdb pointer truncated")
		}
		return d.baseOffset + pointerValueOffset[1] + (partial << 16) + u16be(d.buf, off), off + 2, nil
	case 2:
		if off+3 > len(d.buf) {
			return 0, 0, fmt.Errorf("mmdb pointer truncated")
		}
		return d.baseOffset + pointerValueOffset[2] + (partial << 24) + u24be(d.buf, off), off + 3, nil
	default: // 3：VVV 不用，随后 4 字节完整值
		if off+4 > len(d.buf) {
			return 0, 0, fmt.Errorf("mmdb pointer truncated")
		}
		return d.baseOffset + int(u32be(d.buf, off)), off + 4, nil
	}
}

// sizeFromCtrl 解析控制字节低 5 位承载的尺寸（29/30/31 为扩展尺寸）。
func (d *decoder) sizeFromCtrl(ctrl byte, off int) (size, next int, err error) {
	s := int(ctrl & 0x1f)
	switch {
	case s < 29:
		return s, off, nil
	case s == 29:
		if off+1 > len(d.buf) {
			return 0, 0, fmt.Errorf("mmdb size truncated")
		}
		return 29 + int(d.buf[off]), off + 1, nil
	case s == 30:
		if off+2 > len(d.buf) {
			return 0, 0, fmt.Errorf("mmdb size truncated")
		}
		return 285 + u16be(d.buf, off), off + 2, nil
	default: // 31
		if off+3 > len(d.buf) {
			return 0, 0, fmt.Errorf("mmdb size truncated")
		}
		return 65821 + u24be(d.buf, off), off + 3, nil
	}
}

// decodeByType 按类型解码 size 字节载荷（off 已越过控制/尺寸字节）。
func (d *decoder) decodeByType(typ, off, size, depth int) (any, int, error) {
	if typ == dtBoolean { // 布尔无载荷：尺寸位即值
		return size != 0, off, nil
	}
	if size < 0 || off+size > len(d.buf) {
		return nil, 0, fmt.Errorf("mmdb payload type %d size %d out of bounds", typ, size)
	}
	switch typ {
	case dtUTF8:
		return string(d.buf[off : off+size]), off + size, nil
	case dtBytes:
		out := make([]byte, size)
		copy(out, d.buf[off:off+size])
		return out, off + size, nil
	case dtUint16, dtUint32, dtUint64:
		if size > 8 {
			return nil, 0, fmt.Errorf("mmdb uint size %d too large", size)
		}
		var n uint64
		for i := 0; i < size; i++ {
			n = n<<8 | uint64(d.buf[off+i])
		}
		return n, off + size, nil
	case dtUint128:
		n := new(big.Int).SetBytes(d.buf[off : off+size])
		return n, off + size, nil
	case dtInt32:
		if size > 4 {
			return nil, 0, fmt.Errorf("mmdb int32 size %d too large", size)
		}
		var n int32
		for i := 0; i < size; i++ {
			n = n<<8 | int32(d.buf[off+i])
		}
		if size > 0 { // 符号扩展（大端有符号）
			if shift := 32 - size*8; shift > 0 {
				n = n << shift >> shift
			}
		}
		return n, off + size, nil
	case dtDouble:
		if size != 8 {
			return nil, 0, fmt.Errorf("mmdb double size %d != 8", size)
		}
		bits := u64be(d.buf, off)
		return float64FromBits(bits), off + 8, nil
	case dtFloat:
		if size != 4 {
			return nil, 0, fmt.Errorf("mmdb float size %d != 4", size)
		}
		return float32FromBits(u32be(d.buf, off)), off + 4, nil
	case dtMap:
		return d.decodeMap(off, size, depth+1)
	case dtArray:
		return d.decodeArray(off, size, depth+1)
	default:
		return nil, 0, fmt.Errorf("mmdb unsupported type %d", typ)
	}
}

// decodeMap 解码 size 个键值对（键经完整 decode，兼容指针键）。
func (d *decoder) decodeMap(off, size, depth int) (map[string]any, int, error) {
	out := make(map[string]any, size)
	var err error
	for i := 0; i < size; i++ {
		var k any
		k, off, err = d.decodeAt(off, depth)
		if err != nil {
			return nil, 0, err
		}
		key, ok := k.(string)
		if !ok {
			return nil, 0, fmt.Errorf("mmdb map key is not a string")
		}
		var v any
		v, off, err = d.decodeAt(off, depth)
		if err != nil {
			return nil, 0, err
		}
		out[key] = v
	}
	return out, off, nil
}

// decodeArray 解码 size 个元素。
func (d *decoder) decodeArray(off, size, depth int) ([]any, int, error) {
	out := make([]any, 0, size)
	var err error
	for i := 0; i < size; i++ {
		var v any
		v, off, err = d.decodeAt(off, depth)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, off, nil
}

// metaInt 元数据整型字段提取（uint16/32/64 统一为 uint64 解码）。
func metaInt(m map[string]any, key string) (int, bool) {
	v, ok := m[key].(uint64)
	if !ok {
		return 0, false
	}
	return int(v), true
}

// sortedKeys map 键排序（小工具，供确定性输出使用）。
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lastIndex 反向搜索子串（元数据标记定位）。
func lastIndex(buf, sep []byte) int {
	for i := len(buf) - len(sep); i >= 0; i-- {
		match := true
		for j := range sep {
			if buf[i+j] != sep[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// u16be/u24be/u32be/u64be 大端无符号读取（调用方保证边界）。
func u16be(b []byte, off int) int { return int(b[off])<<8 | int(b[off+1]) }

func u24be(b []byte, off int) int { return int(b[off])<<16 | int(b[off+1])<<8 | int(b[off+2]) }

func u32be(b []byte, off int) uint32 {
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
}

func u64be(b []byte, off int) uint64 {
	return uint64(u32be(b, off))<<32 | uint64(u32be(b, off+4))
}

// float64FromBits / float32FromBits IEEE754 位还原（math 标准库薄封装，集中转换点）。
func float64FromBits(bits uint64) float64 { return math.Float64frombits(bits) }

func float32FromBits(bits uint32) float32 { return math.Float32frombits(bits) }
