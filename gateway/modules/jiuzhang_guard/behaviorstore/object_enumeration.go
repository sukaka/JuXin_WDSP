package behaviorstore

import (
	"errors"
	"strconv"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

// objectEnumerationObserveLua 在单个 Hash 内原子维护滚动窗口。对象引用已是
// HMAC；Hash 键对主体/应用/接口再做一次哈希，字段名不包含原始对象 ID。
// 返回 {不同对象数, 请求数, 连续步进数, 本窗口是否首次达阈}。
const objectEnumerationObserveLua = `
local now = tonumber(ARGV[1])
local started = tonumber(redis.call('HGET', KEYS[1], 'start'))
if not started or now < started or now - started >= tonumber(ARGV[5]) then
  redis.call('DEL', KEYS[1])
  redis.call('HSET', KEYS[1], 'start', ARGV[1], 'distinct', 0, 'requests', 0, 'sequence_steps', 0, 'expected', '', 'reported', 0)
end
local ref = ARGV[2]
local nextRef = ARGV[3]
local seen = redis.call('HEXISTS', KEYS[1], 'ref:' .. ref) == 1
if not seen then
  local distinct = tonumber(redis.call('HGET', KEYS[1], 'distinct')) or 0
  if distinct < tonumber(ARGV[6]) then
    redis.call('HSET', KEYS[1], 'ref:' .. ref, '1')
    redis.call('HINCRBY', KEYS[1], 'distinct', 1)
  end
  if nextRef ~= '' and redis.call('HGET', KEYS[1], 'expected') == ref then
    redis.call('HINCRBY', KEYS[1], 'sequence_steps', 1)
  end
end
redis.call('HSET', KEYS[1], 'expected', nextRef)
local requests = redis.call('HINCRBY', KEYS[1], 'requests', 1)
local distinct = tonumber(redis.call('HGET', KEYS[1], 'distinct')) or 0
local steps = tonumber(redis.call('HGET', KEYS[1], 'sequence_steps')) or 0
local reported = tonumber(redis.call('HGET', KEYS[1], 'reported')) or 0
local alert = 0
if reported == 0 and ((distinct >= tonumber(ARGV[7]) and steps >= tonumber(ARGV[8])) or distinct >= tonumber(ARGV[9])) then
  alert = 1
  redis.call('HSET', KEYS[1], 'reported', 1)
end
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]))
return {distinct, requests, steps, alert}
`

var errObjectEnumerationResult = errors.New("behaviorstore: invalid object enumeration eval result")

// ObserveObject 实现 detectors.ObjectEnumerationStore。故障时按统一契约降级内存；
// 故障期本地计数不会回灌共享窗口，恢复后继续使用 Valkey 中已有的状态。
func (s *Store) ObserveObject(key, ref, nextRef string) detectors.ObjectEnumerationResult {
	fullKey := s.pfx + ":" + nsObjectEnumeration + ":" + counters.HashParts(key)
	out, err := s.eval(objectEnumerationObserveLua, []string{fullKey}, []string{
		strconv.FormatInt(s.now().UTC().UnixMilli(), 10),
		ref,
		nextRef,
		strconv.FormatInt(s.ttlFor(objectEnumerationTTLFloor).Milliseconds(), 10),
		strconv.FormatInt(detectors.ObjectEnumerationWindow.Milliseconds(), 10),
		strconv.Itoa(detectors.ObjectEnumerationMaxObjects),
		strconv.Itoa(detectors.ObjectEnumerationMinObjects),
		strconv.Itoa(detectors.ObjectEnumerationMinSequence),
		strconv.Itoa(detectors.ObjectEnumerationHighCardinality),
	})
	if err == nil && len(out) != 4 {
		err = errObjectEnumerationResult
	}
	if err != nil {
		s.warn("object_enumeration", err)
		return s.memEnumeration.ObserveObject(key, ref, nextRef)
	}
	return detectors.ObjectEnumerationResult{
		DistinctObjects: int(luaInt(out[0])),
		RequestCount:    int(luaInt(out[1])),
		SequentialSteps: int(luaInt(out[2])),
		Alert:           luaInt(out[3]) == 1,
	}
}
