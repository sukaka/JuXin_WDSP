package apiruntime

import (
	"encoding/json"
	"testing"

	"github.com/jiuzhang-waf/server/internal/apimodels"
)

func f64(v float64) *float64 { return &v }

func TestParamObsMergeNullAndSampleCount(t *testing.T) {
	var row paramObsRow
	row.merge(ParamObservation{Location: "BODY", Name: "note", Path: "user.note", BaseType: "null", Null: true})
	row.merge(ParamObservation{Location: "BODY", Name: "note", Path: "user.note", BaseType: "string", Length: 5, ValueHash: "h1"})
	if row.sampleCount != 2 || row.nullCount != 1 {
		t.Fatalf("sample=%d null=%d, want 2/1", row.sampleCount, row.nullCount)
	}
	// null 观测不进长度蓄水池；非 null 观测进
	if len(row.lengthReservoir) != 1 || row.lengthReservoir[0] != 5 {
		t.Fatalf("length reservoir = %v, want [5]", row.lengthReservoir)
	}
}

func TestParamObsMergeReservoirCapAndDeterminism(t *testing.T) {
	var row paramObsRow
	for i := 0; i < apimodels.ReservoirCap+500; i++ {
		row.merge(ParamObservation{Location: "QUERY", Name: "n", Length: i % 100, ValueHash: "x", NumValue: f64(float64(i))})
	}
	if len(row.lengthReservoir) != apimodels.ReservoirCap {
		t.Fatalf("length reservoir = %d, want cap %d", len(row.lengthReservoir), apimodels.ReservoirCap)
	}
	if len(row.valueReservoir) != apimodels.ReservoirCap {
		t.Fatalf("value reservoir = %d, want cap %d", len(row.valueReservoir), apimodels.ReservoirCap)
	}
	for i := 1; i < len(row.valueReservoir); i++ {
		if row.valueReservoir[i] < row.valueReservoir[i-1] {
			t.Fatalf("value reservoir not sorted: %v...", row.valueReservoir[:10])
		}
	}
	if row.minVal == nil || *row.minVal != 0 || row.maxVal == nil || *row.maxVal != float64(apimodels.ReservoirCap+499) {
		t.Fatalf("min/max value wrong: %v %v", row.minVal, row.maxVal)
	}
}

func TestParamObsMergeHistogramAndAffix(t *testing.T) {
	var row paramObsRow
	row.merge(ParamObservation{Location: "QUERY", Name: "q", Length: 2, ValueHash: "v1",
		CharHist: map[string]int64{"97": 1, "98": 1}, PrefixHash: "p1", SuffixHash: "s1"})
	row.merge(ParamObservation{Location: "QUERY", Name: "q", Length: 3, ValueHash: "v2",
		CharHist: map[string]int64{"97": 2}, PrefixHash: "p1", SuffixHash: "s2"})
	want := apimodels.MergeHistogram(
		apimodels.MergeHistogram(nil, denseHistogram(map[string]int64{"97": 1, "98": 1})),
		denseHistogram(map[string]int64{"97": 2}))
	if len(row.charHistogram) != len(want) {
		t.Fatalf("hist len = %d, want %d", len(row.charHistogram), len(want))
	}
	for i := range want {
		if row.charHistogram[i] != want[i] {
			t.Fatalf("hist bucket %d = %d, want %d", i, row.charHistogram[i], want[i])
		}
	}
	if row.charHistogram[97] != 3 || row.charHistogram[98] != 1 {
		t.Fatalf("hist merge wrong: 97=%d 98=%d", row.charHistogram[97], row.charHistogram[98])
	}
	if row.prefixCounts["p1"] != 2 || row.suffixCounts["s1"] != 1 || row.suffixCounts["s2"] != 1 {
		t.Fatalf("affix counts wrong: %v %v", row.prefixCounts, row.suffixCounts)
	}
	// 熵重算可消费合并结果
	if _, ok := apimodels.ShannonEntropy(row.charHistogram); !ok {
		t.Fatal("merged histogram must feed ShannonEntropy")
	}
}

func TestDenseHistogramDropsInvalidBuckets(t *testing.T) {
	d := denseHistogram(map[string]int64{"-1": 5, "256": 5, "x": 5, "65": 0, "66": 2})
	if d == nil {
		t.Fatal("valid bucket dropped")
	}
	for i, c := range d {
		if i != 66 && c != 0 {
			t.Fatalf("invalid bucket leaked: %d=%d", i, c)
		}
	}
	if d[66] != 2 {
		t.Fatalf("valid bucket = %d, want 2", d[66])
	}
	if denseHistogram(map[string]int64{"-1": 1}) != nil {
		t.Fatal("all-invalid sparse map must yield nil")
	}
}

func TestParamObsMergeSensitiveShapeOnly(t *testing.T) {
	// 敏感参数：网关抑制 value_hash/值派生字段，仅长度形态进蓄水池
	var row paramObsRow
	row.merge(ParamObservation{Location: "QUERY", Name: "password", Length: 6})
	if row.lengthReservoir == nil || row.lengthReservoir[0] != 6 {
		t.Fatalf("sensitive length should still sample: %v", row.lengthReservoir)
	}
	if len(row.valueReservoir) != 0 || row.charHistogram != nil || row.prefixCounts != nil {
		t.Fatalf("sensitive obs must not produce value-derived state: %+v", row)
	}
}

func TestParamObservationLegacyJSONTolerant(t *testing.T) {
	// 旧版网关上报（无扩展键）缺省容忍
	var o ParamObservation
	if err := json.Unmarshal([]byte(`{"location":"QUERY","name":"q","base_type":"string","length":3,"value_hash":"ab"}`), &o); err != nil {
		t.Fatal(err)
	}
	if o.Null || o.CharHist != nil || o.PrefixHash != "" || o.SuffixHash != "" {
		t.Fatalf("legacy JSON must decode with zero extended fields: %+v", o)
	}
	var row paramObsRow
	row.merge(o)
	if row.sampleCount != 1 || row.nullCount != 0 || len(row.lengthReservoir) != 1 {
		t.Fatalf("legacy merge wrong: %+v", row)
	}
}

func TestMergeHashCapRing(t *testing.T) {
	var row paramObsRow
	for i := 0; i < valueHashCap+10; i++ {
		row.merge(ParamObservation{Location: "QUERY", Name: "q", ValueHash: string(rune('a'+i%26)) + string(rune('a'+i/26))})
	}
	if len(row.hashes) != valueHashCap {
		t.Fatalf("hashes = %d, want cap %d", len(row.hashes), valueHashCap)
	}
}
