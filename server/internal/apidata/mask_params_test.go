package apidata

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateMaskAlgorithmParams(t *testing.T) {
	for _, tc := range []struct {
		name      string
		algorithm string
		params    string
		wantErr   bool
	}{
		{name: "MASK 保持兼容", algorithm: "MASK", params: `{"keep_head":3}`},
		{name: "HASH 保持兼容", algorithm: "HASH", params: `{}`},
		{name: "REMOVE 保持兼容", algorithm: "REMOVE", params: `{}`},
		{name: "ENCRYPT key_id", algorithm: "ENCRYPT", params: `{"key_id":"mask_key-1"}`},
		{name: "ENCRYPT key_id 上限", algorithm: "ENCRYPT", params: `{"key_id":"` + strings.Repeat("k", 64) + `"}`},
		{name: "ENCRYPT 空参数", algorithm: "ENCRYPT", params: `{}`, wantErr: true},
		{name: "ENCRYPT key_id 空值", algorithm: "ENCRYPT", params: `{"key_id":""}`, wantErr: true},
		{name: "ENCRYPT key_id 非字符串", algorithm: "ENCRYPT", params: `{"key_id":1}`, wantErr: true},
		{name: "ENCRYPT key_id 超长", algorithm: "ENCRYPT", params: `{"key_id":"` + strings.Repeat("k", 65) + `"}`, wantErr: true},
		{name: "ENCRYPT key_id 非法字符", algorithm: "ENCRYPT", params: `{"key_id":"bad key"}`, wantErr: true},
		{name: "ENCRYPT 额外键", algorithm: "ENCRYPT", params: `{"key_id":"k1","map_id":"m1"}`, wantErr: true},
		{name: "MAP map_id", algorithm: "MAP", params: `{"map_id":"map_key-1"}`},
		{name: "MAP 空参数", algorithm: "MAP", params: `{}`, wantErr: true},
		{name: "MAP 旧 mapping 拒绝", algorithm: "MAP", params: `{"mapping":{"a":"b"}}`, wantErr: true},
		{name: "MAP map_id 空值", algorithm: "MAP", params: `{"map_id":""}`, wantErr: true},
		{name: "MAP map_id 非字符串", algorithm: "MAP", params: `{"map_id":1}`, wantErr: true},
		{name: "MAP map_id 超长", algorithm: "MAP", params: `{"map_id":"` + strings.Repeat("m", 65) + `"}`, wantErr: true},
		{name: "MAP map_id 非法字符", algorithm: "MAP", params: `{"map_id":"bad.id"}`, wantErr: true},
		{name: "MAP 额外键", algorithm: "MAP", params: `{"map_id":"m1","mapping":{}}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMaskAlgorithmParams(tc.algorithm, json.RawMessage(tc.params))
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestCreateEncryptAndMapRules(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))
	for _, tc := range []struct {
		algorithm string
		params    map[string]any
	}{
		{algorithm: "ENCRYPT", params: map[string]any{"key_id": "mask_k1"}},
		{algorithm: "MAP", params: map[string]any{"map_id": "map_1"}},
	} {
		req := validRuleReq()
		req["algorithm"] = tc.algorithm
		req["params_json"] = tc.params
		created := createRule(t, mux, req)
		if created.Algorithm != tc.algorithm {
			t.Fatalf("created algorithm = %s, want %s", created.Algorithm, tc.algorithm)
		}
	}
}
