// util.go apigql 内部辅助（严格 JSON 解码与审计摘要数字格式化）。
package apigql

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// decodeJSONStrict 严格解码：上限读取 + 拒绝未知字段 + 拒绝多余内容。
func decodeJSONStrict(r *http.Request, v interface{}, limit int64) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > limit {
		return errors.New("请求体超长")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("请求体含多余内容")
	}
	return nil
}

// itoa / itoa64 审计摘要数字格式化。
func itoa(n int) string     { return strconv.Itoa(n) }
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
