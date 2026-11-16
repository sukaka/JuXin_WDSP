package apiobserve

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/jiuzhang-waf/wdsp-agent/internal/apievent"
)

const (
	DefaultMaxBodyBytes = 256 << 10
	DefaultMaxFields    = 256
)

var eventIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var phonePattern = regexp.MustCompile(`^1[3-9][0-9]{9}$`)
var cnIDPattern = regexp.MustCompile(`^[0-9]{17}[0-9X]$`)

type Processor struct {
	agentID      string
	hmacKey      []byte
	hmacKeyID    string
	maxBodyBytes int
	maxFields    int
}

func NewProcessor(agentID string, hmacKey []byte, hmacKeyID string) *Processor {
	return &Processor{agentID: agentID, hmacKey: append([]byte(nil), hmacKey...), hmacKeyID: hmacKeyID, maxBodyBytes: DefaultMaxBodyBytes, maxFields: DefaultMaxFields}
}

func (p *Processor) ProcessBatch(batch apievent.CaptureBatch) ([]apievent.Record, error) {
	if batch.SchemaVersion != apievent.SchemaVersion {
		return nil, errors.New("local capture schema_version must be 1")
	}
	if len(batch.Records) == 0 || len(batch.Records) > 100 {
		return nil, errors.New("local capture records must contain 1..100 items")
	}
	out := make([]apievent.Record, 0, len(batch.Records))
	for i := range batch.Records {
		record, err := p.Process(batch.Records[i])
		if err != nil {
			return nil, fmt.Errorf("records[%d]: %w", i, err)
		}
		out = append(out, record)
	}
	return out, nil
}

func (p *Processor) Process(capture apievent.CaptureRecord) (apievent.Record, error) {
	var out apievent.Record
	if !eventIDPattern.MatchString(capture.EventID) {
		return out, errors.New("event_id is invalid")
	}
	if capture.OccurredAt.IsZero() {
		return out, errors.New("occurred_at is required")
	}
	if capture.Source.Type != "IN_PROCESS" || capture.Source.Language == "" || capture.Source.Framework == "" || capture.Source.AgentVersion == "" {
		return out, errors.New("source identity is incomplete")
	}
	if capture.Service.Name == "" || capture.Service.InstanceID == "" {
		return out, errors.New("service identity is incomplete")
	}
	if capture.HTTP.Direction != "SERVER" && capture.HTTP.Direction != "CLIENT" && capture.HTTP.Direction != "PRODUCER" && capture.HTTP.Direction != "CONSUMER" {
		return out, errors.New("direction is invalid")
	}
	id := sha256.Sum256([]byte(p.agentID + "\x00" + capture.EventID))
	out = apievent.Record{
		EventID: "ev-" + hex.EncodeToString(id[:]), OccurredAt: capture.OccurredAt.UTC(),
		ApplicationBindingID: capture.ApplicationBindingID, BindingVersion: capture.BindingVersion,
		Source: capture.Source, Service: capture.Service, Trace: capture.Trace,
		HTTP: apievent.HTTP{
			Direction: capture.HTTP.Direction, Method: strings.ToUpper(capture.HTTP.Method), Scheme: capture.HTTP.Scheme,
			Host: capture.HTTP.Host, Route: capture.HTTP.Route, PathTemplate: capture.HTTP.PathTemplate,
			Status: capture.HTTP.Status, LatencyMS: capture.HTTP.LatencyMS,
			RequestContentType: capture.HTTP.Request.ContentType, ResponseContentType: capture.HTTP.Response.ContentType,
			PeerService: capture.HTTP.PeerService, PeerAddress: capture.HTTP.PeerAddress,
			ClientAddress: capture.HTTP.ClientAddress, ClientAddressSource: capture.HTTP.ClientAddressSource,
			ServerAddress: capture.HTTP.ServerAddress, MessagingSystem: capture.HTTP.MessagingSystem,
			MessagingDestination: capture.HTTP.MessagingDestination,
		},
		Fields: []apievent.Field{}, Quality: apievent.Quality{
			RouteSource: routeSource(capture.HTTP), RequestBodyState: capture.HTTP.Request.BodyState,
			ResponseBodyState: capture.HTTP.Response.BodyState, CaptureSampled: true,
			Truncated: capture.HTTP.Request.Truncated || capture.HTTP.Response.Truncated,
		},
	}
	if out.Quality.RouteSource == "" {
		out.Quality.RouteSource = "UNKNOWN"
	}
	for _, side := range []struct {
		name    string
		message apievent.CaptureMessage
		state   *string
	}{
		{name: "REQUEST", message: capture.HTTP.Request, state: &out.Quality.RequestBodyState},
		{name: "RESPONSE", message: capture.HTTP.Response, state: &out.Quality.ResponseBodyState},
	} {
		fields, state := p.fieldsForMessage(side.name, side.message, len(out.Fields))
		out.Fields = append(out.Fields, fields...)
		*side.state = state
		if len(out.Fields) >= p.maxFields {
			out.Quality.Truncated = true
			break
		}
	}
	return out, nil
}

func (p *Processor) fieldsForMessage(side string, message apievent.CaptureMessage, already int) ([]apievent.Field, string) {
	if message.BodyBase64 == "" {
		if message.BodyState != "" {
			return nil, message.BodyState
		}
		return nil, "NOT_COLLECTED"
	}
	if !strings.Contains(strings.ToLower(message.ContentType), "json") {
		return nil, "UNSUPPORTED_CONTENT_TYPE"
	}
	if message.Truncated {
		return nil, "TRUNCATED"
	}
	if base64.StdEncoding.DecodedLen(len(message.BodyBase64)) > p.maxBodyBytes {
		return nil, "TRUNCATED"
	}
	body, err := base64.StdEncoding.DecodeString(message.BodyBase64)
	if err != nil || len(body) > p.maxBodyBytes {
		return nil, "DECODE_FAILED"
	}
	var value any
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, "DECODE_FAILED"
	}
	if decoder.More() {
		return nil, "DECODE_FAILED"
	}
	fields := make([]apievent.Field, 0)
	walker := &fieldWalker{processor: p, side: side, fields: fields, limit: p.maxFields - already}
	walker.walk("$", value, 0)
	return walker.fields, "ANALYZED"
}

type fieldWalker struct {
	processor *Processor
	side      string
	fields    []apievent.Field
	limit     int
}

func (w *fieldWalker) walk(path string, value any, depth int) {
	if len(w.fields) >= w.limit || depth > 8 {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			child := typed[key]
			if !utf8.ValidString(key) || strings.ContainsAny(key, "\x00\r\n") {
				continue
			}
			w.walk(path+"."+key, child, depth+1)
		}
	case []any:
		for _, child := range typed {
			w.walk(path+"[]", child, depth+1)
		}
	case string:
		w.add(path, "STRING", typed)
	case json.Number:
		w.add(path, "NUMBER", typed.String())
	case bool:
		w.add(path, "BOOLEAN", fmt.Sprintf("%t", typed))
	case nil:
		w.fields = append(w.fields, apievent.Field{Side: w.side, Location: "JSON_BODY", Path: path, DataType: "NULL", ValuePresent: false})
	}
}

func (w *fieldWalker) add(path, dataType, value string) {
	if len(w.fields) >= w.limit {
		return
	}
	field := apievent.Field{Side: w.side, Location: "JSON_BODY", Path: path, DataType: dataType, ValuePresent: true}
	normalized := normalizeDigits(value)
	switch {
	case phonePattern.MatchString(normalized):
		field.DataType, field.Level = "PHONE", "L3"
		field.ValueHMAC, field.HMACKeyID = w.processor.fingerprint(normalized)
	case validCNID(strings.ToUpper(value)):
		field.DataType, field.Level = "CN_ID", "L4"
		field.ValueHMAC, field.HMACKeyID = w.processor.fingerprint(strings.ToUpper(value))
	}
	w.fields = append(w.fields, field)
}

func (p *Processor) fingerprint(value string) (string, string) {
	if len(p.hmacKey) == 0 || p.hmacKeyID == "" {
		return "", ""
	}
	mac := hmac.New(sha256.New, p.hmacKey)
	_, _ = mac.Write([]byte(value))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), p.hmacKeyID
}

func normalizeDigits(value string) string {
	value = strings.TrimSpace(value)
	value = strings.NewReplacer("-", "", " ", "", "+86", "").Replace(value)
	return value
}

func validCNID(value string) bool {
	if !cnIDPattern.MatchString(value) {
		return false
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	check := []byte("10X98765432")
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(value[i]-'0') * weights[i]
	}
	return check[sum%11] == value[17]
}

func routeSource(http apievent.CaptureHTTP) string {
	if http.Route != "" {
		return "FRAMEWORK"
	}
	if http.PathTemplate != "" {
		return "NORMALIZED"
	}
	return "UNKNOWN"
}
