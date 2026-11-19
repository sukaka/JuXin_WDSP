package agents

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	APIObservationMaxBatchRecords = 100
	APIObservationMaxFields       = 256
)

var (
	apiObservationEventIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	apiObservationHMACPattern    = regexp.MustCompile(`^hmac-sha256:[0-9a-f]{64}$`)
	apiObservationTracePattern   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	apiObservationSpanPattern    = regexp.MustCompile(`^[0-9a-f]{16}$`)
	apiObservationMethodPattern  = regexp.MustCompile(`^[A-Z]+$`)
	apiObservationLevelPattern   = regexp.MustCompile(`^L[1-5]$`)
)

type APIObservationSource struct {
	Type         string `json:"type"`
	Language     string `json:"language"`
	Framework    string `json:"framework"`
	AgentVersion string `json:"agent_version"`
	SourceEpoch  int64  `json:"source_epoch"`
}

type APIObservationService struct {
	Name        string `json:"name"`
	InstanceID  string `json:"instance_id"`
	Version     string `json:"version"`
	Environment string `json:"environment"`
	Namespace   string `json:"namespace"`
	Cluster     string `json:"cluster"`
}

type APIObservationTrace struct {
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id"`
}

type APIObservationHTTP struct {
	Direction            string `json:"direction"`
	Method               string `json:"method"`
	Scheme               string `json:"scheme"`
	Host                 string `json:"host"`
	Route                string `json:"route"`
	PathTemplate         string `json:"path_template"`
	Status               int    `json:"status"`
	LatencyMS            int64  `json:"latency_ms"`
	RequestContentType   string `json:"request_content_type"`
	ResponseContentType  string `json:"response_content_type"`
	PeerService          string `json:"peer_service"`
	PeerAddress          string `json:"peer_address,omitempty"`
	ClientAddress        string `json:"client_address,omitempty"`
	ClientAddressSource  string `json:"client_address_source,omitempty"`
	ServerAddress        string `json:"server_address,omitempty"`
	MessagingSystem      string `json:"messaging_system,omitempty"`
	MessagingDestination string `json:"messaging_destination,omitempty"`
}

type APIObservationField struct {
	Side         string `json:"side"`
	Location     string `json:"location"`
	Path         string `json:"path"`
	DataType     string `json:"data_type"`
	Level        string `json:"level"`
	ValueHMAC    string `json:"value_hmac"`
	HMACKeyID    string `json:"hmac_key_id"`
	ValuePresent bool   `json:"value_present"`
	Truncated    bool   `json:"truncated"`
}

type APIObservationQuality struct {
	RouteSource       string `json:"route_source"`
	RequestBodyState  string `json:"request_body_state"`
	ResponseBodyState string `json:"response_body_state"`
	CaptureSampled    bool   `json:"capture_sampled"`
	Truncated         bool   `json:"truncated"`
}

type APIObservationRecord struct {
	EventID              string                `json:"event_id"`
	OccurredAt           time.Time             `json:"occurred_at"`
	ApplicationBindingID *uuid.UUID            `json:"application_binding_id"`
	BindingVersion       *int64                `json:"binding_version"`
	Source               APIObservationSource  `json:"source"`
	Service              APIObservationService `json:"service"`
	Trace                APIObservationTrace   `json:"trace"`
	HTTP                 APIObservationHTTP    `json:"http"`
	Fields               []APIObservationField `json:"fields"`
	Quality              APIObservationQuality `json:"quality"`
}

type APIObservationBatch struct {
	SchemaVersion int                    `json:"schema_version"`
	Records       []APIObservationRecord `json:"records"`
}

type APIObservationEnvelope struct {
	SchemaVersion int        `json:"schema_version"`
	AgentID       uuid.UUID  `json:"agent_id"`
	ApplicationID *uuid.UUID `json:"application_id,omitempty"`
	ReceivedAt    time.Time  `json:"received_at"`
	APIObservationRecord
}

func (b *APIObservationBatch) Validate(now time.Time) []InvalidRecord {
	if b.SchemaVersion != APIObservationSchemaV1 {
		return []InvalidRecord{{Index: -1, Reason: "schema_version 须为 1"}}
	}
	if len(b.Records) == 0 {
		return []InvalidRecord{{Index: -1, Reason: "records 不能为空"}}
	}
	if len(b.Records) > APIObservationMaxBatchRecords {
		return []InvalidRecord{{Index: -1, Reason: "records 每批最多 100 条"}}
	}
	var out []InvalidRecord
	for i := range b.Records {
		if err := b.Records[i].validate(now); err != nil {
			out = append(out, InvalidRecord{Index: i, Reason: fmt.Sprintf("records[%d]: %v", i, err)})
		}
	}
	return out
}

func (r *APIObservationRecord) validate(now time.Time) error {
	r.EventID = strings.TrimSpace(r.EventID)
	if !apiObservationEventIDPattern.MatchString(r.EventID) {
		return errors.New("event_id 缺失或格式非法")
	}
	if r.OccurredAt.IsZero() || r.OccurredAt.After(now.Add(5*time.Minute)) {
		return errors.New("occurred_at 缺失或超过允许时钟偏差")
	}
	if (r.ApplicationBindingID == nil) != (r.BindingVersion == nil) {
		return errors.New("application_binding_id 与 binding_version 必须同有同无")
	}
	if r.BindingVersion != nil && *r.BindingVersion <= 0 {
		return errors.New("binding_version 须为正整数")
	}
	if r.Source.Type != "IN_PROCESS" {
		return errors.New("source.type 仅支持 IN_PROCESS")
	}
	if err := boundedStrings(map[string]string{
		"source.language": r.Source.Language, "source.framework": r.Source.Framework,
		"source.agent_version": r.Source.AgentVersion,
	}, 64); err != nil {
		return err
	}
	if r.Source.Language == "" || r.Source.Framework == "" || r.Source.AgentVersion == "" || r.Source.SourceEpoch < 0 {
		return errors.New("source.language/framework/agent_version 必填且 source_epoch 不得为负")
	}
	if err := boundedStrings(map[string]string{
		"service.name": r.Service.Name, "service.instance_id": r.Service.InstanceID,
		"service.version": r.Service.Version, "service.environment": r.Service.Environment,
		"service.namespace": r.Service.Namespace, "service.cluster": r.Service.Cluster,
	}, 128); err != nil {
		return err
	}
	if r.Service.Name == "" || r.Service.InstanceID == "" {
		return errors.New("service.name 与 instance_id 必填")
	}
	if r.Trace.TraceID != "" && (!apiObservationTracePattern.MatchString(r.Trace.TraceID) || r.Trace.TraceID == strings.Repeat("0", 32)) {
		return errors.New("trace_id 须为 32 位小写 hex 且不得全零")
	}
	for name, value := range map[string]string{"span_id": r.Trace.SpanID, "parent_span_id": r.Trace.ParentSpanID} {
		if value != "" && (!apiObservationSpanPattern.MatchString(value) || value == strings.Repeat("0", 16)) {
			return fmt.Errorf("%s 须为 16 位小写 hex 且不得全零", name)
		}
	}
	if (r.Trace.TraceID == "") != (r.Trace.SpanID == "") {
		return errors.New("trace_id 与 span_id 必须同有同无")
	}
	if err := r.HTTP.validate(); err != nil {
		return err
	}
	if len(r.Fields) > APIObservationMaxFields {
		return errors.New("fields 最多 256 个")
	}
	for i := range r.Fields {
		if err := r.Fields[i].validate(); err != nil {
			return fmt.Errorf("fields[%d]: %w", i, err)
		}
	}
	return r.Quality.validate()
}

func (h *APIObservationHTTP) validate() error {
	switch h.Direction {
	case "SERVER", "CLIENT":
		if h.Method == "" || h.Host == "" || h.PathTemplate == "" {
			return errors.New("HTTP SERVER/CLIENT 的 method、host、path_template 必填")
		}
	case "PRODUCER", "CONSUMER":
		if h.MessagingSystem == "" || h.MessagingDestination == "" {
			return errors.New("PRODUCER/CONSUMER 的 messaging_system 与 messaging_destination 必填")
		}
	default:
		return errors.New("direction 仅支持 SERVER/CLIENT/PRODUCER/CONSUMER")
	}
	h.Method = strings.ToUpper(strings.TrimSpace(h.Method))
	if len(h.Method) > 16 || (h.Direction == "SERVER" || h.Direction == "CLIENT") && !apiObservationMethodPattern.MatchString(h.Method) {
		return errors.New("method 非法")
	}
	if h.Scheme != "" && h.Scheme != "http" && h.Scheme != "https" {
		return errors.New("scheme 仅支持 http/https")
	}
	if err := boundedStrings(map[string]string{
		"host": h.Host, "route": h.Route, "path_template": h.PathTemplate,
		"request_content_type": h.RequestContentType, "response_content_type": h.ResponseContentType,
		"peer_service": h.PeerService, "messaging_system": h.MessagingSystem,
		"messaging_destination": h.MessagingDestination,
	}, 512); err != nil {
		return err
	}
	if strings.ContainsAny(h.Route, "?#") || strings.ContainsAny(h.PathTemplate, "?#") {
		return errors.New("route/path_template 不得包含 Query 或 Fragment")
	}
	if h.Status != 0 && (h.Status < 100 || h.Status > 599) {
		return errors.New("status 须为 0 或 100..599")
	}
	if h.LatencyMS < 0 || h.LatencyMS > int64(^uint32(0)>>1) {
		return errors.New("latency_ms 超出范围")
	}
	for _, item := range []struct {
		name  string
		value *string
	}{
		{name: "peer_address", value: &h.PeerAddress},
		{name: "client_address", value: &h.ClientAddress},
		{name: "server_address", value: &h.ServerAddress},
	} {
		raw := strings.TrimSpace(*item.value)
		if raw == "" {
			*item.value = ""
			continue
		}
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return fmt.Errorf("%s 须为不含端口的 IP 地址", item.name)
		}
		*item.value = address.String()
	}
	h.ClientAddressSource = strings.TrimSpace(h.ClientAddressSource)
	if h.ClientAddressSource == "" {
		switch {
		case h.ClientAddress == "" && h.PeerAddress != "":
			h.ClientAddress = h.PeerAddress
			h.ClientAddressSource = "DIRECT_PEER"
		case h.ClientAddress != "":
			h.ClientAddressSource = "UNKNOWN"
		}
	}
	switch h.ClientAddressSource {
	case "", "DIRECT_PEER", "TRUSTED_PROXY", "GATEWAY", "UNKNOWN":
	default:
		return errors.New("client_address_source 仅支持 DIRECT_PEER/TRUSTED_PROXY/GATEWAY/UNKNOWN")
	}
	if h.ClientAddressSource == "DIRECT_PEER" && h.PeerAddress != "" {
		if h.ClientAddress == "" {
			h.ClientAddress = h.PeerAddress
		}
		if h.ClientAddress != h.PeerAddress {
			return errors.New("DIRECT_PEER 的 client_address 必须与 peer_address 一致")
		}
	}
	return nil
}

func (f *APIObservationField) validate() error {
	switch f.Side {
	case "REQUEST", "RESPONSE", "MESSAGE":
	default:
		return errors.New("side 非法")
	}
	switch f.Location {
	case "JSON_BODY", "FORM", "XML", "QUERY", "HEADER", "PATH", "MESSAGE":
	default:
		return errors.New("location 非法")
	}
	if err := boundedStrings(map[string]string{
		"path": f.Path, "data_type": f.DataType, "level": f.Level,
		"value_hmac": f.ValueHMAC, "hmac_key_id": f.HMACKeyID,
	}, 512); err != nil {
		return err
	}
	if f.Path == "" || f.DataType == "" {
		return errors.New("path 与 data_type 必填")
	}
	if f.Level != "" && !apiObservationLevelPattern.MatchString(f.Level) {
		return errors.New("level 仅支持 L1..L5")
	}
	if f.ValueHMAC != "" {
		if !apiObservationHMACPattern.MatchString(f.ValueHMAC) || f.HMACKeyID == "" {
			return errors.New("value_hmac 或 hmac_key_id 非法")
		}
	}
	return nil
}

func (q *APIObservationQuality) validate() error {
	if q.RouteSource == "" {
		q.RouteSource = "UNKNOWN"
	}
	switch q.RouteSource {
	case "FRAMEWORK", "NORMALIZED", "UNKNOWN":
	default:
		return errors.New("quality.route_source 非法")
	}
	for _, state := range []string{q.RequestBodyState, q.ResponseBodyState} {
		if state == "" {
			continue
		}
		switch state {
		case "ANALYZED", "NOT_COLLECTED", "SAMPLED_OUT", "TRUNCATED", "UNSUPPORTED_CONTENT_TYPE", "DECODE_FAILED", "POLICY_DISABLED":
		default:
			return errors.New("quality body_state 非法")
		}
	}
	return nil
}

func boundedStrings(values map[string]string, max int) error {
	for name, value := range values {
		if !utf8.ValidString(value) || len(value) > max || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s 为空、超长或含控制字符", name)
		}
	}
	return nil
}
