package apievent

import "time"

const SchemaVersion = 1

type Source struct {
	Type         string `json:"type"`
	Language     string `json:"language"`
	Framework    string `json:"framework"`
	AgentVersion string `json:"agent_version"`
	SourceEpoch  int64  `json:"source_epoch"`
}

type Service struct {
	Name        string `json:"name"`
	InstanceID  string `json:"instance_id"`
	Version     string `json:"version"`
	Environment string `json:"environment"`
	Namespace   string `json:"namespace"`
	Cluster     string `json:"cluster"`
}

type Trace struct {
	TraceID      string `json:"trace_id"`
	SpanID       string `json:"span_id"`
	ParentSpanID string `json:"parent_span_id"`
}

type HTTP struct {
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

type Field struct {
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

type Quality struct {
	RouteSource       string `json:"route_source"`
	RequestBodyState  string `json:"request_body_state"`
	ResponseBodyState string `json:"response_body_state"`
	CaptureSampled    bool   `json:"capture_sampled"`
	Truncated         bool   `json:"truncated"`
}

type Record struct {
	EventID              string    `json:"event_id"`
	OccurredAt           time.Time `json:"occurred_at"`
	ApplicationBindingID *string   `json:"application_binding_id"`
	BindingVersion       *int64    `json:"binding_version"`
	Source               Source    `json:"source"`
	Service              Service   `json:"service"`
	Trace                Trace     `json:"trace"`
	HTTP                 HTTP      `json:"http"`
	Fields               []Field   `json:"fields"`
	Quality              Quality   `json:"quality"`
}

type Batch struct {
	SchemaVersion int      `json:"schema_version"`
	Records       []Record `json:"records"`
}

type Response struct {
	AcceptedCount  int `json:"accepted_count"`
	DuplicateCount int `json:"duplicate_count"`
}

type CaptureBatch struct {
	SchemaVersion int             `json:"schema_version"`
	Records       []CaptureRecord `json:"records"`
}

type CaptureRecord struct {
	EventID              string      `json:"event_id"`
	OccurredAt           time.Time   `json:"occurred_at"`
	ApplicationBindingID *string     `json:"application_binding_id"`
	BindingVersion       *int64      `json:"binding_version"`
	Source               Source      `json:"source"`
	Service              Service     `json:"service"`
	Trace                Trace       `json:"trace"`
	HTTP                 CaptureHTTP `json:"http"`
}

type CaptureHTTP struct {
	Direction            string         `json:"direction"`
	Method               string         `json:"method"`
	Scheme               string         `json:"scheme"`
	Host                 string         `json:"host"`
	Route                string         `json:"route"`
	PathTemplate         string         `json:"path_template"`
	Status               int            `json:"status"`
	LatencyMS            int64          `json:"latency_ms"`
	PeerService          string         `json:"peer_service"`
	PeerAddress          string         `json:"peer_address,omitempty"`
	ClientAddress        string         `json:"client_address,omitempty"`
	ClientAddressSource  string         `json:"client_address_source,omitempty"`
	ServerAddress        string         `json:"server_address,omitempty"`
	MessagingSystem      string         `json:"messaging_system,omitempty"`
	MessagingDestination string         `json:"messaging_destination,omitempty"`
	Request              CaptureMessage `json:"request"`
	Response             CaptureMessage `json:"response"`
}

type CaptureMessage struct {
	ContentType string `json:"content_type"`
	BodyBase64  string `json:"body_base64"`
	BodyState   string `json:"body_state"`
	Truncated   bool   `json:"truncated"`
}
