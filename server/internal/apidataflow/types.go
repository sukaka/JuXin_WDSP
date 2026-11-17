package apidataflow

import (
	"time"

	"github.com/google/uuid"
)

type GraphFilter struct {
	Start         time.Time
	End           time.Time
	ApplicationID *uuid.UUID
	Method        string
	DataType      string
	MaxEdges      int
	View          string
}

type Node struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Type          string   `json:"type"`
	NetworkZone   string   `json:"network_zone"`
	ServiceName   string   `json:"service_name"`
	GroupName     string   `json:"group_name"`
	Addresses     []string `json:"addresses"`
	Environment   string   `json:"environment"`
	Namespace     string   `json:"namespace"`
	Cluster       string   `json:"cluster"`
	Calls         uint64   `json:"calls"`
	APICount      uint64   `json:"api_count"`
	AvgLatencyMS  float64  `json:"avg_latency_ms"`
	MaxLatencyMS  int64    `json:"max_latency_ms"`
	ErrorRate     float64  `json:"error_rate"`
	Health        string   `json:"health"`
	IncomingCount uint64   `json:"incoming_count"`
	OutgoingCount uint64   `json:"outgoing_count"`
}

type Edge struct {
	ID               string          `json:"id"`
	SourceID         string          `json:"source_id"`
	TargetID         string          `json:"target_id"`
	SourceName       string          `json:"source_name"`
	TargetName       string          `json:"target_name"`
	SourceZone       string          `json:"source_zone"`
	TargetZone       string          `json:"target_zone"`
	BoundaryType     string          `json:"boundary_type"`
	BoundaryEvidence string          `json:"boundary_evidence"`
	Protocol         string          `json:"protocol"`
	Method           string          `json:"method"`
	PathTemplate     string          `json:"path_template"`
	APIs             []string        `json:"apis"`
	Calls            uint64          `json:"calls"`
	Errors           uint64          `json:"errors"`
	AvgLatencyMS     float64         `json:"avg_latency_ms"`
	MaxLatencyMS     int64           `json:"max_latency_ms"`
	DataTypes        []string        `json:"data_types"`
	Fields           []FieldEvidence `json:"fields"`
	EvidenceType     string          `json:"evidence_type"`
	Confidence       float64         `json:"confidence"`
	FirstSeenAt      time.Time       `json:"first_seen_at"`
	LastSeenAt       time.Time       `json:"last_seen_at"`
	SampleTraceIDs   []string        `json:"sample_trace_ids"`
}

type DataQuality struct {
	Observations  uint64  `json:"observations"`
	TraceLinked   uint64  `json:"trace_linked"`
	TraceCoverage float64 `json:"trace_coverage"`
	Truncated     uint64  `json:"truncated"`
	DataSource    string  `json:"data_source"`
	Partial       bool    `json:"partial"`
	Message       string  `json:"message"`
}

type Graph struct {
	Nodes                []Node      `json:"nodes"`
	Edges                []Edge      `json:"edges"`
	Truncated            bool        `json:"truncated"`
	View                 string      `json:"view"`
	Quality              DataQuality `json:"quality"`
	RuntimeFieldsWarning string      `json:"-"`
}

type EvidenceRecord struct {
	AgentID             uuid.UUID       `json:"agent_id"`
	EventID             string          `json:"event_id"`
	EdgeID              string          `json:"edge_id"`
	OccurredAt          time.Time       `json:"occurred_at"`
	ServiceName         string          `json:"service_name"`
	TraceID             string          `json:"trace_id"`
	SpanID              string          `json:"span_id"`
	PeerAddress         string          `json:"peer_address,omitempty"`
	ClientAddress       string          `json:"client_address,omitempty"`
	ClientAddressSource string          `json:"client_address_source,omitempty"`
	ServerAddress       string          `json:"server_address,omitempty"`
	SourceZone          string          `json:"source_zone,omitempty"`
	TargetZone          string          `json:"target_zone,omitempty"`
	BoundaryType        string          `json:"boundary_type,omitempty"`
	BoundaryEvidence    string          `json:"boundary_evidence,omitempty"`
	Fields              []FieldEvidence `json:"fields"`
	EvidenceType        string          `json:"evidence_type"`
	Confidence          float64         `json:"confidence"`
}
