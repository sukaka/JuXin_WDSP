package pcapevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

type FlowMeta struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

var captureRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// RequestEvidence 只含脱敏后的关联元数据，不包含请求/响应正文。
type RequestEvidence struct {
	RequestID     string    `json:"request_id"`
	TraceID       string    `json:"trace_id,omitempty"`
	ConnectionID  string    `json:"connection_id"`
	ObservedAt    time.Time `json:"observed_at"`
	CapturePoint  string    `json:"capture_point"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	Host          string    `json:"host"`
	BodyTruncated bool      `json:"body_truncated"`
	FirstPacketNo uint64    `json:"first_packet_no,omitempty"`
	LastPacketNo  uint64    `json:"last_packet_no,omitempty"`
}

// RequestLinker 只接受网关出口这一受信抓包点；客户端入口或不可信镜像不能用请求头冒充身份。
type RequestLinker struct {
	nodeID       string
	bootID       string
	capturePoint string
	onEvidence   func(RequestEvidence)
	skipped      atomic.Uint64
}

func NewRequestLinker(nodeID, capturePoint string, onEvidence func(RequestEvidence)) (*RequestLinker, error) {
	if nodeID == "" || capturePoint != "GATEWAY_EGRESS" {
		return nil, fmt.Errorf("request ID correlation requires a trusted GATEWAY_EGRESS capture point")
	}
	bootID, err := NewArtifactID()
	if err != nil {
		return nil, err
	}
	return &RequestLinker{nodeID: nodeID, bootID: bootID.String(), capturePoint: capturePoint, onEvidence: onEvidence}, nil
}

func (l *RequestLinker) Skipped() uint64 { return l.skipped.Load() }

// ConnectionID 对双向端点使用同一摘要，并绑定节点与抓包进程启动纪元。
func (l *RequestLinker) ConnectionID(meta FlowMeta) string {
	left := fmt.Sprintf("%s:%d", meta.SrcIP, meta.SrcPort)
	right := fmt.Sprintf("%s:%d", meta.DstIP, meta.DstPort)
	if right < left {
		left, right = right, left
	}
	input := strings.Join([]string{l.nodeID, l.bootID, left, right}, "\x00")
	digest := sha256.Sum256([]byte(input))
	return hex.EncodeToString(digest[:])
}

// HandleRequest 消费重组后的请求；网关适配器负责头部、Body上限与TCP重组。
func (l *RequestLinker) HandleRequest(req *http.Request, meta FlowMeta, bodyTruncated bool) {
	if req == nil || req.URL == nil || l.onEvidence == nil {
		l.skipped.Add(1)
		return
	}
	requestID := strings.TrimSpace(req.Header.Get("X-Request-Id"))
	path := req.URL.EscapedPath()
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if !captureRequestIDPattern.MatchString(requestID) || len(path) > 512 || len(method) > 16 || method == "" {
		l.skipped.Add(1)
		return
	}
	if path == "" {
		path = "/"
	}
	l.onEvidence(RequestEvidence{
		RequestID: requestID, TraceID: capturedTraceID(req.Header.Get("traceparent")),
		ConnectionID: l.ConnectionID(meta), ObservedAt: time.Now().UTC(),
		CapturePoint: l.capturePoint, Method: method, Path: path, Host: strings.TrimSpace(req.Host),
		BodyTruncated: bodyTruncated,
	})
}

func capturedTraceID(header string) string {
	parts := strings.Split(strings.TrimSpace(header), "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[3]) != 2 {
		return ""
	}
	if !validCaptureHex(parts[1], 32) || !validCaptureHex(parts[2], 16) || !validCaptureHex(parts[3], 2) {
		return ""
	}
	if parts[1] == strings.Repeat("0", 32) || parts[2] == strings.Repeat("0", 16) {
		return ""
	}
	return parts[1]
}

func validCaptureHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
