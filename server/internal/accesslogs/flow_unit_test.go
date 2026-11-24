package accesslogs

import (
	"testing"
	"time"
)

func TestFlowBuilderIgnoresProtocolHeaderFieldNoise(t *testing.T) {
	start := time.Now().UTC().Add(-time.Hour)
	end := time.Now().UTC()
	filter := ListFilter{StartTime: &start, EndTime: &end}
	builder := &flowBuilder{
		nodes:       make(map[string]*flowAggregate),
		edges:       make(map[string]*flowAggregate),
		nodeMeta:    make(map[string]FlowNode),
		edgeMeta:    make(map[string]FlowEdge),
		allRequests: make(map[string]struct{}),
		sensitive:   make(map[string]struct{}),
	}

	// 历史误报行：header.sec-ch-ua-mobile 与 path.mobile.zip 的 sensitive.field 均不应计入涉敏流转
	builder.addRow(flowRow{
		requestID:       "req-noise",
		sourceIP:        "192.0.2.1",
		applicationID:   "app-1",
		applicationName: "官网",
		endpoint:        "GET /robots.txt",
		eventID:         "ev-1",
		fieldPath:       "header.sec-ch-ua-mobile",
		dataType:        "phone",
		direction:       "REQUEST",
		ruleID:          "sensitive.field",
	}, filter)
	builder.addRow(flowRow{
		requestID:       "req-path-noise",
		sourceIP:        "3.85.91.123",
		applicationID:   "app-1",
		applicationName: "官网",
		endpoint:        "GET /mobile.zip",
		eventID:         "ev-1b",
		fieldPath:       "path.mobile.zip",
		dataType:        "phone",
		direction:       "REQUEST",
		ruleID:          "sensitive.field",
	}, filter)

	// 值级命中行（含 path 值级命中）与自定义业务头仍正常计入涉敏流转
	builder.addRow(flowRow{
		requestID:       "req-real-value",
		sourceIP:        "192.0.2.2",
		applicationID:   "app-1",
		applicationName: "官网",
		endpoint:        "POST /v1/profile",
		eventID:         "ev-2",
		fieldPath:       "header.user-agent",
		dataType:        "phone",
		direction:       "REQUEST",
		ruleID:          "sensitive.value",
	}, filter)
	builder.addRow(flowRow{
		requestID:       "req-path-value",
		sourceIP:        "192.0.2.4",
		applicationID:   "app-1",
		applicationName: "官网",
		endpoint:        "GET /v1/users/{id}",
		eventID:         "ev-2b",
		fieldPath:       "path.{id}",
		dataType:        "phone",
		direction:       "REQUEST",
		ruleID:          "sensitive.value",
	}, filter)
	builder.addRow(flowRow{
		requestID:       "req-custom-header",
		sourceIP:        "192.0.2.3",
		applicationID:   "app-1",
		applicationName: "官网",
		endpoint:        "POST /v1/profile",
		eventID:         "ev-3",
		fieldPath:       "header.x-user-mobile",
		dataType:        "phone",
		direction:       "REQUEST",
		ruleID:          "sensitive.field",
	}, filter)

	res := builder.result(start, end, 10)
	if res.RequestCount != 5 {
		t.Fatalf("RequestCount = %d, want 5", res.RequestCount)
	}
	if res.SensitiveRequestCount != 3 {
		t.Fatalf("SensitiveRequestCount = %d, want 3 (noise must be excluded)", res.SensitiveRequestCount)
	}
	for _, node := range res.Nodes {
		if node.Kind == "REQUEST_FIELD" && (node.Name == "header.sec-ch-ua-mobile · 手机号" || node.Name == "path.mobile.zip · 手机号") {
			t.Fatalf("noise field must not appear as flow node: %+v", node)
		}
	}
}
