package apidataflow

import (
	"testing"
	"time"
)

func TestApplyNetworkViewPreservesEvidenceIdentity(t *testing.T) {
	graph := &Graph{
		Nodes: []Node{
			{ID: "service:orders", Name: "orders", ServiceName: "orders", Type: "SERVICE", Addresses: []string{"10.20.0.10"}},
			{ID: "service:profile", Name: "profile", ServiceName: "profile", Type: "SERVICE", Addresses: []string{"10.20.0.20"}},
		},
		Edges: []Edge{{ID: "original-edge-id", SourceID: "service:orders", TargetID: "service:profile", SourceName: "orders", TargetName: "profile", Protocol: "HTTP"}},
	}
	applyNetworkView(graph)
	if graph.Nodes[0].Name != "10.20.0.10" || graph.Nodes[0].Type != "ENDPOINT" {
		t.Fatalf("unexpected network node: %+v", graph.Nodes[0])
	}
	edge := graph.Edges[0]
	if edge.ID != "original-edge-id" || edge.SourceName != "10.20.0.10" || edge.TargetName != "10.20.0.20" || edge.TargetID != "endpoint:10.20.0.20" {
		t.Fatalf("network mapping broke evidence identity: %+v", edge)
	}
}

func TestGraphFilterViewValidation(t *testing.T) {
	filter := GraphFilter{Start: time.Now().Add(-time.Hour), End: time.Now(), MaxEdges: 50}
	if err := validateGraphFilter(&filter); err != nil || filter.View != "service" {
		t.Fatalf("default view=%q err=%v", filter.View, err)
	}
	filter.View = "physical"
	if err := validateGraphFilter(&filter); err == nil {
		t.Fatal("unsupported view must be rejected")
	}
}
