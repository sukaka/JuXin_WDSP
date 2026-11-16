package tests

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/jiuzhang-waf/server/internal/apiassets"
)

func TestStage8APIProtocolDimensions(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apiassets.NewStore(env.db)

	cases := []struct {
		name, protocol, technical, interaction string
	}{
		{"rest", "REST", "REST", "REQUEST_RESPONSE"},
		{"rest_json_normalized", " rest_json ", "REST_JSON", "REQUEST_RESPONSE"},
		{"rest_xml", "REST_XML", "REST_XML", "REQUEST_RESPONSE"},
		{"form_api", "FORM_API", "FORM_API", "REQUEST_RESPONSE"},
		{"graphql", "GRAPHQL", "GRAPHQL", "REQUEST_RESPONSE"},
		{"json_rpc", "JSON_RPC", "JSON_RPC", "RPC"},
		{"xml_rpc", "XML_RPC", "XML_RPC", "RPC"},
		{"soap", "SOAP", "SOAP", "RPC"},
		{"webhook", "WEBHOOK", "WEBHOOK", "EVENT_CALLBACK"},
		{"file_upload", "FILE_UPLOAD", "FILE_UPLOAD", "FILE_TRANSFER"},
		{"file_download", "FILE_DOWNLOAD", "FILE_DOWNLOAD", "FILE_TRANSFER"},
		{"websocket_handshake", "WEBSOCKET_HANDSHAKE", "WEBSOCKET_HANDSHAKE", "BIDIRECTIONAL_STREAM"},
		{"server_sent_events", "SERVER_SENT_EVENTS", "SERVER_SENT_EVENTS", "SERVER_PUSH"},
		{"grpc", "GRPC", "GRPC", "RPC"},
		{"legacy_websocket", "websocket", "WEBSOCKET", "BIDIRECTIONAL_STREAM"},
		{"unknown_http_api", "UNKNOWN_HTTP_API", "UNKNOWN_HTTP_API", ""},
		{"invalid_protocol", "NOT_A_PROTOCOL", "UNKNOWN_HTTP_API", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ep, err := store.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
				Method: "GET", PathTemplate: fmt.Sprintf("/s8-protocol/%s", c.name), ProtocolType: c.protocol,
				Confidence: 0.9, IsAPI: true,
			})
			if err != nil {
				t.Fatalf("seed endpoint: %v", err)
			}
			dims, err := store.AutoClassify(ctx, ep.ID)
			if err != nil {
				t.Fatalf("AutoClassify: %v", err)
			}
			got := map[string]apiassets.ClassificationDimension{}
			for _, d := range dims {
				got[d.Dimension] = d
			}
			technical := got["TECHNICAL_PROTOCOL"]
			if technical.Value != c.technical || technical.Source != "AUTO" || technical.EndpointID != ep.ID {
				t.Fatalf("TECHNICAL_PROTOCOL=%+v, want value=%q source=AUTO endpoint=%s", technical, c.technical, ep.ID)
			}
			if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
				WHERE endpoint_id=$1 AND dimension='TECHNICAL_PROTOCOL' AND value=$2 AND source='AUTO'`, ep.ID, c.technical); n != 1 {
				t.Fatalf("TECHNICAL_PROTOCOL row count=%d, want 1", n)
			}

			interaction, ok := got["INTERACTION_MODE"]
			if c.interaction == "" {
				if ok {
					t.Fatalf("unexpected INTERACTION_MODE: %+v", interaction)
				}
				if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
					WHERE endpoint_id=$1 AND dimension='INTERACTION_MODE'`, ep.ID); n != 0 {
					t.Fatalf("INTERACTION_MODE row count=%d, want 0", n)
				}
				return
			}
			if !ok || interaction.Value != c.interaction || interaction.Source != "AUTO" || interaction.EndpointID != ep.ID {
				t.Fatalf("INTERACTION_MODE=%+v, want value=%q source=AUTO endpoint=%s", interaction, c.interaction, ep.ID)
			}
			if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
				WHERE endpoint_id=$1 AND dimension='INTERACTION_MODE' AND value=$2 AND source='AUTO'`, ep.ID, c.interaction); n != 1 {
				t.Fatalf("INTERACTION_MODE row count=%d, want 1", n)
			}
		})
	}

	t.Run("empty_protocol", func(t *testing.T) {
		ep := s8SeedEndpoint(t, env, "GET", "/s8-protocol/empty", 0.9)
		s8Exec(t, env, `UPDATE api_endpoints SET protocol_type='' WHERE id=$1`, ep.ID)
		dims, err := store.AutoClassify(ctx, ep.ID)
		if err != nil {
			t.Fatalf("AutoClassify: %v", err)
		}
		for _, d := range dims {
			if d.Dimension == "TECHNICAL_PROTOCOL" || d.Dimension == "INTERACTION_MODE" {
				t.Fatalf("empty protocol produced dimension: %+v", d)
			}
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions
			WHERE endpoint_id=$1 AND dimension IN ('TECHNICAL_PROTOCOL','INTERACTION_MODE')`, ep.ID); n != 0 {
			t.Fatalf("empty protocol dimension row count=%d, want 0", n)
		}
	})

	t.Run("classification_locked", func(t *testing.T) {
		ep, err := store.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
			Method: "GET", PathTemplate: "/s8-protocol/locked", ProtocolType: "GRPC",
			Confidence: 0.9, IsAPI: true,
		})
		if err != nil {
			t.Fatalf("seed endpoint: %v", err)
		}
		if err := store.SetClassificationLocked(ctx, ep.ID, true); err != nil {
			t.Fatalf("lock classification: %v", err)
		}
		if _, err := store.AutoClassify(ctx, ep.ID); !errors.Is(err, apiassets.ErrClassificationLocked) {
			t.Fatalf("AutoClassify locked error=%v, want ErrClassificationLocked", err)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_classification_dimensions WHERE endpoint_id=$1`, ep.ID); n != 0 {
			t.Fatalf("locked classification wrote %d rows, want 0", n)
		}
	})
}
