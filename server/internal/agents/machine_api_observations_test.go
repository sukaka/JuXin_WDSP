package agents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/ingest"
)

type fakeObservationProducer struct {
	records []ingest.Record
	topic   string
	err     error
}

func (f *fakeObservationProducer) PublishBatch(_ context.Context, topic string, records []ingest.Record) error {
	f.topic = topic
	f.records = append(f.records, records...)
	return f.err
}
func (f *fakeObservationProducer) Health(context.Context) error { return f.err }
func (f *fakeObservationProducer) Close() error                 { return nil }

type fakeObservationReceipts struct {
	accepted   []int
	duplicates int
	err        error
	eventIDs   []string
}

func (f *fakeObservationReceipts) RecordAPIObservationReceipts(_ context.Context, _ uuid.UUID, eventIDs []string, _ time.Time) ([]int, int, error) {
	f.eventIDs = append([]string(nil), eventIDs...)
	if f.accepted == nil && f.err == nil {
		f.accepted = make([]int, len(eventIDs))
		for i := range eventIDs {
			f.accepted[i] = i
		}
	}
	return f.accepted, f.duplicates, f.err
}

type fakeWorkloadBindings struct {
	applicationID *uuid.UUID
	err           error
}

func (f *fakeWorkloadBindings) ResolveWorkloadBinding(context.Context, uuid.UUID, uuid.UUID, int64, string, string) (*uuid.UUID, error) {
	return f.applicationID, f.err
}

type fakeObservationCapabilities struct{ schemas []int16 }

func (f *fakeObservationCapabilities) UpdateAPIObservationSchemas(_ context.Context, _ uuid.UUID, schemas []int16) error {
	f.schemas = schemas
	return nil
}

func validAPIObservationRecord() APIObservationRecord {
	bindingVersion := int64(3)
	bindingID := uuid.New()
	return APIObservationRecord{
		EventID: "ev-observation-1", OccurredAt: time.Now().UTC().Add(-time.Second),
		Source:               APIObservationSource{Type: "IN_PROCESS", Language: "java", Framework: "spring-webmvc", AgentVersion: "1.0.0", SourceEpoch: 1},
		Service:              APIObservationService{Name: "order-service", InstanceID: "order-1", Environment: "prod"},
		Trace:                APIObservationTrace{TraceID: strings.Repeat("a", 32), SpanID: strings.Repeat("b", 16)},
		HTTP:                 APIObservationHTTP{Direction: "SERVER", Method: "POST", Scheme: "https", Host: "orders.internal", PathTemplate: "/orders", Status: 201, LatencyMS: 18},
		Fields:               []APIObservationField{{Side: "REQUEST", Location: "JSON_BODY", Path: "$.customer.mobile", DataType: "PHONE", Level: "L3", ValueHMAC: "hmac-sha256:" + strings.Repeat("c", 64), HMACKeyID: "key-1", ValuePresent: true}},
		Quality:              APIObservationQuality{RouteSource: "FRAMEWORK", RequestBodyState: "ANALYZED", CaptureSampled: true},
		ApplicationBindingID: &bindingID,
		BindingVersion:       &bindingVersion,
	}
}

func observationBatchJSON(t *testing.T, records ...APIObservationRecord) string {
	t.Helper()
	raw, err := json.Marshal(APIObservationBatch{SchemaVersion: 1, Records: records})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestAPIObservationPeerAddress(t *testing.T) {
	record := validAPIObservationRecord()
	record.HTTP.PeerAddress = "192.0.2.10:8080"
	batch := APIObservationBatch{SchemaVersion: 1, Records: []APIObservationRecord{record}}
	if len(batch.Validate(time.Now())) != 1 {
		t.Fatal("peer_address must not contain a port")
	}
	record.HTTP.PeerAddress = "2001:db8::10"
	batch.Records[0] = record
	if invalid := batch.Validate(time.Now()); len(invalid) != 0 {
		t.Fatalf("valid IP rejected: %+v", invalid)
	}
	if batch.Records[0].HTTP.PeerAddress != "2001:db8::10" {
		t.Fatalf("unexpected normalized IP: %s", batch.Records[0].HTTP.PeerAddress)
	}
}

func TestAPIObservationsEndpoint(t *testing.T) {
	newHandler := func(store *fakeMachineStore, producer *fakeObservationProducer, receipts *fakeObservationReceipts, bindings *fakeWorkloadBindings) *MachineHandler {
		return NewMachineHandler(store).SetAPIObservationReceiver(producer, "wdsp.api.observations.v1", receipts, bindings, &fakeObservationCapabilities{})
	}
	t.Run("accepted with server resolved identity and binding", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		store.agentsByHash[HashSecret(cred)].APIObservationSchemas = []int{1}
		producer := &fakeObservationProducer{}
		receipts := &fakeObservationReceipts{}
		applicationID := uuid.New()
		bindingID := uuid.New()
		bindings := &fakeWorkloadBindings{applicationID: &applicationID}
		mux := newMachineMux(newHandler(store, producer, receipts, bindings))
		record := validAPIObservationRecord()
		record.ApplicationBindingID = &bindingID
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/api-observations", observationBatchJSON(t, record), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
		}
		if producer.topic != "wdsp.api.observations.v1" || len(producer.records) != 1 {
			t.Fatalf("unexpected produced records: %+v", producer.records)
		}
		var envelope APIObservationEnvelope
		if err := json.Unmarshal(producer.records[0].Value, &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.AgentID != agentID || envelope.ApplicationID == nil || *envelope.ApplicationID != applicationID {
			t.Fatalf("server identity not applied: %+v", envelope)
		}
		if strings.Contains(string(producer.records[0].Value), "secret") || strings.Contains(string(producer.records[0].Value), "raw_body") {
			t.Fatal("unexpected body in observation")
		}
		if !strings.Contains(rr.Body.String(), `"accepted_count":1`) {
			t.Fatalf("unexpected response: %s", rr.Body.String())
		}
	})

	t.Run("duplicate and producer failure", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		store.agentsByHash[HashSecret(cred)].APIObservationSchemas = []int{1}
		producer := &fakeObservationProducer{}
		receipts := &fakeObservationReceipts{accepted: []int{}, duplicates: 1}
		mux := newMachineMux(newHandler(store, producer, receipts, &fakeWorkloadBindings{}))
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/api-observations", observationBatchJSON(t, validAPIObservationRecord()), cred)
		if rr.Code != http.StatusAccepted || !strings.Contains(rr.Body.String(), `"duplicate_count":1`) {
			t.Fatalf("duplicate response: %d %s", rr.Code, rr.Body.String())
		}
		producer.err = errors.New("broker unavailable")
		rr = doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/api-observations", observationBatchJSON(t, validAPIObservationRecord()), cred)
		if rr.Code != http.StatusServiceUnavailable || rr.Header().Get("Retry-After") == "" {
			t.Fatalf("producer failure response: %d %s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid query and missing capability rejected before produce", func(t *testing.T) {
		store := newFakeMachineStore()
		agentID := uuid.New()
		cred := registerAgent(store, agentID, false)
		producer := &fakeObservationProducer{}
		mux := newMachineMux(newHandler(store, producer, &fakeObservationReceipts{}, &fakeWorkloadBindings{}))
		record := validAPIObservationRecord()
		record.HTTP.PathTemplate = "/orders?id=secret"
		rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/api-observations", observationBatchJSON(t, record), cred)
		if rr.Code != http.StatusBadRequest || len(producer.records) != 0 {
			t.Fatalf("invalid record accepted: %d %s", rr.Code, rr.Body.String())
		}
		store.agentsByHash[HashSecret(cred)].APIObservationSchemas = []int{1}
		record = validAPIObservationRecord()
		rr = doMachine(t, mux, http.MethodPost, "/api/v1/agents/"+agentID.String()+"/api-observations", observationBatchJSON(t, record), cred)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("valid record rejected: %d %s", rr.Code, rr.Body.String())
		}
	})
}

func TestEnrollAPIObservationCapability(t *testing.T) {
	store := newFakeMachineStore()
	mux := newMachineMux(NewMachineHandler(store))
	token := "wdt_" + strings.Repeat("cd", 32)
	body := `{"enrollment_token":"` + token + `","hostname":"h","ip":"10.0.0.1","capabilities":{"http_event_schema_versions":[1,2],"api_observation_schema_versions":[1]}}`
	rr := doMachine(t, mux, http.MethodPost, "/api/v1/agents/enroll", body, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if store.enrollIn == nil || len(store.enrollIn.APIObservationSchemas) != 1 || store.enrollIn.APIObservationSchemas[0] != 1 {
		t.Fatalf("capability not persisted: %+v", store.enrollIn)
	}
	if !strings.Contains(rr.Body.String(), `"api_observation_schema_versions":[1]`) {
		t.Fatalf("capability receipt missing: %s", rr.Body.String())
	}
}
