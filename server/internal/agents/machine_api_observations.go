package agents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/ingest"
)

const machineAPIObservationMaxBody = 4 << 20

type apiObservationCapabilityStore interface {
	UpdateAPIObservationSchemas(context.Context, uuid.UUID, []int16) error
}

type apiObservationReceiver struct {
	producer     ingest.Producer
	topic        string
	receipts     APIObservationReceiptStore
	bindings     WorkloadBindingStore
	capabilities apiObservationCapabilityStore
}

func (h *MachineHandler) SetAPIObservationReceiver(producer ingest.Producer, topic string, receipts APIObservationReceiptStore, bindings WorkloadBindingStore, capabilities apiObservationCapabilityStore) *MachineHandler {
	h.apiObservation = &apiObservationReceiver{producer: producer, topic: topic, receipts: receipts, bindings: bindings, capabilities: capabilities}
	return h
}

func (h *MachineHandler) APIObservations(w http.ResponseWriter, r *http.Request) {
	body, err := readMachineBody(w, r, machineAPIObservationMaxBody)
	if err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求体过大或读取失败")
		return
	}
	agent, method, ok := h.authenticate(w, r, body)
	if !ok {
		return
	}
	if method == authMethodBearer && !h.matchPathAgent(w, r, agent) {
		return
	}
	if !requireEnabled(w, agent) {
		return
	}
	if !agent.SupportsAPIObservationV1() {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "该 Agent 未协商 API Observation schema v1")
		return
	}
	receiver := h.apiObservation
	if receiver == nil || receiver.producer == nil || receiver.topic == "" || receiver.receipts == nil {
		w.Header().Set("Retry-After", "5")
		machineError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "API Observation 接收层未配置或不可用")
		return
	}
	var batch APIObservationBatch
	if err := decodeMachineJSON(body, &batch); err != nil {
		machineError(w, http.StatusBadRequest, mcInvalidArgument, "请求格式错误")
		return
	}
	if invalid := batch.Validate(h.now().UTC()); len(invalid) > 0 {
		machineJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":           map[string]string{"code": mcInvalidArgument, "message": "批次含非法记录，整批未接收"},
			"invalid_records": invalid,
		})
		return
	}

	receivedAt := h.now().UTC()
	records := make([]ingest.Record, 0, len(batch.Records))
	eventIDs := make([]string, 0, len(batch.Records))
	for i := range batch.Records {
		record := &batch.Records[i]
		var applicationID *uuid.UUID
		if record.ApplicationBindingID != nil {
			if receiver.bindings == nil {
				machineError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "工作负载绑定校验不可用")
				return
			}
			applicationID, err = receiver.bindings.ResolveWorkloadBinding(r.Context(), agent.AgentID, *record.ApplicationBindingID, *record.BindingVersion, record.Service.Name, record.Service.Environment)
			if err != nil {
				if errors.Is(err, ErrWorkloadBinding) {
					machineError(w, http.StatusForbidden, mcForbidden, "工作负载绑定不存在、已失效或与服务身份不匹配")
					return
				}
				machineInternal(w, r, err)
				return
			}
		}
		envelope := APIObservationEnvelope{
			SchemaVersion: APIObservationSchemaV1, AgentID: agent.AgentID,
			ApplicationID: applicationID, ReceivedAt: receivedAt, APIObservationRecord: *record,
		}
		value, err := json.Marshal(envelope)
		if err != nil {
			machineInternal(w, r, err)
			return
		}
		records = append(records, ingest.Record{
			Key: agent.AgentID.String(), Value: value,
			Headers: map[string]string{
				"schema_version": "1", "event_id": record.EventID,
				"agent_id": agent.AgentID.String(), "content_type": "application/json",
			},
		})
		eventIDs = append(eventIDs, record.EventID)
	}
	if err := receiver.producer.PublishBatch(r.Context(), receiver.topic, records); err != nil {
		w.Header().Set("Retry-After", "5")
		machineError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "API Observation 接收层暂时不可用，请有界重试")
		return
	}
	accepted, duplicates, err := receiver.receipts.RecordAPIObservationReceipts(r.Context(), agent.AgentID, eventIDs, receivedAt)
	if err != nil {
		w.Header().Set("Retry-After", "5")
		machineError(w, http.StatusServiceUnavailable, "UNAVAILABLE", "接收回执暂时不可用；重试将按事件 ID 幂等")
		return
	}
	machineJSON(w, http.StatusAccepted, map[string]interface{}{
		"accepted_count": len(accepted), "duplicate_count": duplicates,
	})
}
