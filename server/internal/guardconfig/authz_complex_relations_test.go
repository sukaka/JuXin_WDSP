package guardconfig

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func complexAuthzModel() gatewayconfig.GuardAuthzObjectModel {
	model := authzSnapshotTestModel()
	model.RequiredRelation = "ANY_OF"
	model.RequiredRelations = []string{"OWNER", "SHARED_WITH"}
	return model
}

func TestPublishableAuthzModelRelationContract(t *testing.T) {
	tests := []struct {
		name      string
		relation  string
		relations []string
		wantError bool
	}{
		{name: "legacy null", relation: "OWNER"},
		{name: "legacy empty", relation: "OWNER", relations: []string{}},
		{name: "canonical any_of", relation: "ANY_OF", relations: []string{"OWNER", "SHARED_WITH"}},
		{name: "legacy with fields", relation: "OWNER", relations: []string{"OWNER"}, wantError: true},
		{name: "any_of missing array", relation: "ANY_OF", wantError: true},
		{name: "any_of missing shared", relation: "ANY_OF", relations: []string{"OWNER"}, wantError: true},
		{name: "any_of duplicate", relation: "ANY_OF", relations: []string{"OWNER", "OWNER", "SHARED_WITH"}, wantError: true},
		{name: "any_of non canonical order", relation: "ANY_OF", relations: []string{"SHARED_WITH", "OWNER"}, wantError: true},
		{name: "any_of unsupported relation", relation: "ANY_OF", relations: []string{"OWNER", "DELEGATED_TO"}, wantError: true},
		{name: "unsupported model relation", relation: "SHARED_WITH", relations: []string{"SHARED_WITH"}, wantError: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			model := gatewayconfig.GuardAuthzObjectModel{RequiredRelation: tc.relation, RequiredRelations: tc.relations}
			err := validatePublishableAuthzModelRelations(model)
			if (err != nil) != tc.wantError {
				t.Fatalf("validatePublishableAuthzModelRelations() error=%v, wantError=%t", err, tc.wantError)
			}
		})
	}
}

func TestLoadAPIAuthzSnapshotPublishesAnyOfAndSharedFutureRelation(t *testing.T) {
	model := complexAuthzModel()
	future := time.Now().UTC().Add(time.Hour)
	lister := &fakeAuthzSnapshotLister{
		models: []gatewayconfig.GuardAuthzObjectModel{model},
		relations: []gatewayconfig.GuardAuthzObjectRelation{
			{ApplicationID: "app-1", PrincipalID: "owner", ObjectType: "ORDER", ObjectRef: "objref:shared", Relation: "OWNER", Status: "CONFIRMED"},
			{ApplicationID: "app-1", PrincipalID: "recipient", ObjectType: "ORDER", ObjectRef: "objref:shared", Relation: "SHARED_WITH", Status: "CONFIRMED", ValidFrom: &future},
		},
	}
	provider := &Provider{authzSnapshot: lister, authzObjectHMACKey: func(context.Context) (string, error) { return "001122", nil }}
	models, relations, _, key, err := provider.loadAPIAuthzSnapshot(context.Background())
	if err != nil {
		t.Fatalf("loadAPIAuthzSnapshot() error=%v", err)
	}
	if key != "001122" || len(models) != 1 || models[0].RequiredRelation != "ANY_OF" ||
		len(models[0].RequiredRelations) != 2 || models[0].RequiredRelations[1] != "SHARED_WITH" {
		t.Fatalf("complex model/key mismatch: models=%+v key=%q", models, key)
	}
	if len(relations) != 2 || relations[1].Relation != "SHARED_WITH" || relations[1].PrincipalID != "recipient" ||
		relations[1].ValidFrom == nil || !relations[1].ValidFrom.Equal(future) {
		t.Fatalf("shared/future relations mismatch: %+v", relations)
	}
	if models[0].PolicyVersion == "" {
		t.Fatal("complex model policy version is empty")
	}
}

func TestAuthzComplexQueriesAndVersionStamp(t *testing.T) {
	for _, want := range []string{"om.required_relations", "om.required_relation IN ('OWNER','ANY_OF')"} {
		if !strings.Contains(listPublishableAuthzModelsQuery, want) {
			t.Errorf("model query missing %q: %s", want, listPublishableAuthzModelsQuery)
		}
	}

	baseModel := complexAuthzModel()
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIAuthzModels: []gatewayconfig.GuardAuthzObjectModel{baseModel}})
	changed := baseModel
	changed.RequiredRelations = []string{"SHARED_WITH", "OWNER"}
	if got := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIAuthzModels: []gatewayconfig.GuardAuthzObjectModel{changed}}); got == base {
		t.Fatal("required_relations must participate in api_policy_version")
	}
	legacy := baseModel
	legacy.RequiredRelation = "OWNER"
	legacy.RequiredRelations = nil
	if got := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIAuthzModels: []gatewayconfig.GuardAuthzObjectModel{legacy}}); got == base {
		t.Fatal("OWNER to ANY_OF must change api_policy_version")
	}
	if gatewayconfig.AuthzSnapshotSchemaV2 != "authz-snap/2" {
		t.Fatalf("snapshot schema changed: %q", gatewayconfig.AuthzSnapshotSchemaV2)
	}
}

func TestCloneAuthzSnapshotDeepCopiesRequiredRelations(t *testing.T) {
	model := complexAuthzModel()
	cfg := &gatewayconfig.GuardConfig{APIAuthzModels: []gatewayconfig.GuardAuthzObjectModel{model}}
	snapshot := cloneAuthzSnapshot(cfg)
	if snapshot == nil || len(snapshot.Models) != 1 {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	snapshot.Models[0].RequiredRelations[0] = "CHANGED"
	if cfg.APIAuthzModels[0].RequiredRelations[0] != "OWNER" {
		t.Fatal("PreviousValid required_relations shares source backing storage")
	}
}
