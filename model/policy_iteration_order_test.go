package model

import (
	"reflect"
	"testing"
)

func TestProcessAndExtractPolicy_MergesFromTheMostSuperiorStatementDown(t *testing.T) {
	const (
		leaf         = EntityIdentifier("https://leaf.example.com")
		intermediate = EntityIdentifier("https://intermediate.example.com")
		middle       = EntityIdentifier("https://middle.example.com")
		anchor       = EntityIdentifier("https://ta.example.com")
	)
	addOf := func(t *testing.T, operand string) *MetadataPolicy {
		t.Helper()
		added, err := NewAdd([]any{operand})
		if err != nil {
			t.Fatalf("expected the add operator to build, got %v", err)
		}
		return &MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"contacts": {Metadata: []MetadataPolicyOperator{*added}}}}
	}
	subject := EntityStatement{Iss: leaf, Sub: leaf, Metadata: &Metadata{OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"contacts": []any{"leaf@example.com"}}}}

	tests := []struct {
		name   string
		chain  []EntityStatement
		merged []any
	}{
		{
			name: "two superiors",
			chain: []EntityStatement{
				subject,
				{Iss: intermediate, Sub: leaf, MetadataPolicy: addOf(t, "int@example.com")},
				{Iss: anchor, Sub: intermediate, MetadataPolicy: addOf(t, "ta@example.com")},
				{Iss: anchor, Sub: anchor},
			},
			merged: []any{"ta@example.com", "int@example.com"},
		},
		{
			name: "three superiors",
			chain: []EntityStatement{
				subject,
				{Iss: intermediate, Sub: leaf, MetadataPolicy: addOf(t, "int@example.com")},
				{Iss: middle, Sub: intermediate, MetadataPolicy: addOf(t, "middle@example.com")},
				{Iss: anchor, Sub: middle, MetadataPolicy: addOf(t, "ta@example.com")},
			},
			merged: []any{"ta@example.com", "middle@example.com", "int@example.com"},
		},
		{
			name: "a superior with no policy between two that have one",
			chain: []EntityStatement{
				subject,
				{Iss: intermediate, Sub: leaf, MetadataPolicy: addOf(t, "int@example.com")},
				{Iss: middle, Sub: intermediate},
				{Iss: anchor, Sub: middle, MetadataPolicy: addOf(t, "ta@example.com")},
			},
			merged: []any{"ta@example.com", "int@example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := ProcessAndExtractPolicy(tc.chain)
			if err != nil {
				t.Fatalf("expected the policy to merge, got %v", err)
			}
			if got := policy.OpenIDRelyingPartyMetadata["contacts"].Metadata[0].OperatorValue(); !reflect.DeepEqual(got, tc.merged) {
				t.Errorf("[6.1.4.1] the iteration MUST begin with the statement issued by the most superior entity, so the union is %v, got %v", tc.merged, got)
			}
			applied, err := ApplyPolicy(subject, *policy)
			if err != nil {
				t.Fatalf("expected the policy to apply, got %v", err)
			}
			want := append([]any{"leaf@example.com"}, tc.merged...)
			if got := (*applied.Metadata.OpenIDRelyingPartyMetadata)["contacts"]; !reflect.DeepEqual(got, want) {
				t.Errorf("[6.1.4.1] expected the resolved contacts %v, got %v", want, got)
			}
		})
	}
}
