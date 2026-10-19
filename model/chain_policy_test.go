package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func chainPolicy(t *testing.T, raw string) *MetadataPolicy {
	t.Helper()
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatalf("no error expected parsing the policy, got: %v", err)
	}
	return &policy
}

func TestProcessAndExtractPolicy_TakesPolicyOnlyFromSubordinateStatements(t *testing.T) {
	subjectPolicy := `{"openid_relying_party":{"client_name":{"value":"from-subject"}}}`
	superiorPolicy := `{"openid_relying_party":{"client_name":{"value":"from-superior"}}}`
	anchorPolicy := `{"openid_relying_party":{"client_name":{"value":"from-anchor-configuration"}}}`

	tests := []struct {
		name   string
		chain  func(*testing.T) []EntityStatement
		expect any
	}{
		{
			name: "a policy in the subject's own entity configuration",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{MetadataPolicy: chainPolicy(t, subjectPolicy)},
					{},
					{},
				}
			},
		},
		{
			name: "a policy in the trust anchor's entity configuration",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{},
					{},
					{MetadataPolicy: chainPolicy(t, anchorPolicy)},
				}
			},
		},
		{
			name: "a policy in the subordinate statement between them",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{},
					{MetadataPolicy: chainPolicy(t, superiorPolicy)},
					{},
				}
			},
			expect: "from-superior",
		},
		{
			name: "a policy at every level keeps only the subordinate statement's",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{MetadataPolicy: chainPolicy(t, subjectPolicy)},
					{MetadataPolicy: chainPolicy(t, superiorPolicy)},
					{MetadataPolicy: chainPolicy(t, anchorPolicy)},
				}
			},
			expect: "from-superior",
		},
		{
			name: "a chain with no statements between the ends",
			chain: func(t *testing.T) []EntityStatement {
				return []EntityStatement{
					{MetadataPolicy: chainPolicy(t, subjectPolicy)},
					{MetadataPolicy: chainPolicy(t, anchorPolicy)},
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, err := ProcessAndExtractPolicy(test.chain(t))
			if err != nil {
				t.Fatalf("no error expected extracting the policy, got: %v", err)
			}
			if test.expect == nil {
				if policy != nil && len(policy.OpenIDRelyingPartyMetadata) > 0 {
					t.Fatalf("expected no policy, got %+v", policy.OpenIDRelyingPartyMetadata)
				}
				return
			}
			if policy == nil {
				t.Fatal("expected the subordinate statement's policy to be extracted, got none")
			}
			operators, found := policy.OpenIDRelyingPartyMetadata["client_name"]
			if !found {
				t.Fatalf("expected a client_name policy, got %+v", policy.OpenIDRelyingPartyMetadata)
			}
			if got := operators.Metadata[0].OperatorValue(); !reflect.DeepEqual(got, test.expect) {
				t.Errorf("expected %v, got %v", test.expect, got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_RejectsAChainWithoutTwoStatements(t *testing.T) {
	policy := chainPolicy(t, `{"federation_entity":{"contacts":{"value":["x@example.com"]}}}`)

	for _, chain := range [][]EntityStatement{
		{},
		{{MetadataPolicy: policy}},
	} {
		got, err := ProcessAndExtractPolicy(chain)
		if err == nil {
			t.Errorf("expected a chain of %d to be refused, got %+v", len(chain), got)
		}
	}
}

func TestApplySuperiorMetadata(t *testing.T) {
	tests := []struct {
		name     string
		subject  *Metadata
		superior *Metadata
		expect   map[string]map[string]any
	}{
		{
			name:     "a parameter the subject also publishes is overridden",
			subject:  &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"leaf@example.com"}}},
			superior: &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"superior@example.com"}}},
			expect:   map[string]map[string]any{"federation_entity": {"contacts": []any{"superior@example.com"}}},
		},
		{
			name:     "a parameter the subject does not publish is added",
			subject:  &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"leaf@example.com"}}},
			superior: &Metadata{FederationMetadata: &FederationMetadata{"organization_name": "Pinned"}},
			expect: map[string]map[string]any{"federation_entity": {
				"contacts":          []any{"leaf@example.com"},
				"organization_name": "Pinned",
			}},
		},
		{
			name:     "an entity type the subject does not publish is ignored",
			subject:  &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"leaf@example.com"}}},
			superior: &Metadata{OAuthResourceMetadata: &OAuthResourceMetadata{"resource": "https://leaf.example.com/api"}},
			expect:   map[string]map[string]any{"federation_entity": {"contacts": []any{"leaf@example.com"}}},
		},
		{
			name:    "no superior metadata leaves the subject as published",
			subject: &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"leaf@example.com"}}},
			expect:  map[string]map[string]any{"federation_entity": {"contacts": []any{"leaf@example.com"}}},
		},
		{
			name:     "an extension entity type is overridden the same way",
			subject:  &Metadata{Extensions: map[string]map[string]any{"example_type": {"a": "subject"}}},
			superior: &Metadata{Extensions: map[string]map[string]any{"example_type": {"a": "superior"}}},
			expect:   map[string]map[string]any{"example_type": {"a": "superior"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			subjectBefore := test.subject.byEntityType()
			snapshot, err := json.Marshal(subjectBefore)
			if err != nil {
				t.Fatalf("no error expected capturing the subject, got: %v", err)
			}

			got := ApplySuperiorMetadata(test.subject, test.superior)
			if got == nil {
				t.Fatal("expected metadata, got nil")
			}
			if !reflect.DeepEqual(got.byEntityType(), test.expect) {
				t.Errorf("expected %v, got %v", test.expect, got.byEntityType())
			}

			after, err := json.Marshal(test.subject.byEntityType())
			if err != nil {
				t.Fatalf("no error expected capturing the subject, got: %v", err)
			}
			if string(after) != string(snapshot) {
				t.Errorf("the subject's own metadata was modified: %s became %s", snapshot, after)
			}
		})
	}
}

func TestApplySuperiorMetadata_NilSubject(t *testing.T) {
	if got := ApplySuperiorMetadata(nil, &Metadata{FederationMetadata: &FederationMetadata{"contacts": []any{"x@example.com"}}}); got != nil {
		t.Errorf("a subject with no metadata stays without metadata, got %v", got.byEntityType())
	}
}

func TestSupersetOfMerge_ReturnsAnOperatorForEveryValidInput(t *testing.T) {
	tests := []struct {
		name     string
		operand  []any
		incoming any
		expect   []any
	}{
		{
			name:     "two requirements combine into their union",
			operand:  []any{"a"},
			incoming: []any{"b"},
			expect:   []any{"b", "a"},
		},
		{
			name:     "a value both levels require is kept once",
			operand:  []any{"a", "b"},
			incoming: []any{"b", "c"},
			expect:   []any{"b", "c", "a"},
		},
		{
			name:     "two empty requirements stay empty",
			operand:  []any{},
			incoming: []any{},
			expect:   []any{},
		},
		{
			name:     "an empty incoming requirement keeps the current one",
			operand:  []any{"a"},
			incoming: []any{},
			expect:   []any{"a"},
		},
		{
			name:     "no incoming requirement keeps the current one",
			operand:  []any{"a"},
			incoming: nil,
			expect:   []any{"a"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operator, err := NewSupersetOf(test.operand)
			if err != nil {
				t.Fatalf("no error expected building the operator, got: %v", err)
			}

			merged, err := operator.Merge(test.incoming)
			if err != nil {
				t.Fatalf("no error expected merging, got: %v", err)
			}
			got, ok := merged.OperatorValue().([]any)
			if !ok {
				t.Fatalf("expected an array operand, got %T", merged.OperatorValue())
			}
			if !reflect.DeepEqual(got, test.expect) {
				t.Errorf("expected %v, got %v", test.expect, got)
			}
		})
	}
}

func TestAddMerge_DeduplicatesTheUnionOnce(t *testing.T) {
	operator, err := NewAdd([]any{"a", "b"})
	if err != nil {
		t.Fatalf("no error expected building the operator, got: %v", err)
	}

	merged, err := operator.Merge([]any{"b", "c"})
	if err != nil {
		t.Fatalf("no error expected merging, got: %v", err)
	}
	got, ok := merged.OperatorValue().([]any)
	if !ok {
		t.Fatalf("expected an array operand, got %T", merged.OperatorValue())
	}
	if !reflect.DeepEqual(got, []any{"b", "c", "a"}) {
		t.Errorf("expected the union deduplicated once, got %v", got)
	}
}
