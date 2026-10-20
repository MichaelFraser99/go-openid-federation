package model

import (
	"encoding/json"
	"strings"
	"testing"
)

func parsePolicyForTest(t *testing.T, raw string) *MetadataPolicy {
	t.Helper()
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatalf("failed to parse the policy fixture: %v", err)
	}
	return &policy
}

func TestProcessAndExtractPolicy_ObjectValuedOperands(t *testing.T) {
	tests := []struct {
		name      string
		reference string
		policy    string
		expectErr string
	}{
		{
			name:      "an object in value that one_of also lists",
			reference: "6.1.3.1.4",
			policy:    `{"openid_relying_party":{"x":{"value":{"a":1},"one_of":[{"a":1}]}}}`,
		},
		{
			name:      "an object in value that one_of does not list",
			reference: "6.1.3.1.4",
			policy:    `{"openid_relying_party":{"x":{"value":{"a":1},"one_of":[{"b":2}]}}}`,
			expectErr: "one_of",
		},
		{
			name:      "objects in value that add also lists",
			reference: "6.1.3.1.2",
			policy:    `{"openid_relying_party":{"x":{"value":[{"a":1}],"add":[{"a":1}]}}}`,
		},
		{
			name:      "objects in value that add does not list",
			reference: "6.1.3.1.2",
			policy:    `{"openid_relying_party":{"x":{"value":[{"a":1}],"add":[{"b":2}]}}}`,
			expectErr: "add",
		},
		{
			name:      "objects in value that subset_of also lists",
			reference: "6.1.3.1.5",
			policy:    `{"openid_relying_party":{"x":{"value":[{"a":1}],"subset_of":[{"a":1}]}}}`,
		},
		{
			name:      "objects in value that subset_of does not list",
			reference: "6.1.3.1.5",
			policy:    `{"openid_relying_party":{"x":{"value":[{"a":1}],"subset_of":[{"b":2}]}}}`,
			expectErr: "subset_of",
		},
		{
			name:      "objects in add that subset_of also lists",
			reference: "6.1.3.1.5",
			policy:    `{"openid_relying_party":{"x":{"add":[{"a":1}],"subset_of":[{"a":1}]}}}`,
		},
		{
			name:      "objects in add that subset_of does not list",
			reference: "6.1.3.1.5",
			policy:    `{"openid_relying_party":{"x":{"add":[{"a":1}],"subset_of":[{"b":2}]}}}`,
			expectErr: "subset_of",
		},
		{
			name:      "objects in superset_of that subset_of also lists",
			reference: "6.1.3.1.6",
			policy:    `{"openid_relying_party":{"x":{"superset_of":[{"a":1}],"subset_of":[{"a":1}]}}}`,
		},
		{
			name:      "objects in superset_of that subset_of does not list",
			reference: "6.1.3.1.6",
			policy:    `{"openid_relying_party":{"x":{"superset_of":[{"a":1}],"subset_of":[{"b":2}]}}}`,
			expectErr: "subset_of",
		},
		{
			name:      "objects in value that superset_of also lists",
			reference: "6.1.3.1.6",
			policy:    `{"openid_relying_party":{"x":{"value":[{"a":1}],"superset_of":[{"a":1}]}}}`,
		},
		{
			name:      "objects in value that superset_of does not list",
			reference: "6.1.3.1.6",
			policy:    `{"openid_relying_party":{"x":{"value":[{"a":1}],"superset_of":[{"b":2}]}}}`,
			expectErr: "superset_of",
		},
		{
			name:      "nested objects compare by value",
			reference: "6.1.3.1.5",
			policy:    `{"openid_relying_party":{"x":{"value":[{"a":{"b":[1,2]}}],"subset_of":[{"a":{"b":[1,2]}}]}}}`,
		},
		{
			name:      "nested objects differing deep inside conflict",
			reference: "6.1.3.1.5",
			policy:    `{"openid_relying_party":{"x":{"value":[{"a":{"b":[1,2]}}],"subset_of":[{"a":{"b":[1,3]}}]}}}`,
			expectErr: "subset_of",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			subordinate := EntityStatement{
				Iss:            "https://ta.example.com",
				Sub:            "https://leaf.example.com",
				MetadataPolicy: parsePolicyForTest(t, tc.policy),
			}

			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("[%s] an object valued operand panicked, which the specification permits neither: %v", tc.reference, r)
					}
				}()
				_, err = ProcessAndExtractPolicy([]EntityStatement{subordinate})
			}()

			if tc.expectErr == "" {
				if err != nil {
					t.Fatalf("[%s] expected the policy to resolve, got %v", tc.reference, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("[%s] expected a policy error naming %q, got an accepted policy", tc.reference, tc.expectErr)
			}
			if !strings.Contains(err.Error(), tc.expectErr) {
				t.Fatalf("[%s] expected a policy error naming %q, got %v", tc.reference, tc.expectErr, err)
			}
		})
	}
}

func TestAddSubordinate_IgnoresANilConfiguration(t *testing.T) {
	intermediate := &IntermediateConfiguration{}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a nil subordinate configuration panicked: %v", r)
		}
	}()

	intermediate.AddSubordinate("https://leaf.example.com", nil)

	cfg := ServerConfiguration{IntermediateConfiguration: intermediate}
	if _, err := cfg.GetSubordinate(t.Context(), "https://leaf.example.com"); err == nil {
		t.Fatal("expected a subordinate that was never stored to be reported as not found")
	}
}

func TestOperandSet_CompositeHoldingAMapDoesNotPanic(t *testing.T) {
	tests := []struct {
		name     string
		haystack []any
		needle   any
		expect   bool
	}{
		{name: "an array holding a map, matching", haystack: []any{[1]any{map[string]any{"a": 1}}}, needle: [1]any{map[string]any{"a": 1}}, expect: true},
		{name: "an array holding a map, not matching", haystack: []any{[1]any{map[string]any{"a": 1}}}, needle: [1]any{map[string]any{"b": 2}}},
		{name: "a struct holding a slice", haystack: []any{struct{ V []int }{V: []int{1}}}, needle: struct{ V []int }{V: []int{1}}, expect: true},
		{name: "scalars still take the cheap path", haystack: []any{"a", "b"}, needle: "b", expect: true},
		{name: "a scalar that is absent", haystack: []any{"a", "b"}, needle: "c"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("comparing a composite value panicked: %v", r)
				}
			}()
			if got := containsOperand(tc.haystack, tc.needle); got != tc.expect {
				t.Errorf("expected %v, got %v", tc.expect, got)
			}
		})
	}
}

func TestGetSubordinateJWKs_SkipsANilConfiguration(t *testing.T) {
	intermediate := &IntermediateConfiguration{}
	intermediate.AddSubordinate("https://leaf.example.com", &SubordinateConfiguration{})
	intermediate.subordinates["https://nil.example.com"] = nil

	cfg := ServerConfiguration{IntermediateConfiguration: intermediate}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a nil subordinate configuration in the map panicked: %v", r)
		}
	}()

	if _, err := cfg.GetSubordinateJWKs(t.Context()); err != nil {
		t.Fatalf("expected the signers to be collected, got %v", err)
	}
}

func TestApplyPolicy_EmptyEntityTypeObjectDoesNotPanic(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "an empty relying party object", raw: `{"openid_relying_party":{}}`},
		{name: "an empty provider object", raw: `{"openid_provider":{}}`},
		{name: "an empty federation entity object", raw: `{"federation_entity":{}}`},
		{name: "an empty extension type object", raw: `{"urn:example:type":{}}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var metadata Metadata
			if err := json.Unmarshal([]byte(tc.raw), &metadata); err != nil {
				t.Fatalf("expected an empty entity type object to parse, got %v", err)
			}

			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(`{"openid_relying_party":{"contacts":{"default":["ops@example.com"]}},"openid_provider":{"contacts":{"default":["ops@example.com"]}},"federation_entity":{"contacts":{"default":["ops@example.com"]}}}`), &policy); err != nil {
				t.Fatalf("the policy fixture did not parse: %v", err)
			}

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("applying a policy to an empty entity type object panicked, which a peer can trigger: %v", r)
				}
			}()

			if _, err := ApplyPolicy(EntityStatement{Metadata: &metadata}, policy); err != nil {
				t.Logf("policy error, which is acceptable: %v", err)
			}
		})
	}
}

func TestOperandSet_NilCandidate(t *testing.T) {
	tests := []struct {
		name     string
		haystack []any
		needle   any
		expect   bool
	}{
		{name: "a nil candidate against a string", haystack: []any{nil, "a"}, needle: "a", expect: true},
		{name: "a nil candidate against an absent string", haystack: []any{nil, "a"}, needle: "b"},
		{name: "a nil candidate against a nil needle", haystack: []any{nil}, needle: nil, expect: true},
		{name: "a nil candidate against an object", haystack: []any{nil}, needle: map[string]any{"a": 1}},
		{name: "a nil needle against an object candidate", haystack: []any{map[string]any{"a": 1}}, needle: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a nil operand value panicked, which peer JSON can produce: %v", r)
				}
			}()
			if got := containsOperand(tc.haystack, tc.needle); got != tc.expect {
				t.Errorf("expected %v, got %v", tc.expect, got)
			}
		})
	}
}

func TestProcessAndExtractPolicy_NullOperandValueDoesNotPanic(t *testing.T) {
	var policy MetadataPolicy
	if err := json.Unmarshal([]byte(`{"openid_relying_party":{"contacts":{"value":["a"],"subset_of":[null,"a"]}}}`), &policy); err != nil {
		t.Fatalf("the policy fixture did not parse: %v", err)
	}
	subordinate := EntityStatement{Iss: "https://ta.example.com", Sub: "https://leaf.example.com", MetadataPolicy: &policy}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("a null element in a peer supplied operand panicked: %v", r)
		}
	}()

	if _, err := ProcessAndExtractPolicy([]EntityStatement{subordinate}); err != nil {
		t.Logf("policy error, which is acceptable: %v", err)
	}
}
