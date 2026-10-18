package model

import (
	"encoding/json"
	"testing"
)

func TestMetadataPolicy_HasParameterPolicies(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		expect bool
	}{
		{
			name:   "an empty policy has no parameter policies",
			policy: `{}`,
			expect: false,
		},
		{
			name:   "an entity type with no parameters has no parameter policies",
			policy: `{"openid_provider":{}}`,
			expect: false,
		},
		{
			name:   "a parameter with no operators has no parameter policies",
			policy: `{"openid_provider":{"scope":{}}}`,
			expect: false,
		},
		{
			name:   "a parameter with an operator has parameter policies",
			policy: `{"federation_entity":{"contacts":{"add":["ops@ta.example.com"]}}}`,
			expect: true,
		},
		{
			name:   "a populated entity type alongside an empty one has parameter policies",
			policy: `{"federation_entity":{"contacts":{"add":["ops@ta.example.com"]}},"openid_provider":{}}`,
			expect: true,
		},
		{
			name:   "an extension entity type with an operator has parameter policies",
			policy: `{"urn:example:type":{"x":{"essential":true}}}`,
			expect: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(tc.policy), &policy); err != nil {
				t.Fatalf("failed to parse policy: %v", err)
			}
			if got := policy.HasParameterPolicies(); got != tc.expect {
				t.Errorf("expected HasParameterPolicies()=%t for %s, got %t", tc.expect, tc.policy, got)
			}
		})
	}
}
