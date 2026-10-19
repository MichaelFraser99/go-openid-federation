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
				_, err = ProcessAndExtractPolicy([]EntityStatement{{}, subordinate, {}})
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
