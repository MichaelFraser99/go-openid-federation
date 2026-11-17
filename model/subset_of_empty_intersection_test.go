package model

import (
	"encoding/json"
	"testing"
)

func TestApplyPolicyToMetadata_AnEmptySubsetOfIntersectionIsAnEmptyArray(t *testing.T) {
	tests := map[string]struct {
		metadata any
		want     string
	}{
		"no value in the operand":  {metadata: []any{"token"}, want: `{"response_types":[]}`},
		"an empty metadata array":  {metadata: []any{}, want: `{"response_types":[]}`},
		"a partial intersection":   {metadata: []any{"token", "code"}, want: `{"response_types":["code"]}`},
		"a Go slice with no match": {metadata: []string{"token"}, want: `{"response_types":[]}`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var policy MetadataPolicy
			if err := json.Unmarshal([]byte(`{"openid_relying_party":{"response_types":{"subset_of":["code"]}}}`), &policy); err != nil {
				t.Fatalf("failed to parse the policy: %v", err)
			}
			metadata := map[string]any{"response_types": tc.metadata}
			if err := applyPolicyToMetadata(metadata, policy.OpenIDRelyingPartyMetadata); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			raw, err := json.Marshal(metadata)
			if err != nil {
				t.Fatalf("failed to marshal the metadata: %v", err)
			}
			if string(raw) != tc.want {
				t.Errorf("[6.1.3.1.5] expected %s, got %s", tc.want, raw)
			}
		})
	}
}
