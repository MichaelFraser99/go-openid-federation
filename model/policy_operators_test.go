package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPolicyOperators_UnmarshalJSON_DefersValidationToResolution(t *testing.T) {
	forbidden := map[string]string{
		"null value with default":    `{"value": null, "default": ["a"]}`,
		"null value with essential":  `{"value": null, "essential": true}`,
		"subset_of with superset_of": `{"subset_of": ["a"], "superset_of": ["b"]}`,
	}
	for name, input := range forbidden {
		t.Run(name, func(t *testing.T) {
			var operators PolicyOperators
			if err := json.Unmarshal([]byte(input), &operators); err != nil {
				t.Fatalf("expected parsing to accept the policy, got %q", err.Error())
			}

			policy := MetadataPolicy{OpenIDRelyingPartyMetadata: map[string]PolicyOperators{"grant_types": operators}}
			chain := []EntityStatement{subordinateWith(&policy)}
			if _, err := ProcessAndExtractPolicy(chain); err == nil {
				t.Fatal("expected resolution to reject the policy, got no error")
			}
		})
	}
}

func TestProcessAndExtractPolicy_UnmergedPolicyIsOrdered(t *testing.T) {
	const policyJSON = `{"openid_relying_party": {"grant_types": {"default": ["a","x"], "subset_of": ["a","b"]}}}`
	other := `{"openid_relying_party": {"redirect_uris": {"essential": false}}}`
	tests := map[string][]string{
		"single policy":           {policyJSON},
		"only one sets the claim": {policyJSON, other},
	}
	for name, policies := range tests {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				var chain []EntityStatement
				for _, raw := range policies {
					var mp MetadataPolicy
					if err := json.Unmarshal([]byte(raw), &mp); err != nil {
						t.Fatal(err)
					}
					chain = append(chain, subordinateWith(&mp))
				}
				mp, err := ProcessAndExtractPolicy(chain)
				if err != nil {
					t.Fatal(err)
				}
				metadata := map[string]any{}
				if err := applyPolicyToMetadata(metadata, mp.OpenIDRelyingPartyMetadata); err != nil {
					t.Fatal(err)
				}
				if got := metadata["grant_types"]; !reflect.DeepEqual(got, []any{"a"}) {
					t.Fatalf("expected [a], got %v", got)
				}
			}
		})
	}
}
