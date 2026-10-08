package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPolicyOperators_UnmarshalJSON_OrdersAndValidates(t *testing.T) {
	tests := map[string]struct {
		input       string
		expectError bool
	}{
		"default and subset_of":     {input: `{"default": ["a","x"], "subset_of": ["a","b"]}`},
		"null value with default":   {input: `{"value": null, "default": ["a"]}`, expectError: true},
		"null value with essential": {input: `{"value": null, "essential": true}`, expectError: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				var p PolicyOperators
				err := json.Unmarshal([]byte(tt.input), &p)
				if tt.expectError {
					if err == nil {
						t.Fatal("expected error, got nil")
					}
					continue
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				for j := 1; j < len(p.Metadata); j++ {
					if p.Metadata[j-1].ResolutionHierarchy() > p.Metadata[j].ResolutionHierarchy() {
						t.Fatalf("operators not sorted by resolution hierarchy")
					}
				}
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
				chain := []EntityStatement{{}}
				for _, raw := range policies {
					var mp MetadataPolicy
					if err := json.Unmarshal([]byte(raw), &mp); err != nil {
						t.Fatal(err)
					}
					chain = append(chain, EntityStatement{MetadataPolicy: &mp})
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
