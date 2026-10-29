package model

import (
	"encoding/json"
	"reflect"
	"slices"
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

func TestPolicyOperators_RecordsWhatItDoesNotUnderstand(t *testing.T) {
	tests := map[string]struct {
		raw          string
		expectKnown  int
		unrecognised []string
	}{
		"only known operators":         {raw: `{"add":["a"],"essential":true}`, expectKnown: 2},
		"an unknown beside a known":    {raw: `{"add":["a"],"regexp":"^x"}`, expectKnown: 1, unrecognised: []string{"regexp"}},
		"only unknown operators":       {raw: `{"zeta":1,"alpha":2}`, unrecognised: []string{"alpha", "zeta"}},
		"a known name in another case": {raw: `{"Add":["a"]}`, unrecognised: []string{"Add"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var operators PolicyOperators
			if err := json.Unmarshal([]byte(tc.raw), &operators); err != nil {
				t.Fatalf("[6.1.3.2] an operator that is not understood must not refuse the policy, got %v", err)
			}
			if len(operators.Metadata) != tc.expectKnown {
				t.Errorf("expected %d known operators, got %d", tc.expectKnown, len(operators.Metadata))
			}
			if !slices.Equal(operators.Unrecognised, tc.unrecognised) {
				t.Errorf("expected the unrecognised operators %v in order, got %v", tc.unrecognised, operators.Unrecognised)
			}
		})
	}
}

func TestMetadataPolicy_ListsItsUnrecognisedOperators(t *testing.T) {
	var policy MetadataPolicy
	raw := `{"openid_relying_party":{"scope":{"regexp":"x","add":["openid"]},"contacts":{"m":1,"b":1}},"federation_entity":{"contacts":{"pattern":1},"homepage_uri":{"y":1}},"oauth_client":{"jwks":{"k":1}},"custom_type":{"p":{"z":1},"a":{"q":1}}}`
	if err := json.Unmarshal([]byte(raw), &policy); err != nil {
		t.Fatal(err)
	}
	expected := []string{"custom_type.a.q", "custom_type.p.z", "federation_entity.contacts.pattern", "federation_entity.homepage_uri.y", "oauth_client.jwks.k", "openid_relying_party.contacts.b", "openid_relying_party.contacts.m", "openid_relying_party.scope.regexp"}
	if got := policy.UnrecognisedOperators(); !slices.Equal(got, expected) {
		t.Errorf("expected %v, got %v", expected, got)
	}
}
