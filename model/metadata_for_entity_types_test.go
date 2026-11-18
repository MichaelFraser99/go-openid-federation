package model

import (
	"testing"
)

func TestMetadata_ForEntityTypesCopiesAndLeavesTheReceiverWhole(t *testing.T) {
	tests := map[string]struct {
		entityTypes                         []string
		relyingParty, federation, extension bool
	}{
		"no entity type keeps every type":   {relyingParty: true, federation: true, extension: true},
		"one built-in type":                 {entityTypes: []string{"federation_entity"}, federation: true},
		"an extension type":                 {entityTypes: []string{"x_custom"}, extension: true},
		"a type the metadata does not hold": {entityTypes: []string{"oauth_client"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			original := &Metadata{
				FederationMetadata:         &FederationMetadata{"organization_name": "Leaf", "contacts": []any{"a@leaf.example.com"}},
				OpenIDRelyingPartyMetadata: &OpenIDRelyingPartyMetadata{"client_name": "Leaf RP"},
				Extensions:                 map[string]map[string]any{"x_custom": {"k": "v"}},
			}
			copied := original.ForEntityTypes(tc.entityTypes)

			if got := copied.OpenIDRelyingPartyMetadata != nil; got != tc.relyingParty {
				t.Errorf("expected openid_relying_party=%v, got %v", tc.relyingParty, got)
			}
			if got := copied.FederationMetadata != nil; got != tc.federation {
				t.Errorf("expected federation_entity=%v, got %v", tc.federation, got)
			}
			if _, got := copied.Extensions["x_custom"]; got != tc.extension {
				t.Errorf("expected x_custom=%v, got %v", tc.extension, got)
			}
			if original.FederationMetadata == nil || original.OpenIDRelyingPartyMetadata == nil || original.Extensions["x_custom"] == nil {
				t.Fatalf("expected the receiver to keep every type, got %#v", original)
			}
			if copied.FederationMetadata != nil {
				(*copied.FederationMetadata)["contacts"].([]any)[0] = "changed"
				if (*original.FederationMetadata)["contacts"].([]any)[0] != "a@leaf.example.com" {
					t.Errorf("expected the copy to share nothing with the receiver")
				}
			}
		})
	}

	if (*Metadata)(nil).ForEntityTypes([]string{"federation_entity"}) != nil {
		t.Error("expected nil metadata to stay nil")
	}
}
